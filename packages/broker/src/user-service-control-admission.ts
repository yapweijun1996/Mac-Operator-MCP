import { randomUUID } from "node:crypto";
import {
  BrokerError,
  canonicalJson,
  sha256,
  type BrokerRequest
} from "@mac-operator/contracts";
import {
  BrokerStore,
  type BrokerJob,
  type RequestAdmissionLimits,
  type ServiceControlJobMetadata
} from "./persistence.js";
import { keyIdentity } from "./edge-keyring.js";
import {
  UserServiceControlAdapter,
  type UserServiceControlAction,
  type UserServiceControlPrecondition,
  type UserServiceControlRequest,
  type UserServiceControlResult,
  type UserServiceControlState,
  type UserServiceExecutionControl
} from "./user-service-control.js";
import {
  USER_SERVICE_CONTROL_CONTRACT,
  validateUserServiceControlContract
} from "./user-service-control-contract.js";
import {
  UserServiceControlJobExecutor,
  createServiceControlJobMetadata
} from "./user-service-control-executor.js";

const REQUEST_MAX_AGE_MS = 600_000;
const JOB_LEASE_DURATION_MS = 30_000;
const JOB_LEASE_OWNER = "broker:user-service-control-candidate";
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;

export interface UserServiceControlCandidateAuthority {
  /** Re-checks normal Broker authentication authority, policy revision, and revocation. */
  assertRequestAuthority(request: BrokerRequest): void;
}

export interface UserServiceControlCandidateOptions {
  store: BrokerStore;
  adapter: UserServiceControlAdapter;
  executor: UserServiceControlJobExecutor;
  /** Exact principal allowlist for this non-public candidate seam. Empty means deny all. */
  authorizedPrincipalIds: readonly string[];
  /** Explicit opt-in; omitted means disabled. */
  enabled?: boolean;
  now?: () => number;
  maxRequestAgeMs?: number;
}

export interface UserServiceControlCandidateAdmission {
  request: BrokerRequest;
  job: BrokerJob;
  precondition: {
    state: UserServiceControlState;
    sourceRevision: string;
  };
  metadata: ServiceControlJobMetadata;
  targetRef: string;
  payloadDigest: string;
  reused: boolean;
}

export interface UserServiceControlCandidateExecution {
  request: BrokerRequest;
  job: BrokerJob;
  result?: UserServiceControlResult;
  reused: boolean;
}

export interface ParsedUserServiceControlArguments {
  serviceId: string;
  action: UserServiceControlAction;
  expectedState: UserServiceControlState;
  idempotencyKey: string;
}

/**
 * Internal Broker admission and execution seam for the MOP-104 candidate.
 *
 * This class owns the bounded host/runtime seam. The public MCP path remains
 * fail-closed unless the normal Broker policy, OAuth grant, and runtime
 * availability gates are independently enabled.
 */
export class UserServiceControlBrokerCandidate {
  private readonly enabled: boolean;
  private readonly now: () => number;
  private readonly maxRequestAgeMs: number;
  private readonly authorizedPrincipalIds: ReadonlySet<string>;

  constructor(private readonly options: UserServiceControlCandidateOptions) {
    validateUserServiceControlContract(USER_SERVICE_CONTROL_CONTRACT);
    if (!options || typeof options !== "object" || !options.store || !options.adapter || !options.executor) {
      throw new Error("User service-control Broker candidate requires store, adapter, and executor");
    }
    if (!Array.isArray(options.authorizedPrincipalIds) || options.authorizedPrincipalIds.length > 64 ||
        options.authorizedPrincipalIds.some((value) => typeof value !== "string" || !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(value))) {
      throw new Error("User service-control candidate principal allowlist is invalid");
    }
    this.authorizedPrincipalIds = new Set(options.authorizedPrincipalIds);
    if (options.enabled !== undefined && typeof options.enabled !== "boolean") {
      throw new Error("User service-control Broker candidate enablement is invalid");
    }
    this.enabled = options.enabled ?? false;
    this.now = options.now ?? Date.now;
    this.maxRequestAgeMs = options.maxRequestAgeMs ?? REQUEST_MAX_AGE_MS;
    if (typeof this.now !== "function" || !Number.isSafeInteger(this.maxRequestAgeMs) ||
        this.maxRequestAgeMs < 1 || this.maxRequestAgeMs > REQUEST_MAX_AGE_MS) {
      throw new Error("User service-control Broker candidate limits are invalid");
    }
  }

  get available(): boolean {
    return this.enabled && this.authorizedPrincipalIds.size > 0 &&
      this.options.adapter.available && this.options.executor.available;
  }

  get adapter(): UserServiceControlAdapter {
    return this.options.adapter;
  }

  get executor(): UserServiceControlJobExecutor {
    return this.options.executor;
  }

  isPrincipalAuthorized(principalId: string): boolean {
    return this.authorizedPrincipalIds.has(principalId);
  }

  async readPrecondition(
    request: UserServiceControlRequest,
    control: UserServiceExecutionControl,
    principalId: string
  ): Promise<UserServiceControlPrecondition> {
    this.requireAvailable();
    this.assertPrincipalId(principalId);
    return this.options.adapter.readPrecondition(request, control);
  }

  executeJob(
    input: Parameters<UserServiceControlJobExecutor["execute"]>[0],
    principalId: string
  ): ReturnType<UserServiceControlJobExecutor["execute"]> {
    this.requireAvailable();
    this.assertPrincipalId(principalId);
    return this.options.executor.execute(input);
  }

  /**
   * Atomically admits a signed candidate request, consumes an exact approval,
   * records decision plus intent, and creates an idempotent durable Job.
   */
  async admit(
    request: BrokerRequest,
    authority: UserServiceControlCandidateAuthority,
    limits?: RequestAdmissionLimits
  ): Promise<UserServiceControlCandidateAdmission> {
    this.requireAvailable();
    const parsed = parseUserServiceControlArguments(request);
    this.assertPrincipal(request);
    this.assertCandidateSwitches();
    authority.assertRequestAuthority(request);

    const precondition = await this.options.adapter.readPrecondition(
      { serviceId: parsed.serviceId, action: parsed.action, expectedState: parsed.expectedState },
      { timeoutMs: USER_SERVICE_CONTROL_CONTRACT.maxOperationTimeoutMs, shouldCancel: () => false }
    );
    authority.assertRequestAuthority(request);
    this.assertCandidateSwitches();

    const targetRef = `service:${parsed.serviceId}`;
    const payloadDigest = sha256(canonicalJson(request.arguments));
    const metadata = createServiceControlJobMetadata(
      { serviceId: parsed.serviceId, action: parsed.action, expectedState: parsed.expectedState },
      precondition
    );
    const nowMs = this.readNow();
    const job: UserServiceControlCandidateAdmission["job"] = {
      jobId: `job:service-${sha256(canonicalJson({ principalId: request.principal.principalId, idempotencyKey: parsed.idempotencyKey })).slice(0, 48)}`,
      ownerEdgeId: request.principal.edgeId,
      ownerEdgeKeyId: keyIdentity(request.principal.edgeId, request.authenticationKeyId),
      ownerPrincipalId: request.principal.principalId,
      ownerSessionId: request.principal.sessionId,
      tool: USER_SERVICE_CONTROL_CONTRACT.tool,
      targetRef,
      policyVersion: request.policyVersion,
      payloadDigest,
      idempotencyKey: `service-control:${parsed.idempotencyKey}`,
      state: "queued",
      resultClass: "queued",
      createdAtMs: nowMs,
      startedAtMs: null,
      finishedAtMs: null,
      exitCode: null,
      stdout: "",
      stderr: "",
      truncated: false,
      cancelRequested: false,
      revision: 0,
      serviceMetadata: metadata
    };
    const admitted = this.options.store.admitApprovedJob({
      request: {
        requestId: request.requestId,
        edgeId: request.principal.edgeId,
        edgeKeyId: keyIdentity(request.principal.edgeId, request.authenticationKeyId),
        nonce: request.nonce,
        nonceExpiresAtMs: nowMs + this.maxRequestAgeMs,
        principalId: request.principal.principalId,
        sessionId: request.principal.sessionId,
        tool: USER_SERVICE_CONTROL_CONTRACT.tool,
        policyVersion: request.policyVersion,
        payloadDigest: request.payloadDigest,
        mutation: true,
        capabilityFamilies: ["write"],
        receivedAtMs: nowMs
      },
      decision: {
        requestId: request.requestId,
        principalId: request.principal.principalId,
        tool: USER_SERVICE_CONTROL_CONTRACT.tool,
        eventType: "decision",
        decision: "allow",
        resultClass: "AUTHORIZED",
        targetRef,
        policyVersion: request.policyVersion,
        evidence: { candidate: true, targetType: USER_SERVICE_CONTROL_CONTRACT.targetType },
        timestampMs: nowMs
      },
      intent: {
        requestId: request.requestId,
        principalId: request.principal.principalId,
        tool: USER_SERVICE_CONTROL_CONTRACT.tool,
        eventType: "intent",
        decision: "allow",
        resultClass: "INTENT_RECORDED",
        targetRef,
        policyVersion: request.policyVersion,
        evidence: {
          candidate: true,
          action: parsed.action,
          expectedState: parsed.expectedState,
          argumentDigest: payloadDigest,
          preState: precondition.state,
          sourceRevision: precondition.sourceRevision,
          idempotencyKey: parsed.idempotencyKey,
          targetType: USER_SERVICE_CONTROL_CONTRACT.targetType
        },
        timestampMs: nowMs
      },
      approval: {
        contractVersion: USER_SERVICE_CONTROL_CONTRACT.contractVersion,
        targetKind: "service",
        targetRef,
        payloadDigest,
        approvalClass: USER_SERVICE_CONTROL_CONTRACT.approvalClass,
        unattended: false
      },
      job: {
        jobId: job.jobId,
        edgeId: request.principal.edgeId,
        edgeKeyId: keyIdentity(request.principal.edgeId, request.authenticationKeyId),
        ownerPrincipalId: job.ownerPrincipalId,
        ownerSessionId: job.ownerSessionId,
        tool: job.tool,
        targetRef: job.targetRef,
        policyVersion: job.policyVersion,
        payloadDigest: job.payloadDigest,
        idempotencyKey: job.idempotencyKey,
        createdAtMs: job.createdAtMs,
        serviceMetadata: metadata
      },
      ...(limits === undefined ? {} : { limits })
    });
    return {
      request,
      job: admitted.job,
      precondition,
      metadata,
      targetRef,
      payloadDigest,
      reused: admitted.reused
    };
  }

  /** Start and execute a newly admitted candidate Job, then close its Request lifecycle. */
  async execute(
    admission: UserServiceControlCandidateAdmission,
    authority: UserServiceControlCandidateAuthority
  ): Promise<UserServiceControlCandidateExecution> {
    this.requireAvailable();
    if (admission.reused) {
      return { request: admission.request, job: admission.job, reused: true };
    }
    authority.assertRequestAuthority(admission.request);
    this.assertCandidateSwitches();
    const startedAtMs = this.readNow();
    let running = admission.job;
    const lease = {
      ownerId: JOB_LEASE_OWNER,
      token: `lease:${randomUUID()}`,
      expiresAtMs: startedAtMs + JOB_LEASE_DURATION_MS
    } as const;
    try {
      this.options.store.markRequestRunning(admission.request.requestId, startedAtMs);
      authority.assertRequestAuthority(admission.request);
      this.assertCandidateSwitches();
      const started = this.options.store.startJob(
        admission.job.jobId,
        admission.request.principal.principalId,
        admission.job.revision,
        startedAtMs,
        lease
      );
      const outcome = await this.options.executor.execute({
        requestId: admission.request.requestId,
        principalId: admission.request.principal.principalId,
        sessionId: admission.request.principal.sessionId,
        job: started,
        lease,
        timeoutMs: USER_SERVICE_CONTROL_CONTRACT.maxOperationTimeoutMs,
        assertAuthority: () => {
          authority.assertRequestAuthority(admission.request);
          this.assertCandidateSwitches();
        }
      });
      running = outcome.job;
      authority.assertRequestAuthority(admission.request);
      this.assertCandidateSwitches();
      if (outcome.result.resultClass === "SUCCEEDED") {
        this.options.store.completeRequest({
          requestId: admission.request.requestId,
          principalId: admission.request.principal.principalId,
          tool: USER_SERVICE_CONTROL_CONTRACT.tool,
          eventType: "completion",
          decision: "allow",
          resultClass: "SUCCEEDED",
          targetRef: admission.targetRef,
          policyVersion: admission.request.policyVersion,
          evidence: completionEvidence(outcome.result),
          timestampMs: this.readNow()
        });
      } else {
        this.options.store.failRequest({
          requestId: admission.request.requestId,
          principalId: admission.request.principal.principalId,
          tool: USER_SERVICE_CONTROL_CONTRACT.tool,
          eventType: "completion",
          decision: "allow",
          resultClass: outcome.result.resultClass === "VERIFICATION_FAILED" ? "VERIFICATION_FAILED" : "UNKNOWN_OUTCOME",
          targetRef: admission.targetRef,
          policyVersion: admission.request.policyVersion,
          evidence: completionEvidence(outcome.result),
          timestampMs: this.readNow()
        });
      }
      return { request: admission.request, job: running, result: outcome.result, reused: false };
    } catch (error) {
      const brokerError = error instanceof BrokerError
        ? error
        : new BrokerError("EXECUTION_FAILED", "User service-control candidate execution failed");
      try {
        const current = this.options.store.requestRecord(admission.request.requestId);
        if (current !== undefined && !isTerminalRequestState(current.state)) {
          if (current.jobId !== null) {
            try {
              this.options.store.requestJobCancellation(
                current.jobId,
                admission.request.principal.principalId,
                "CANDIDATE_EXECUTION_FAILED",
                this.readNow()
              );
            } catch {
              // Preserve the original failure; a concurrent terminal transition owns the Job.
            }
          }
          this.options.store.failRequest({
            requestId: admission.request.requestId,
            principalId: admission.request.principal.principalId,
            tool: USER_SERVICE_CONTROL_CONTRACT.tool,
            eventType: "completion",
            decision: "allow",
            resultClass: failureResultClass(brokerError),
            targetRef: admission.targetRef,
            policyVersion: admission.request.policyVersion,
            evidence: { candidate: true, errorClass: brokerError.errorClass },
            timestampMs: this.readNow()
          });
        }
      } catch {
        // Preserve the execution failure; the durable Job/executor remains authoritative.
      }
      throw brokerError;
    }
  }

  private requireAvailable(): void {
    if (!this.available) {
      throw new BrokerError("UNSUPPORTED_CAPABILITY", "User service-control Broker candidate is disabled");
    }
  }

  private assertPrincipal(request: BrokerRequest): void {
    this.assertPrincipalId(request.principal.principalId);
  }

  private assertPrincipalId(principalId: string): void {
    if (!this.authorizedPrincipalIds.has(principalId)) {
      throw new BrokerError("POLICY_DENIED", "Principal is not authorized for the user service-control candidate");
    }
  }

  private assertCandidateSwitches(): void {
    if (this.options.store.isSwitchDisabled("global") || this.options.store.isSwitchDisabled("mutations")) {
      throw new BrokerError("REVOKED", "User service-control candidate is disabled by the Broker kill-switch");
    }
  }

  private readNow(): number {
    const value = this.now();
    if (!Number.isSafeInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER - Math.max(this.maxRequestAgeMs, JOB_LEASE_DURATION_MS)) {
      throw new BrokerError("PRECONDITION_FAILED", "User service-control candidate clock is invalid");
    }
    return value;
  }
}

export function parseUserServiceControlArguments(request: BrokerRequest): ParsedUserServiceControlArguments {
  if (request.tool !== USER_SERVICE_CONTROL_CONTRACT.tool || request.contractVersion !== USER_SERVICE_CONTROL_CONTRACT.contractVersion) {
    throw new BrokerError("UNSUPPORTED_CAPABILITY", "User service-control candidate contract is not selected");
  }
  const argumentsValue = request.arguments;
  if (Object.keys(argumentsValue).sort().join(",") !== USER_SERVICE_CONTROL_CONTRACT.argumentKeys.join(",")) {
    throw new BrokerError("PRECONDITION_FAILED", "User service-control candidate arguments are malformed");
  }
  const serviceId = argumentsValue.service_id;
  const action = argumentsValue.action;
  const expectedState = argumentsValue.expected_state;
  const idempotencyKey = argumentsValue.idempotency_key;
  if (typeof serviceId !== "string" || typeof action !== "string" || typeof expectedState !== "string" ||
      typeof idempotencyKey !== "string" || !IDEMPOTENCY_KEY_PATTERN.test(idempotencyKey) ||
      !["start", "stop", "restart"].includes(action) || !["running", "stopped"].includes(expectedState)) {
    throw new BrokerError("PRECONDITION_FAILED", "User service-control candidate arguments are malformed");
  }
  const expected = action === "stop" ? "stopped" : "running";
  if (expectedState !== expected) {
    throw new BrokerError("PRECONDITION_FAILED", "User service expected_state does not match the action");
  }
  return {
    serviceId,
    action: action as UserServiceControlAction,
    expectedState: expectedState as UserServiceControlState,
    idempotencyKey
  };
}

function completionEvidence(result: UserServiceControlResult): Record<string, unknown> {
  return {
    candidate: true,
    operation: result.operation,
    serviceId: result.serviceId,
    action: result.action,
    state: result.state,
    resultClass: result.resultClass,
    preState: result.preState,
    postState: result.postState,
    sourceRevision: result.sourceRevision,
    idempotent: result.idempotent,
    rollbackStatus: result.rollback.status,
    verificationStatus: result.verification.status
  };
}

function failureResultClass(error: BrokerError): "CANCELLED" | "TIMEOUT" | "VERIFICATION_FAILED" | "UNKNOWN_OUTCOME" | "EXECUTION_FAILED" {
  if (error.errorClass === "CANCELLED") return "CANCELLED";
  if (error.errorClass === "TIMEOUT") return "TIMEOUT";
  if (error.errorClass === "VERIFICATION_FAILED") return "VERIFICATION_FAILED";
  if (error.errorClass === "UNKNOWN_OUTCOME" || error.errorClass === "REVOKED" || error.errorClass === "CONFLICT") return "UNKNOWN_OUTCOME";
  return "EXECUTION_FAILED";
}

function isTerminalRequestState(state: string): boolean {
  return ["SUCCEEDED", "FAILED", "DENIED", "CANCELLED", "TIMED_OUT", "VERIFICATION_FAILED", "UNKNOWN"].includes(state);
}
