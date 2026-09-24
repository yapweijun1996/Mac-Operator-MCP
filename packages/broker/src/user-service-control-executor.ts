import { BrokerError, canonicalJson } from "@mac-operator/contracts";
import {
  type BrokerJob,
  type BrokerStore,
  type JobLease,
  type ServiceControlJobMetadata,
  validateServiceControlJobMetadata
} from "./persistence.js";
import {
  type UserServiceControlAdapter,
  type UserServiceControlPrecondition,
  type UserServiceControlRequest,
  type UserServiceControlResult
} from "./user-service-control.js";

const DEFAULT_LEASE_DURATION_MS = 30_000;
const MAX_LEASE_DURATION_MS = 120_000;
const MAX_TIMEOUT_MS = 600_000;
const REQUEST_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

export interface UserServiceControlJobExecutorOptions {
  store: BrokerStore;
  adapter: UserServiceControlAdapter;
  /** Explicit opt-in. The default is fail-closed and performs no Job work. */
  enabled?: boolean;
  now?: () => number;
  leaseDurationMs?: number;
}

export interface UserServiceControlJobExecutionInput {
  requestId: string;
  principalId: string;
  sessionId: string;
  job: BrokerJob;
  lease: JobLease;
  timeoutMs: number;
  /** Re-checks policy, revocation, kill-switch, and host authority. */
  assertAuthority: () => void;
}

export interface UserServiceControlJobExecutionOutcome {
  job: BrokerJob;
  result: UserServiceControlResult;
}

/**
 * Runs one already admitted user-service Job and persists its terminal state.
 * The standard Broker dispatch path reaches this executor only after its
 * policy, approval, target, and host-runtime gates pass. The default policy
 * and public OAuth profile keep the capability disabled. The persisted
 * precondition proves that the adapter acted on the same service identity it
 * admitted.
 */
export class UserServiceControlJobExecutor {
  private readonly enabled: boolean;
  private readonly now: () => number;
  private readonly leaseDurationMs: number;

  constructor(private readonly options: UserServiceControlJobExecutorOptions) {
    if (!options || typeof options !== "object" || !options.store || !options.adapter) {
      throw new Error("User service-control Job executor requires a store and adapter");
    }
    if (options.enabled !== undefined && typeof options.enabled !== "boolean") {
      throw new Error("User service-control Job executor enablement is invalid");
    }
    this.enabled = options.enabled ?? false;
    this.now = options.now ?? Date.now;
    if (typeof this.now !== "function") throw new Error("User service-control Job executor clock is invalid");
    this.leaseDurationMs = options.leaseDurationMs ?? DEFAULT_LEASE_DURATION_MS;
    if (!Number.isSafeInteger(this.leaseDurationMs) || this.leaseDurationMs < 1_000 || this.leaseDurationMs > MAX_LEASE_DURATION_MS) {
      throw new Error("User service-control Job lease duration is invalid");
    }
    if (this.enabled && !options.adapter.available) {
      throw new Error("Enabled user service-control Job executor requires an available adapter");
    }
  }

  get available(): boolean {
    return this.enabled && this.options.adapter.available;
  }

  /**
   * Re-observe service identity for Jobs left UNKNOWN by a Broker restart.
   * A readback can explain the state, but cannot prove which actor caused it;
   * this method therefore never promotes the Job or replays the mutation.
   */
  async reconcileRestartedJobs(limit = 100): Promise<{
    inspected: number;
    readback: number;
    identityMismatch: number;
    unavailable: number;
    unknown: number;
  }> {
    const jobs = this.options.store.restartUnknownServiceJobs(limit);
    if (jobs.length === 0) return { inspected: 0, readback: 0, identityMismatch: 0, unavailable: 0, unknown: 0 };
    let readback = 0;
    let identityMismatch = 0;
    let unavailable = 0;
    let unknown = 0;
    for (const job of jobs) {
      const metadata = job.serviceMetadata;
      const auditRequestId = `job-service-recovery-${job.jobId}-${job.revision}`;
      if (metadata === undefined) {
        unknown += 1;
        continue;
      }
      const priorCompletion = this.options.store.auditEventResult(auditRequestId, "completion");
      if (priorCompletion === "SERVICE_READBACK" || priorCompletion === "SERVICE_IDENTITY_MISMATCH" ||
          priorCompletion === "SERVICE_RECOVERY_UNAVAILABLE" || priorCompletion === "SERVICE_RECOVERY_UNKNOWN") {
        if (priorCompletion === "SERVICE_READBACK") readback += 1;
        else if (priorCompletion === "SERVICE_IDENTITY_MISMATCH") identityMismatch += 1;
        else if (priorCompletion === "SERVICE_RECOVERY_UNAVAILABLE") unavailable += 1;
        else unknown += 1;
        continue;
      }
      if (!this.options.store.auditEventExists(auditRequestId, "intent")) {
        this.options.store.appendAudit({
          requestId: auditRequestId,
          principalId: job.ownerPrincipalId,
          tool: "internal_user_service_recovery",
          eventType: "intent",
          decision: "allow",
          resultClass: "INTENT_RECORDED",
          targetRef: `job:${job.jobId}`,
          policyVersion: job.policyVersion,
          evidence: { jobId: job.jobId, jobRevision: job.revision, action: metadata.action },
          timestampMs: this.now()
        });
      }
      let resultClass: "SERVICE_READBACK" | "SERVICE_IDENTITY_MISMATCH" | "SERVICE_RECOVERY_UNAVAILABLE" | "SERVICE_RECOVERY_UNKNOWN";
      try {
        if (!this.available) throw new BrokerError("UNSUPPORTED_CAPABILITY", "User service-control recovery is unavailable");
        const current = await this.options.adapter.readPrecondition({
          serviceId: metadata.serviceId,
          action: metadata.action,
          expectedState: metadata.expectedState
        }, { timeoutMs: Math.min(MAX_TIMEOUT_MS, 5_000), shouldCancel: () => false });
        if (current.sourceRevision !== metadata.bindingSourceRevision) resultClass = "SERVICE_IDENTITY_MISMATCH";
        else resultClass = "SERVICE_READBACK";
      } catch (error) {
        resultClass = error instanceof BrokerError && error.errorClass === "UNSUPPORTED_CAPABILITY"
          ? "SERVICE_RECOVERY_UNAVAILABLE"
          : "SERVICE_RECOVERY_UNKNOWN";
      }
      if (resultClass === "SERVICE_READBACK") readback += 1;
      else if (resultClass === "SERVICE_IDENTITY_MISMATCH") identityMismatch += 1;
      else if (resultClass === "SERVICE_RECOVERY_UNAVAILABLE") unavailable += 1;
      else unknown += 1;
      this.options.store.appendAudit({
        requestId: auditRequestId,
        principalId: job.ownerPrincipalId,
        tool: "internal_user_service_recovery",
        eventType: "completion",
        decision: "allow",
        resultClass,
        targetRef: `job:${job.jobId}`,
        policyVersion: job.policyVersion,
        evidence: {
          jobId: job.jobId,
          jobRevision: job.revision,
          action: metadata.action,
          sourceRevision: metadata.bindingSourceRevision,
          remainsUnknown: true
        },
        timestampMs: this.now()
      });
    }
    return { inspected: jobs.length, readback, identityMismatch, unavailable, unknown };
  }

  async execute(input: UserServiceControlJobExecutionInput): Promise<UserServiceControlJobExecutionOutcome> {
    if (!this.enabled) throw new BrokerError("UNSUPPORTED_CAPABILITY", "User service-control Job executor is disabled");
    validateInput(input);
    let current: BrokerJob;
    try {
      current = this.requireRunningJob(input);
    } catch (error) {
      if (this.finishCancelledBeforeDispatch(input)) {
        throw new BrokerError("CANCELLED", "User service-control Job was cancelled before dispatch");
      }
      throw error;
    }
    let lease = this.options.store.renewJobLease(
      current.jobId,
      input.principalId,
      input.lease,
      this.now(),
      this.leaseDurationMs
    );
    let leaseRenewalFailure: unknown;
    const renewalInterval = setInterval(() => {
      try {
        lease = this.options.store.renewJobLease(
          current.jobId,
          input.principalId,
          lease,
          this.now(),
          this.leaseDurationMs
        );
      } catch (error) {
        leaseRenewalFailure ??= error;
      }
    }, Math.min(5_000, Math.max(1_000, Math.floor(this.leaseDurationMs / 3))));

    const metadata = current.serviceMetadata!;
    const request: UserServiceControlRequest = {
      serviceId: metadata.serviceId,
      action: metadata.action,
      expectedState: metadata.expectedState
    };
    const precondition: UserServiceControlPrecondition = {
      state: metadata.preState,
      sourceRevision: metadata.preSourceRevision
    };
    try {
      input.assertAuthority();
      this.assertJobNotCancelled(input, current.jobId);
      if (leaseRenewalFailure !== undefined) throw leaseRenewalFailure;
      const result = await this.options.adapter.execute(request, {
        timeoutMs: input.timeoutMs,
        shouldCancel: () => {
          if (leaseRenewalFailure !== undefined) return true;
          try {
            input.assertAuthority();
            this.assertJobNotCancelled(input, current.jobId);
            return false;
          } catch {
            return true;
          }
        }
      }, precondition);
      input.assertAuthority();
      if (leaseRenewalFailure !== undefined) throw leaseRenewalFailure;
      current = this.requireRunningJob(input);
      const terminal = classifyResult(result);
      const finished = this.options.store.finishJob(
        current.jobId,
        input.principalId,
        current.revision,
        {
          state: terminal.state,
          resultClass: terminal.resultClass,
          finishedAtMs: this.now(),
          stdout: canonicalJson(result)
        },
        lease,
        this.now()
      );
      clearInterval(renewalInterval);
      return { job: finished, result };
    } catch (error) {
      const brokerError = error instanceof BrokerError ? error : new BrokerError("EXECUTION_FAILED", "User service-control Job failed");
      let currentJob: BrokerJob | undefined;
      try {
        currentJob = this.options.store.ownedJob(input.job.jobId, input.principalId);
      } catch {
        currentJob = undefined;
      }
      const commandMayHaveCrossedBoundary = brokerError.errorClass === "CANCELLED" ||
        brokerError.errorClass === "TIMEOUT" || brokerError.errorClass === "REVOKED" ||
        brokerError.errorClass === "CONFLICT" || brokerError.errorClass === "UNKNOWN_OUTCOME";
      if (currentJob?.state === "running") {
        try {
          this.options.store.finishJob(
            currentJob.jobId,
            input.principalId,
            currentJob.revision,
            {
              state: commandMayHaveCrossedBoundary ? "unknown" : "failed",
              resultClass: commandMayHaveCrossedBoundary ? "unknown" : "failed",
              finishedAtMs: this.now(),
              stdout: canonicalJson({ result_class: commandMayHaveCrossedBoundary ? "UNKNOWN_OUTCOME" : "EXECUTION_FAILED" })
            },
            lease,
            this.now()
          );
        } catch {
          // A concurrent cancellation or lease loss owns the terminal state.
        }
      }
      clearInterval(renewalInterval);
      if (commandMayHaveCrossedBoundary) {
        throw new BrokerError("UNKNOWN_OUTCOME", "User service-control outcome is unresolved; inspect its Broker Job", true);
      }
      throw brokerError;
    }
  }

  private requireRunningJob(input: UserServiceControlJobExecutionInput): BrokerJob {
    const current = this.options.store.ownedJob(input.job.jobId, input.principalId);
    if (!current || current.ownerSessionId !== input.sessionId || current.revision !== input.job.revision) {
      throw new BrokerError("CONFLICT", "User service-control Job identity changed concurrently", true);
    }
    if (current.state !== "running" || current.cancelRequested || current.tool !== "mac_service_control" ||
        current.targetRef !== `service:${current.serviceMetadata?.serviceId ?? ""}` || current.serviceMetadata === undefined) {
      throw new BrokerError("CONFLICT", "User service-control Job is no longer runnable", true);
    }
    validateServiceControlJobMetadata(current.serviceMetadata);
    return current;
  }

  private assertJobNotCancelled(input: UserServiceControlJobExecutionInput, jobId: string): void {
    const current = this.options.store.ownedJob(jobId, input.principalId);
    if (!current || current.state !== "running") throw new BrokerError("CONFLICT", "User service-control Job is no longer running", true);
    if (current.cancelRequested) throw new BrokerError("CANCELLED", "User service-control Job was cancelled before dispatch");
  }

  private finishCancelledBeforeDispatch(input: UserServiceControlJobExecutionInput): boolean {
    let current: BrokerJob | undefined;
    try {
      current = this.options.store.ownedJob(input.job.jobId, input.principalId);
    } catch {
      return false;
    }
    if (!current || current.state !== "running" || !current.cancelRequested) return false;
    try {
      this.options.store.finishJob(current.jobId, input.principalId, current.revision, {
        state: "cancelled",
        resultClass: "denied",
        finishedAtMs: this.now()
      }, input.lease, this.now());
      return true;
    } catch {
      return false;
    }
  }
}

export function createServiceControlJobMetadata(
  request: UserServiceControlRequest,
  precondition: UserServiceControlPrecondition,
  bindingSourceRevision?: string
): ServiceControlJobMetadata {
  const resolvedBindingSourceRevision = bindingSourceRevision ?? precondition?.sourceRevision;
  if (request === null || typeof request !== "object" || typeof request.serviceId !== "string" ||
      (request.action !== "start" && request.action !== "stop" && request.action !== "restart") ||
      (precondition?.state !== "running" && precondition?.state !== "stopped") ||
      !/^[0-9a-f]{7,64}$/u.test(precondition.sourceRevision) ||
      typeof resolvedBindingSourceRevision !== "string" ||
      !/^[0-9a-f]{7,64}$/u.test(resolvedBindingSourceRevision)) {
    throw new BrokerError("PRECONDITION_FAILED", "User service-control Job precondition is malformed");
  }
  const expectedState = request.action === "stop" ? "stopped" : "running";
  if (request.expectedState !== undefined && request.expectedState !== expectedState) {
    throw new BrokerError("PRECONDITION_FAILED", "User service expected_state does not match the action");
  }
  const metadata: ServiceControlJobMetadata = {
    serviceId: request.serviceId,
    action: request.action,
    expectedState,
    preState: precondition.state,
    preSourceRevision: precondition.sourceRevision,
    bindingSourceRevision: resolvedBindingSourceRevision
  };
  validateServiceControlJobMetadata(metadata);
  return metadata;
}

function validateInput(input: UserServiceControlJobExecutionInput): void {
  const job = input?.job;
  const lease = input?.lease;
  if (!input || typeof input !== "object" || !job || !lease || typeof input.assertAuthority !== "function" ||
      !REQUEST_ID_PATTERN.test(input.requestId) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(input.principalId) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(input.sessionId) ||
      !/^job:[A-Za-z0-9._-]{1,240}$/u.test(job.jobId) ||
      !/^service:gui\/[1-9][0-9]{0,9}\/com\.mac-operator\.[A-Za-z0-9_:@+-]{1,96}$/u.test(job.targetRef) ||
      !/^[a-f0-9]{64}$/u.test(job.payloadDigest) ||
      !/^policy-[A-Za-z0-9._:-]{1,120}$/u.test(job.policyVersion) ||
      !Number.isSafeInteger(job.revision) || job.revision < 0 ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(lease.ownerId) ||
      !/^lease:[A-Za-z0-9._:-]{16,128}$/u.test(lease.token) ||
      !Number.isSafeInteger(lease.expiresAtMs) || lease.expiresAtMs < 0 ||
      !Number.isSafeInteger(input.timeoutMs) || input.timeoutMs < 1 || input.timeoutMs > MAX_TIMEOUT_MS) {
    throw new BrokerError("PRECONDITION_FAILED", "User service-control Job execution input is malformed");
  }
}

function classifyResult(result: UserServiceControlResult): {
  state: "completed" | "failed" | "unknown";
  resultClass: "success" | "failed" | "verification_failed" | "unknown";
} {
  if (result.resultClass === "SUCCEEDED" && result.state === "completed" && result.verification.status === "verified") {
    return { state: "completed", resultClass: "success" };
  }
  if (result.resultClass === "VERIFICATION_FAILED" && result.state === "failed") {
    return { state: "failed", resultClass: "verification_failed" };
  }
  return { state: "unknown", resultClass: "unknown" };
}
