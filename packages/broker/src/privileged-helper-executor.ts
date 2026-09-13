import { BrokerError, canonicalJson } from "@mac-operator/contracts";
import {
  executePrivilegedHelperCommand,
  validatePrivilegedHelperExecutionResult,
  type PrivilegedHelperCommandIssueInput,
  type PrivilegedHelperCommandClientOptions,
  type PrivilegedHelperFailureResponse,
  type PrivilegedHelperOperation,
  type PrivilegedHelperResponse,
  type SignedPrivilegedHelperCommand
} from "./privileged-helper.js";
import type { BrokerJob, BrokerStore, JobLease } from "./persistence.js";

const DEFAULT_LEASE_DURATION_MS = 30_000;
const MAX_TIMEOUT_MS = 600_000;

/** The only authority that may issue a command for a helper Job. */
export interface PrivilegedHelperCommandIssuer {
  issue(input: PrivilegedHelperCommandIssueInput): SignedPrivilegedHelperCommand;
}

/**
 * Host-side command transport. The callback must authenticate the complete
 * helper response before returning it. Keeping this as an injected boundary
 * prevents the executor from owning or logging helper credentials.
 */
export type PrivilegedHelperCommandClient = (
  command: SignedPrivilegedHelperCommand,
  timeoutMs: number
) => Promise<PrivilegedHelperResponse>;

/**
 * Binds the executor to the bounded authenticated command client while
 * keeping the short-lived key buffer outside the executor's long-lived state.
 */
export function createPrivilegedHelperCommandClient(
  optionsForRequest: (timeoutMs: number) => PrivilegedHelperCommandClientOptions
): PrivilegedHelperCommandClient {
  if (typeof optionsForRequest !== "function") throw new Error("Privileged helper command options provider is required");
  return async (command, timeoutMs) => {
    const options = optionsForRequest(timeoutMs);
    if (!options || !Buffer.isBuffer(options.authenticationKey)) {
      throw new BrokerError("PRECONDITION_FAILED", "Privileged helper command options are unavailable");
    }
    try {
      return await executePrivilegedHelperCommand(command, { ...options, timeoutMs });
    } finally {
      options.authenticationKey.fill(0);
    }
  };
}

export interface PrivilegedHelperJobExecutorOptions {
  store: BrokerStore;
  /** Explicit opt-in. The default is fail-closed and performs no Job writes. */
  enabled?: boolean;
  commandFactory?: PrivilegedHelperCommandIssuer;
  commandClient?: PrivilegedHelperCommandClient;
  now?: () => number;
  leaseDurationMs?: number;
}

export interface PrivilegedHelperJobExecutionInput {
  requestId: string;
  principalId: string;
  sessionId: string;
  job: BrokerJob;
  lease: JobLease;
  operation: PrivilegedHelperOperation;
  timeoutMs: number;
  /** Re-checks Broker policy, revocation, kill-switch, and helper-key state. */
  assertAuthority: () => void;
}

export interface PrivilegedHelperJobExecutionOutcome {
  job: BrokerJob;
  response: PrivilegedHelperResponse;
  commandId: string;
}

/**
 * Runs one already admitted privileged Job through the separately
 * authenticated helper and persists a terminal Job state. This class is not
 * wired to any MCP tool by default: construction with `enabled: false` is the
 * safe production default until the helper package, policy, and real-Mac
 * evidence gates are complete.
 */
export class PrivilegedHelperJobExecutor {
  private readonly enabled: boolean;
  private readonly now: () => number;
  private readonly leaseDurationMs: number;
  private readonly commandFactory: PrivilegedHelperCommandIssuer | undefined;
  private readonly commandClient: PrivilegedHelperCommandClient | undefined;

  constructor(private readonly options: PrivilegedHelperJobExecutorOptions) {
    if (!options.store) throw new Error("Privileged helper Job executor requires a BrokerStore");
    this.enabled = options.enabled ?? false;
    this.now = options.now ?? Date.now;
    this.leaseDurationMs = options.leaseDurationMs ?? DEFAULT_LEASE_DURATION_MS;
    if (!Number.isSafeInteger(this.leaseDurationMs) || this.leaseDurationMs < 1_000 || this.leaseDurationMs > MAX_TIMEOUT_MS) {
      throw new Error("Privileged helper Job lease duration is invalid");
    }
    this.commandFactory = options.commandFactory;
    this.commandClient = options.commandClient;
    if (this.enabled && (!this.commandFactory || !this.commandClient)) {
      throw new Error("Enabled privileged helper Job executor requires command authority and transport");
    }
  }

  async execute(input: PrivilegedHelperJobExecutionInput): Promise<PrivilegedHelperJobExecutionOutcome> {
    if (!this.enabled) {
      throw new BrokerError("PRIVILEGE_DENIED", "Privileged helper Job executor is disabled");
    }
    validateInput(input);
    if (input.timeoutMs > this.leaseDurationMs) {
      throw new BrokerError("PRECONDITION_FAILED", "Privileged helper timeout exceeds the active Job lease");
    }
    const current = this.requireRunningJob(input);
    const lease = this.options.store.renewJobLease(
      current.jobId,
      input.principalId,
      input.lease,
      this.now(),
      this.leaseDurationMs
    );
    let command: SignedPrivilegedHelperCommand;
    try {
      input.assertAuthority();
      command = this.commandFactory!.issue({
        requestId: input.requestId,
        principalId: input.principalId,
        sessionId: input.sessionId,
        jobId: current.jobId,
        operation: input.operation,
        nowMs: this.now()
      });
      if (command.operation !== input.operation || command.targetRef !== current.targetRef ||
          command.payloadDigest !== current.payloadDigest || command.policyVersion !== current.policyVersion) {
        throw new BrokerError("CONFLICT", "Privileged helper command is not bound to the running Job");
      }
    } catch (error) {
      // No command crossed the helper boundary. Persist a denial/failure when
      // the lease is still available so the Job cannot remain indefinitely
      // running after a Broker-side authority rejection.
      this.finishBeforeDispatch(current, input, error);
      throw error;
    }

    try {
      const response = normalizeResponse(
        await this.commandClient!(command, input.timeoutMs),
        input.operation,
        current.targetRef
      );
      input.assertAuthority();
      const latest = this.requireRunningJob(input);
      const terminal = classifyResponse(response, input.operation, latest.targetRef);
      const finished = this.options.store.finishJob(
        latest.jobId,
        input.principalId,
        latest.revision,
        {
          state: terminal.state,
          resultClass: terminal.resultClass,
          finishedAtMs: this.now(),
          stdout: serializeResponse(response)
        },
        lease,
        this.now()
      );
      return { job: finished, response, commandId: command.commandId };
    } catch (error) {
      const unknown = this.finishUnknown(input, command, lease);
      if (unknown !== undefined) {
        throw new BrokerError("UNKNOWN_OUTCOME", "Privileged helper outcome is unresolved; inspect its Broker Job", true);
      }
      if (error instanceof BrokerError && error.errorClass === "UNKNOWN_OUTCOME") throw error;
      throw new BrokerError("UNKNOWN_OUTCOME", "Privileged helper outcome could not be persisted", true);
    }
  }

  private requireRunningJob(input: PrivilegedHelperJobExecutionInput): BrokerJob {
    const current = this.options.store.ownedJob(input.job.jobId, input.principalId);
    if (!current) throw new BrokerError("TARGET_NOT_FOUND", "Privileged helper Job was not found");
    if (current.revision !== input.job.revision || current.state !== "running" || current.cancelRequested ||
        current.ownerSessionId !== input.sessionId || current.tool !== toolForOperation(input.operation) ||
        current.targetRef !== input.job.targetRef || current.payloadDigest !== input.job.payloadDigest) {
      throw new BrokerError("CONFLICT", "Privileged helper Job lease or identity changed concurrently", true);
    }
    return current;
  }

  private finishBeforeDispatch(current: BrokerJob, input: PrivilegedHelperJobExecutionInput, error: unknown): void {
    const nowMs = this.now();
    const brokerError = error instanceof BrokerError ? error : new BrokerError("EXECUTION_FAILED", "Privileged helper command could not be issued");
    const state = brokerError.errorClass === "CANCELLED" || brokerError.errorClass === "REVOKED" ? "cancelled" : "failed";
    const resultClass = state === "cancelled" || brokerError.errorClass === "POLICY_DENIED" || brokerError.errorClass === "PRIVILEGE_DENIED"
      ? "denied"
      : brokerError.errorClass === "VERIFICATION_FAILED" ? "verification_failed" : "failed";
    try {
      this.options.store.finishJob(current.jobId, input.principalId, current.revision, {
        state,
        resultClass,
        finishedAtMs: nowMs
      }, input.lease, nowMs);
    } catch {
      // A concurrent cancellation/revocation owns the terminal transition.
    }
  }

  private finishUnknown(input: PrivilegedHelperJobExecutionInput, command: SignedPrivilegedHelperCommand, lease: JobLease): BrokerJob | undefined {
    const current = this.options.store.ownedJob(input.job.jobId, input.principalId);
    if (!current || current.state !== "running") return undefined;
    try {
      return this.options.store.finishJob(current.jobId, input.principalId, current.revision, {
        state: "unknown",
        resultClass: "unknown",
        finishedAtMs: this.now(),
        stdout: canonicalJson({ command_id: command.commandId, result_class: "UNKNOWN_OUTCOME" })
      }, lease, this.now());
    } catch {
      return undefined;
    }
  }
}

function validateInput(input: PrivilegedHelperJobExecutionInput): void {
  if (!input || typeof input !== "object" || !input.job || !input.lease || typeof input.assertAuthority !== "function" ||
      !/^[A-Za-z0-9._:@/+-]{1,128}$/u.test(input.requestId) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(input.principalId) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(input.sessionId) ||
      !Number.isSafeInteger(input.timeoutMs) || input.timeoutMs < 1 || input.timeoutMs > MAX_TIMEOUT_MS) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper Job execution input is malformed");
  }
}

function toolForOperation(operation: PrivilegedHelperOperation): string {
  if (operation === "service_control") return "mac_priv_service_control";
  if (operation === "package_install") return "mac_priv_package_install";
  return "mac_priv_power";
}

function classifyResponse(
  response: PrivilegedHelperResponse,
  operation: PrivilegedHelperOperation,
  targetRef: string
): { state: "completed" | "failed" | "cancelled" | "unknown"; resultClass: "success" | "denied" | "failed" | "verification_failed" | "unknown" } {
  if (response.ok) {
    const result = validatePrivilegedHelperExecutionResult(response.result, { operation, targetRef });
    if (result.resultClass === "UNKNOWN_OUTCOME" || result.resultClass === "TIMEOUT" || result.state === "unknown") {
      return { state: "unknown", resultClass: "unknown" };
    }
    if (result.state === "accepted") {
      return { state: "unknown", resultClass: "unknown" };
    }
    if (result.resultClass === "CANCELLED" || result.state === "cancelled") {
      return { state: "cancelled", resultClass: "denied" };
    }
    if (result.resultClass === "VERIFICATION_FAILED" || result.verification.status === "failed") {
      return { state: "failed", resultClass: "verification_failed" };
    }
    if (result.resultClass === "SUCCEEDED" && result.state === "completed" && result.verification.status === "verified") {
      return { state: "completed", resultClass: "success" };
    }
    return { state: "failed", resultClass: "failed" };
  }
  const failure = response as PrivilegedHelperFailureResponse;
  if (["UNKNOWN_OUTCOME", "TIMEOUT", "CONFLICT", "EXECUTION_FAILED", "OUTPUT_LIMIT", "AUDIT_UNAVAILABLE"].includes(failure.resultClass)) {
    return { state: "unknown", resultClass: "unknown" };
  }
  if (failure.resultClass === "CANCELLED") return { state: "cancelled", resultClass: "denied" };
  if (failure.resultClass === "VERIFICATION_FAILED") return { state: "failed", resultClass: "verification_failed" };
  return { state: "failed", resultClass: "denied" };
}

function normalizeResponse(
  response: PrivilegedHelperResponse,
  operation: PrivilegedHelperOperation,
  targetRef: string
): PrivilegedHelperResponse {
  if (!response.ok) return response;
  return {
    ...response,
    result: validatePrivilegedHelperExecutionResult(response.result, { operation, targetRef })
  };
}

function serializeResponse(response: PrivilegedHelperResponse): string {
  if (response.ok) {
    return canonicalJson({
      ok: true,
      result: response.result
    });
  }
  return canonicalJson({
    ok: false,
    result_class: response.resultClass,
    retryable: response.error.retryable
  });
}
