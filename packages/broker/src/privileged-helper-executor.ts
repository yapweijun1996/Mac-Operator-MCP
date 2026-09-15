import { BrokerError, canonicalJson } from "@mac-operator/contracts";
import { isPlainDataRecord } from "./plain-record.js";
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
const MAX_LEASE_DURATION_MS = 120_000;
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
    if (!Number.isSafeInteger(this.leaseDurationMs) || this.leaseDurationMs < 1_000 || this.leaseDurationMs > MAX_LEASE_DURATION_MS) {
      throw new Error("Privileged helper Job lease duration is invalid");
    }
    this.commandFactory = options.commandFactory;
    this.commandClient = options.commandClient;
    if (this.enabled && (!this.commandFactory || !this.commandClient)) {
      throw new Error("Enabled privileged helper Job executor requires command authority and transport");
    }
  }

  /** Whether this executor has an explicitly configured helper transport. */
  get available(): boolean {
    return this.enabled;
  }

  async execute(input: PrivilegedHelperJobExecutionInput): Promise<PrivilegedHelperJobExecutionOutcome> {
    if (!this.enabled) {
      throw new BrokerError("PRIVILEGE_DENIED", "Privileged helper Job executor is disabled");
    }
    validateInput(input);
    let current: BrokerJob;
    try {
      current = this.requireRunningJob(input);
    } catch (error) {
      // A cancellation can win the revision race immediately after the
      // Broker starts a Job but before this executor obtains its first lease.
      // Close that pre-dispatch window instead of leaving a cancelled Job
      // stranded in `running` until restart reconciliation.
      if (this.finishCancelledBeforeDispatch(input)) {
        throw new BrokerError("CANCELLED", "Privileged helper Job was cancelled before command dispatch");
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
    let command: SignedPrivilegedHelperCommand;
    try {
      input.assertAuthority();
      this.assertJobNotCancelled(input, current.jobId);
      if (leaseRenewalFailure !== undefined) throw leaseRenewalFailure;
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
      // The Job may be cancelled while the command factory is signing. Check
      // again before any bytes can cross the helper IPC boundary.
      this.assertJobNotCancelled(input, current.jobId);
    } catch (error) {
      // No command crossed the helper boundary. Persist a denial/failure when
      // the lease is still available so the Job cannot remain indefinitely
      // running after a Broker-side authority rejection.
      this.finishBeforeDispatch(current, input, error);
      clearInterval(renewalInterval);
      throw error;
    }

    try {
      const response = normalizeResponse(
        await this.commandClient!(command, input.timeoutMs),
        input.operation,
        current.targetRef
      );
      input.assertAuthority();
      if (leaseRenewalFailure !== undefined) throw leaseRenewalFailure;
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
      clearInterval(renewalInterval);
      return { job: finished, response, commandId: command.commandId };
    } catch (error) {
      const unknown = this.finishUnknown(input, command, lease);
      clearInterval(renewalInterval);
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

  private assertJobNotCancelled(input: PrivilegedHelperJobExecutionInput, jobId: string): void {
    const current = this.options.store.ownedJob(jobId, input.principalId);
    if (!current || current.state !== "running") {
      throw new BrokerError("CONFLICT", "Privileged helper Job is no longer running", true);
    }
    if (current.cancelRequested) {
      throw new BrokerError("CANCELLED", "Privileged helper Job was cancelled before command dispatch");
    }
  }

  private finishCancelledBeforeDispatch(input: PrivilegedHelperJobExecutionInput): boolean {
    const current = this.options.store.ownedJob(input.job.jobId, input.principalId);
    if (!current || current.state !== "running" || !current.cancelRequested) return false;
    try {
      this.options.store.finishJob(current.jobId, input.principalId, current.revision, {
        state: "cancelled",
        resultClass: "denied",
        finishedAtMs: this.now()
      }, input.lease, this.now());
      return true;
    } catch {
      // If the lease was concurrently lost, startup/owner reconciliation must
      // retain the conservative unresolved state rather than guessing.
      return false;
    }
  }

  private finishBeforeDispatch(current: BrokerJob, input: PrivilegedHelperJobExecutionInput, error: unknown): void {
    const nowMs = this.now();
    const brokerError = error instanceof BrokerError ? error : new BrokerError("EXECUTION_FAILED", "Privileged helper command could not be issued");
    const state = brokerError.errorClass === "CANCELLED" || brokerError.errorClass === "REVOKED" ? "cancelled" : "failed";
    const resultClass = state === "cancelled" || brokerError.errorClass === "POLICY_DENIED" || brokerError.errorClass === "PRIVILEGE_DENIED"
      ? "denied"
      : brokerError.errorClass === "VERIFICATION_FAILED" ? "verification_failed" : "failed";
    try {
      const latest = this.options.store.ownedJob(current.jobId, input.principalId);
      const candidate = latest?.state === "running" ? latest : current;
      this.options.store.finishJob(candidate.jobId, input.principalId, candidate.revision, {
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
  const job = input?.job;
  const lease = input?.lease;
  if (!input || typeof input !== "object" || !isPlainDataRecord(job) || !isPlainDataRecord(lease) ||
      typeof input.assertAuthority !== "function" ||
      !/^[A-Za-z0-9._:@/+-]{1,128}$/u.test(input.requestId) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(input.principalId) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(input.sessionId) ||
      (input.operation !== "service_control" && input.operation !== "package_install" && input.operation !== "power") ||
      !/^job:[A-Za-z0-9._-]{1,240}$/u.test(job.jobId) ||
      typeof job.targetRef !== "string" || job.targetRef.length < 1 || job.targetRef.length > 4_096 || job.targetRef.includes("\0") ||
      !/^[a-f0-9]{64}$/u.test(job.payloadDigest) ||
      !/^policy-[A-Za-z0-9._:-]{1,120}$/u.test(job.policyVersion) ||
      !Number.isSafeInteger(job.revision) || job.revision < 0 ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(lease.ownerId) ||
      !/^lease:[A-Za-z0-9._:-]{16,128}$/u.test(lease.token) ||
      !Number.isSafeInteger(lease.expiresAtMs) || lease.expiresAtMs < 0 ||
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
