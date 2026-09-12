import { BrokerError } from "@mac-operator/contracts";
import type { ResolvedTaskProfile } from "./task-profile.js";

export interface TaskExecutionControl {
  timeoutMs: number;
  shouldCancel: () => boolean;
}

export type TaskVerificationStatus = "verified" | "failed" | "unknown" | "not_run";

export interface TaskExecutionResult {
  state: "completed" | "failed" | "cancelled" | "timed_out" | "unknown";
  resultClass: "SUCCEEDED" | "EXECUTION_FAILED" | "CANCELLED" | "TIMEOUT" | "OUTPUT_LIMIT" | "UNKNOWN_OUTCOME";
  exitCode: number | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  durationMs: number;
  verification: {
    status: TaskVerificationStatus;
    summary?: string;
  };
}

/**
 * The Broker owns task admission, but a task cannot run without an explicitly
 * selected isolation boundary. The default runner is intentionally unavailable
 * so enabling a profile cannot silently fall back to the unsandboxed Broker.
 */
export interface TaskRunner {
  readonly available: boolean;
  run(profile: ResolvedTaskProfile, control: TaskExecutionControl): Promise<TaskExecutionResult>;
}

export class FailClosedTaskRunner implements TaskRunner {
  readonly available = false;

  async run(_profile: ResolvedTaskProfile, _control: TaskExecutionControl): Promise<TaskExecutionResult> {
    throw new BrokerError("POLICY_DENIED", "Task isolation boundary is not enabled");
  }
}

export function validateTaskExecutionResult(value: TaskExecutionResult): TaskExecutionResult {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      !["completed", "failed", "cancelled", "timed_out", "unknown"].includes(value.state) ||
      !["SUCCEEDED", "EXECUTION_FAILED", "CANCELLED", "TIMEOUT", "OUTPUT_LIMIT", "UNKNOWN_OUTCOME"].includes(value.resultClass) ||
      (value.exitCode !== null && (!Number.isInteger(value.exitCode) || value.exitCode < -2_147_483_648 || value.exitCode > 2_147_483_647)) ||
      typeof value.stdout !== "string" || typeof value.stderr !== "string" ||
      typeof value.truncated !== "boolean" || !Number.isSafeInteger(value.durationMs) || value.durationMs < 0 ||
      value.verification === null || typeof value.verification !== "object" ||
      !["verified", "failed", "unknown", "not_run"].includes(value.verification.status)) {
    throw new BrokerError("EXECUTION_FAILED", "Task runner returned a malformed result");
  }
  if (value.verification.summary !== undefined &&
      (typeof value.verification.summary !== "string" || value.verification.summary.length > 512 || value.verification.summary.includes("\0"))) {
    throw new BrokerError("EXECUTION_FAILED", "Task runner returned a malformed verification summary");
  }
  return value;
}
