import { BrokerError } from "@mac-operator/contracts";
import type { ResolvedTaskProfile } from "./task-profile.js";

const EVIDENCE_REFERENCE_PATTERN = /^[A-Za-z0-9._:/-]{1,256}$/u;
const SANDBOX_PROFILE_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;

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
 * A runner may be enabled only when its host boundary has evidence for every
 * isolation dimension required by a project-controlled task. This is an
 * attestation gate, not a substitute for independently reviewing the evidence.
 */
export interface TaskIsolationProof {
  schemaVersion: "0.1";
  sandboxProfile: string;
  filesystem: "enforced";
  network: "enforced";
  credentials: "isolated";
  processTree: "owned";
  evidenceRef: string;
}

/**
 * The Broker owns task admission, but a task cannot run without an explicitly
 * selected isolation boundary. The default runner is intentionally unavailable
 * so enabling a profile cannot silently fall back to the unsandboxed Broker.
 */
export interface TaskRunner {
  readonly available: boolean;
  readonly isolationProof: TaskIsolationProof | null;
  run(profile: ResolvedTaskProfile, control: TaskExecutionControl): Promise<TaskExecutionResult>;
}

export class FailClosedTaskRunner implements TaskRunner {
  readonly available = false;
  readonly isolationProof = null;

  async run(_profile: ResolvedTaskProfile, _control: TaskExecutionControl): Promise<TaskExecutionResult> {
    throw new BrokerError("POLICY_DENIED", "Task isolation boundary is not enabled");
  }
}

export function validateTaskIsolationProof(value: unknown): TaskIsolationProof {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("POLICY_DENIED", "Task isolation proof is unavailable");
  }
  const proof = value as Partial<TaskIsolationProof>;
  const allowedKeys = new Set(["schemaVersion", "sandboxProfile", "filesystem", "network", "credentials", "processTree", "evidenceRef"]);
  if (
    Object.keys(value).some((key) => !allowedKeys.has(key)) ||
    proof.schemaVersion !== "0.1" ||
    typeof proof.sandboxProfile !== "string" ||
    !SANDBOX_PROFILE_PATTERN.test(proof.sandboxProfile) ||
    proof.filesystem !== "enforced" ||
    proof.network !== "enforced" ||
    proof.credentials !== "isolated" ||
    proof.processTree !== "owned" ||
    typeof proof.evidenceRef !== "string" ||
    !EVIDENCE_REFERENCE_PATTERN.test(proof.evidenceRef)
  ) {
    throw new BrokerError("POLICY_DENIED", "Task isolation proof is not complete");
  }
  return {
    schemaVersion: "0.1",
    sandboxProfile: proof.sandboxProfile,
    filesystem: "enforced",
    network: "enforced",
    credentials: "isolated",
    processTree: "owned",
    evidenceRef: proof.evidenceRef
  };
}

export function requireTaskIsolationProof(
  proof: TaskIsolationProof | null | undefined,
  profile: ResolvedTaskProfile
): TaskIsolationProof {
  const validated = validateTaskIsolationProof(proof);
  if (validated.sandboxProfile !== profile.sandboxProfile) {
    throw new BrokerError("POLICY_DENIED", "Task isolation proof does not match the selected profile");
  }
  return validated;
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
