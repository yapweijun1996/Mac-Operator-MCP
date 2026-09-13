import { BrokerError } from "@mac-operator/contracts";
import { ProcessSupervisor, type ProcessExecutionResult, type ProcessOwnershipSnapshot } from "./process-supervisor.js";
import { loadNativePeerAdapter } from "./peer-credentials.js";
import { buildSandboxExecArguments } from "./sandbox-profile.js";
import type { ResolvedTaskProfile } from "./task-profile.js";

const EVIDENCE_REFERENCE_PATTERN = /^[A-Za-z0-9._:/-]{1,256}$/u;
const SANDBOX_PROFILE_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;

/** Mechanisms with an implemented runner and reviewable proof schema. */
export type TaskIsolationMechanism = "sandbox-exec";

export interface TaskExecutionControl {
  timeoutMs: number;
  shouldCancel: () => boolean;
  onProcessStarted?: (snapshot: ProcessOwnershipSnapshot) => void;
  onProcessOwnershipChanged?: (snapshot: ProcessOwnershipSnapshot) => void;
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
  /** Explicit host mechanism; evidence cannot silently transfer to another runner. */
  sandboxMechanism: TaskIsolationMechanism;
  sandboxProfile: string;
  filesystem: "enforced";
  network: "enforced";
  credentials: "isolated";
  processTree: "owned";
  processTreePolicy: "single_process" | "owned_group";
  evidenceRef: string;
}

/**
 * The Broker owns task admission, but a task cannot run without an explicitly
 * selected isolation boundary. The default runner is intentionally unavailable
 * so enabling a profile cannot silently fall back to the unsandboxed Broker.
 */
export interface TaskRunner {
  readonly available: boolean;
  /** Host-owned mechanism used by this runner; null means no executable boundary. */
  readonly mechanism: TaskIsolationMechanism | null;
  readonly isolationProof: TaskIsolationProof | null;
  /** Stop accepting work and drain any Broker-owned OS processes. */
  close?(): Promise<void>;
  run(profile: ResolvedTaskProfile, control: TaskExecutionControl): Promise<TaskExecutionResult>;
}

export class FailClosedTaskRunner implements TaskRunner {
  readonly available = false;
  readonly mechanism = null;
  readonly isolationProof = null;

  async run(_profile: ResolvedTaskProfile, _control: TaskExecutionControl): Promise<TaskExecutionResult> {
    throw new BrokerError("POLICY_DENIED", "Task isolation boundary is not enabled");
  }
}

export interface SandboxExecTaskRunnerOptions {
  /** Explicit opt-in; production defaults remain disabled. */
  enabled?: boolean;
  /** External evidence gate; true means an operator has accepted host evidence. */
  hostEvidenceAccepted?: boolean;
  isolationProof?: TaskIsolationProof | null;
  allowedEnvironmentKeys?: readonly string[];
  /** Test-only override; production reads volume identity from the protected native adapter. */
  filesystemIdentityObserver?: (rootPath: string) => unknown;
  supervisor?: Pick<ProcessSupervisor, "run"> & { close?: () => Promise<void> };
}

interface TaskFilesystemIdentity {
  rootPath: string;
  id: string;
}

interface NativeTaskFilesystemIdentityAdapter {
  statStorageVolumeWithinRoot(rootPath: string): unknown;
}

/**
 * Experimental macOS task boundary. `sandbox-exec` is deprecated and this
 * runner is unavailable unless both an explicit opt-in and an external host
 * evidence gate are supplied. It never accepts a caller-provided profile or
 * executable; both come from the resolved Broker TaskProfile.
 */
export class SandboxExecTaskRunner implements TaskRunner {
  readonly available: boolean;
  readonly mechanism: TaskIsolationMechanism = "sandbox-exec";
  readonly isolationProof: TaskIsolationProof | null;
  private readonly supervisor: Pick<ProcessSupervisor, "run"> & { close?: () => Promise<void> };
  private readonly filesystemIdentityObserver: (rootPath: string) => unknown;

  constructor(options: SandboxExecTaskRunnerOptions = {}) {
    const proof = options.isolationProof === null || options.isolationProof === undefined
      ? null
      : validateTaskIsolationProof(options.isolationProof);
    this.isolationProof = proof;
    this.supervisor = options.supervisor ?? new ProcessSupervisor({
      allowedEnvironmentKeys: options.allowedEnvironmentKeys ?? []
    });
    this.filesystemIdentityObserver = options.filesystemIdentityObserver ?? ((rootPath) => {
      const native = loadNativePeerAdapter() as unknown as NativeTaskFilesystemIdentityAdapter;
      return native.statStorageVolumeWithinRoot(rootPath);
    });
    // The current sandbox evidence covers only the no-fork single-process
    // profile. Keep the owned-group variant unavailable until a separate
    // process-tree ownership and escape-resistance proof is accepted.
    this.available = options.enabled === true && options.hostEvidenceAccepted === true &&
      proof?.sandboxMechanism === "sandbox-exec" &&
      proof?.processTreePolicy === "single_process" && process.platform === "darwin";
  }

  close(): Promise<void> {
    return this.supervisor.close?.() ?? Promise.resolve();
  }

  async run(profile: ResolvedTaskProfile, control: TaskExecutionControl): Promise<TaskExecutionResult> {
    if (!this.available || this.isolationProof === null) {
      throw new BrokerError("POLICY_DENIED", "Task isolation boundary is not enabled");
    }
    requireTaskIsolationProof(this.isolationProof, profile, this.mechanism);
    const filesystemIdentity = captureTaskFilesystemIdentity(profile, this.filesystemIdentityObserver);
    const args = buildSandboxExecArguments(profile);
    let result: ProcessExecutionResult;
    try {
      result = await this.supervisor.run({
        executable: "/usr/bin/sandbox-exec",
        args,
        cwd: profile.cwd,
        ...(profile.process.environment === undefined ? {} : { environment: profile.process.environment }),
        timeoutMs: Math.min(control.timeoutMs, profile.process.timeoutMs),
        outputCapBytes: profile.process.outputCapBytes,
        shouldCancel: control.shouldCancel,
        ...(control.onProcessStarted === undefined ? {} : { onStarted: control.onProcessStarted }),
        ...(control.onProcessOwnershipChanged === undefined ? {} : { onOwnershipChanged: control.onProcessOwnershipChanged })
      });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("EXECUTION_FAILED", "Sandboxed task could not be started");
    }
    assertTaskFilesystemIdentityStable(profile, filesystemIdentity, this.filesystemIdentityObserver);
    return mapProcessResult(result);
  }
}

function captureTaskFilesystemIdentity(
  profile: ResolvedTaskProfile,
  observe: (rootPath: string) => unknown
): readonly TaskFilesystemIdentity[] {
  const roots = [...new Set(profile.filesystemRoots)].sort();
  if (roots.length === 0) throw new BrokerError("POLICY_DENIED", "Task filesystem roots are unavailable");
  try {
    return roots.map((rootPath) => {
      const first = parseTaskFilesystemIdentity(observe(rootPath), rootPath);
      const second = parseTaskFilesystemIdentity(observe(rootPath), rootPath);
      if (first.id !== second.id || first.rootPath !== second.rootPath) {
        throw new BrokerError("POLICY_DENIED", "Task filesystem volume identity changed during preflight");
      }
      return second;
    });
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("POLICY_DENIED", "Task filesystem volume identity could not be established");
  }
}

function assertTaskFilesystemIdentityStable(
  profile: ResolvedTaskProfile,
  expected: readonly TaskFilesystemIdentity[],
  observe: (rootPath: string) => unknown
): void {
  try {
    const roots = [...new Set(profile.filesystemRoots)].sort();
    if (roots.length !== expected.length || roots.some((rootPath, index) => rootPath !== expected[index]?.rootPath)) {
      throw new BrokerError("POLICY_DENIED", "Task filesystem roots changed during execution");
    }
    roots.forEach((rootPath, index) => {
      const current = parseTaskFilesystemIdentity(observe(rootPath), rootPath);
      const prior = expected[index];
      if (prior === undefined || current.id !== prior.id || current.rootPath !== prior.rootPath) {
        throw new BrokerError("POLICY_DENIED", "Task filesystem volume identity changed during execution");
      }
    });
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("POLICY_DENIED", "Task filesystem volume identity could not be verified");
  }
}

function parseTaskFilesystemIdentity(value: unknown, expectedRootPath: string): TaskFilesystemIdentity {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("POLICY_DENIED", "Task filesystem volume identity is malformed");
  }
  const record = value as Record<string, unknown>;
  if (typeof record.rootPath !== "string" || record.rootPath !== expectedRootPath ||
      typeof record.id !== "string" || !/^[A-Za-z0-9._:/-]{1,256}$/u.test(record.id)) {
    throw new BrokerError("POLICY_DENIED", "Task filesystem volume identity is malformed");
  }
  return { rootPath: record.rootPath, id: record.id };
}

export function validateTaskIsolationProof(value: unknown): TaskIsolationProof {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("POLICY_DENIED", "Task isolation proof is unavailable");
  }
  const proof = value as Partial<TaskIsolationProof>;
  const allowedKeys = new Set(["schemaVersion", "sandboxMechanism", "sandboxProfile", "filesystem", "network", "credentials", "processTree", "processTreePolicy", "evidenceRef"]);
  if (
    Object.keys(value).some((key) => !allowedKeys.has(key)) ||
    proof.schemaVersion !== "0.1" ||
    proof.sandboxMechanism !== "sandbox-exec" ||
    typeof proof.sandboxProfile !== "string" ||
    !SANDBOX_PROFILE_PATTERN.test(proof.sandboxProfile) ||
    proof.filesystem !== "enforced" ||
    proof.network !== "enforced" ||
    proof.credentials !== "isolated" ||
    proof.processTree !== "owned" ||
    (proof.processTreePolicy !== "single_process" && proof.processTreePolicy !== "owned_group") ||
    typeof proof.evidenceRef !== "string" ||
    !EVIDENCE_REFERENCE_PATTERN.test(proof.evidenceRef)
  ) {
    throw new BrokerError("POLICY_DENIED", "Task isolation proof is not complete");
  }
  return {
    schemaVersion: "0.1",
    sandboxMechanism: "sandbox-exec",
    sandboxProfile: proof.sandboxProfile,
    filesystem: "enforced",
    network: "enforced",
    credentials: "isolated",
    processTree: "owned",
    processTreePolicy: proof.processTreePolicy,
    evidenceRef: proof.evidenceRef
  };
}

export function requireTaskIsolationProof(
  proof: TaskIsolationProof | null | undefined,
  profile: ResolvedTaskProfile,
  expectedMechanism: TaskIsolationMechanism | null = null
): TaskIsolationProof {
  const validated = validateTaskIsolationProof(proof);
  if (expectedMechanism === null || validated.sandboxMechanism !== expectedMechanism) {
    throw new BrokerError("POLICY_DENIED", "Task isolation proof does not match the selected runner");
  }
  if (validated.sandboxProfile !== profile.sandboxProfile ||
      validated.processTreePolicy !== (profile.processTreePolicy ?? "single_process")) {
    throw new BrokerError("POLICY_DENIED", "Task isolation proof does not match the selected profile");
  }
  if ((profile.credentialPolicy ?? "none") !== "none") {
    throw new BrokerError("POLICY_DENIED", "Task credential policy is not supported by the Broker boundary");
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

function mapProcessResult(result: ProcessExecutionResult): TaskExecutionResult {
  const state = result.state;
  const resultClass = result.resultClass;
  return {
    state,
    resultClass,
    exitCode: result.exitCode,
    stdout: result.stdout,
    stderr: result.stderr,
    truncated: result.truncated,
    durationMs: result.durationMs,
    verification: result.resultClass === "SUCCEEDED"
      ? { status: "verified", summary: "sandboxed process exited successfully" }
      : result.resultClass === "UNKNOWN_OUTCOME"
        ? { status: "unknown", summary: "sandboxed process termination was not observed" }
        : { status: "failed", summary: "sandboxed process did not satisfy exit-status verification" }
  };
}
