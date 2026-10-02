import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import { isAbsolute, resolve } from "node:path";
import type { ContainerTaskJobMetadata } from "./container-job-metadata.js";
import type { GuestTaskJobMetadata } from "./persistence.js";
import {
  type DescriptorSnapshotPreparationInput,
  type PreparedDescriptorSnapshot,
  type DescriptorSnapshotHandoff
} from "./descriptor-snapshot-attestation.js";
import {
  assertProcessPathIdentityStable,
  captureProcessPathIdentity,
  ProcessSupervisor,
  type ProcessExecutionResult,
  type ProcessOwnershipSnapshot,
  type ProcessPathIdentity
} from "./process-supervisor.js";
import { inspectProcessDescriptorExecutionCapability } from "./process-launch-capability.js";
import { loadNativePeerAdapter } from "./peer-credentials.js";
import { isPlainDataRecord } from "./plain-record.js";
import { buildSandboxExecArguments, normalizeTaskSandboxProfileOptions, type TaskSandboxProfileOptions } from "./sandbox-profile.js";
import { assertSystemPublishedExecutablePath, inspectSystemPublishedExecutablePath } from "./system-published-executable.js";
import type { ResolvedTaskProfile } from "./task-profile.js";
import {
  RootHelperSnapshotTaskExecutor,
  validateRootHelperSnapshotTaskRequest,
  type RootHelperSnapshotRequestAdmission,
  type RootHelperSnapshotTaskRequest
} from "./root-helper-snapshot.js";
import {
  isVirtualizationGuestIdentity,
  parseVirtualizationGuestIdentity,
  snapshotSignedVirtualizationGuestAttestation,
  sameVirtualizationGuestIdentity,
  validateVirtualizationGuestAttestation,
  type SignedVirtualizationGuestAttestation,
  type VirtualizationGuestAttestation,
  type VirtualizationGuestAttestationVerifier,
  type VirtualizationGuestIdentity
} from "./virtualization-guest-attestation.js";
import { verifyVirtualizationGuestImage, type LoadedVirtualizationGuestImage } from "./virtualization-guest-image.js";
import type { VirtualizationGuestVmLifecycle } from "./virtualization-guest-lifecycle.js";
import {
  virtualizationGuestProfileDigest,
  virtualizationGuestTaskDigest
} from "./virtualization-guest-executor.js";
import { validateUnsignedVirtualizationGuestResponse, validateUnsignedVirtualizationGuestStatusResponse, virtualizationGuestRequestDigest } from "./virtualization-guest-transport.js";
import type {
  UnsignedVirtualizationGuestResponse,
  UnsignedVirtualizationGuestStatusResponse,
  VirtualizationGuestExchangeOptions,
  VirtualizationGuestRequestInput,
  VirtualizationGuestStatusLookupInput
} from "./virtualization-guest-transport.js";

const EVIDENCE_REFERENCE_PATTERN = /^[A-Za-z0-9._:/-]{1,256}$/u;
const SANDBOX_PROFILE_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
const MAX_TASK_RESULT_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_TASK_RESULT_DURATION_MS = 1_200_000;
const MAX_TASK_RESULT_SUMMARY_BYTES = 512;
const SYSTEM_PUBLISHED_TASK_DISPATCH_PATHS = new Set([
  "/bin/bash",
  "/bin/dash",
  "/bin/ksh",
  "/bin/sh",
  "/bin/zsh",
  "/usr/bin/arch",
  "/usr/bin/env",
  "/usr/bin/node",
  "/usr/bin/nodejs",
  "/usr/bin/osascript",
  "/usr/bin/perl",
  "/usr/bin/php",
  "/usr/bin/python",
  "/usr/bin/python3",
  "/usr/bin/ruby",
  "/usr/bin/swift",
  "/usr/bin/xcrun"
]);

export type {
  SignedVirtualizationGuestAttestation,
  VirtualizationGuestAttestation,
  VirtualizationGuestIdentity
} from "./virtualization-guest-attestation.js";
export { validateVirtualizationGuestAttestation } from "./virtualization-guest-attestation.js";

/** Mechanisms with a governed runner contract; availability remains evidence-gated. */
export type TaskIsolationMechanism = "sandbox-exec" | "app-sandbox" | "virtualization" | "docker-container";
/** Public exposure state; staging evidence must never become a production capability. */
export type TaskRunnerPublicEnablement = "unavailable" | "staging-only" | "production";
export type TaskCredentialIsolationProof =
  | "sandbox-exec-empty-env-deny-secret-zones-v1"
  | "app-sandbox-container-no-host-credentials-v1"
  | "virtualization-no-host-credentials-v1"
  | "docker-container-no-host-credentials-v1";

export interface TaskExecutionControl {
  timeoutMs: number;
  shouldCancel: () => boolean;
  /** Broker-owned admission for an exact root-helper signed envelope. */
  rootHelperSnapshotRequestAuthority?: RootHelperSnapshotRequestAdmission;
  onProcessStarted?: (snapshot: ProcessOwnershipSnapshot) => void;
  onProcessOwnershipChanged?: (snapshot: ProcessOwnershipSnapshot) => void;
  onGuestRequestAdmitted?: (admission: VirtualizationGuestTaskAdmission) => void;
  /** Called after the guest response is authenticated and mapped, before the runner returns. */
  onGuestResultVerified?: (result: TaskExecutionResult) => void;
  onContainerCreated?: (metadata: Omit<ContainerTaskJobMetadata, "taskDescriptorDigest">) => void;
  onWorkspaceImport?: (path: string, phase: "intent" | "verified") => void;
}

/** Non-secret identity captured immediately before a guest request is sent. */
export interface VirtualizationGuestTaskAdmission {
  requestId: string;
  nonce: string;
  requestDigest: string;
  guestIdentity: VirtualizationGuestIdentity;
  profileDigest: string;
  taskDigest: string;
  timeoutMs: number;
  outputCapBytes: number;
}

export interface TaskRecoveryRequest {
  metadata: GuestTaskJobMetadata;
  shouldCancel?: () => boolean;
  authorizeStatusLookup: (input: VirtualizationGuestStatusLookupInput) => void;
}

export type TaskVerificationStatus = "verified" | "failed" | "unknown" | "not_run";

export interface TaskExecutionResult {
  containerCleanupVerified?: boolean;
  changedPaths?: readonly string[];
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
  /** Host persistence surfaces are isolated from the task boundary. */
  persistence: "isolated";
  /** Mechanism-bound proof that host/controller credentials are not inherited. */
  credentialIsolation: TaskCredentialIsolationProof;
  /** App Sandbox currently observes descendants without containing escaped process groups. */
  processTree: "owned" | "observer-only";
  processTreePolicy: "single_process" | "owned_group";
  evidenceRef: string;
  /** Explicit executable-selection proof for the selected host boundary. */
  executableSelection?: "system-published-root-owned-v1" | "descriptor-snapshot-root-helper-v1" | "app-sandbox-helper-v1";
  /** Required for Virtualization.framework guests; absent for host sandboxes. */
  virtualizationGuest?: VirtualizationGuestIdentity;
  containerImage?: { imageId: string; engineId: string };
}

/**
 * The Broker owns task admission, but a task cannot run without an explicitly
 * selected isolation boundary. The default runner is intentionally unavailable
 * so enabling a profile cannot silently fall back to the unsandboxed Broker.
 */
export interface TaskRunner {
  readonly available: boolean;
  /** Host release state used by production startup before public capability exposure. */
  readonly publicEnablement: TaskRunnerPublicEnablement;
  /** Host-owned mechanism used by this runner; null means no executable boundary. */
  readonly mechanism: TaskIsolationMechanism | null;
  readonly isolationProof: TaskIsolationProof | null;
  /** Stop accepting work and drain any Broker-owned OS processes. */
  close?(): Promise<void>;
  run(profile: ResolvedTaskProfile, control: TaskExecutionControl): Promise<TaskExecutionResult>;
  recoverUnknownTask?(request: TaskRecoveryRequest): Promise<TaskExecutionResult>;
  recoverContainerTask?(metadata: ContainerTaskJobMetadata): Promise<boolean>;
}

/**
 * Production startup must not expose a staging runner as a public task
 * capability. An unavailable runner remains fail-closed and may be reported
 * as runtime-unavailable; an available non-production runner is a startup
 * configuration error because it could otherwise create a false release.
 */
export function assertTaskRunnerPublicEnablement(
  taskToolEnabled: boolean,
  taskRunner: Pick<TaskRunner, "available" | "publicEnablement"> | undefined
): void {
  if (!taskToolEnabled || taskRunner === undefined || !taskRunner.available) return;
  if (taskRunner.publicEnablement !== "production") {
    throw new Error("Enabled mac_task_run requires a production task runner release");
  }
}

export class FailClosedTaskRunner implements TaskRunner {
  readonly available = false;
  readonly publicEnablement: TaskRunnerPublicEnablement = "unavailable";
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
  /** Canonical Broker-owned roots denied by the task profile, including persistence roots. */
  protectedFilesystemRoots?: readonly string[];
  /** Test-only override; production reads volume identity from the protected native adapter. */
  filesystemIdentityObserver?: (rootPath: string) => unknown;
  /**
   * Host executable-selection boundary. The default remains descriptor-backed
   * and unavailable on hosts without the native launcher. The system-published
   * mode is restricted to an explicit Broker-owned executable allowlist.
   */
  executionBoundary?: "descriptor" | "system-published";
  /** Fixed root-owned executables accepted by the system-published boundary. */
  systemPublishedExecutableAllowlist?: readonly string[];
  /** Explicit operator acceptance of the host system-published evidence. */
  systemPublishedExecutablePathAccepted?: boolean;
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
  readonly publicEnablement: TaskRunnerPublicEnablement;
  readonly mechanism: TaskIsolationMechanism = "sandbox-exec";
  readonly isolationProof: TaskIsolationProof | null;
  private readonly supervisor: Pick<ProcessSupervisor, "run"> & { close?: () => Promise<void> };
  private readonly filesystemIdentityObserver: (rootPath: string) => unknown;
  private readonly sandboxProfileOptions: TaskSandboxProfileOptions;
  private readonly executionBoundary: "descriptor" | "system-published";
  private readonly systemPublishedExecutableAllowlist: ReadonlySet<string>;

  constructor(options: SandboxExecTaskRunnerOptions = {}) {
    const proof = options.isolationProof === null || options.isolationProof === undefined
      ? null
      : validateTaskIsolationProof(options.isolationProof);
    this.isolationProof = proof;
    this.executionBoundary = options.executionBoundary ?? "descriptor";
    if (this.executionBoundary !== "descriptor" && this.executionBoundary !== "system-published") {
      throw new Error("Task executable-selection boundary is invalid");
    }
    const executableAllowlist = options.systemPublishedExecutableAllowlist ?? [];
    if (!Array.isArray(executableAllowlist) || executableAllowlist.length > 32 ||
        executableAllowlist.some((path) => !isCanonicalTaskPath(path)) || new Set(executableAllowlist).size !== executableAllowlist.length) {
      throw new Error("System-published task executable allowlist is invalid");
    }
    if (this.executionBoundary === "system-published" && executableAllowlist.some((path) =>
      SYSTEM_PUBLISHED_TASK_DISPATCH_PATHS.has(path) && path !== "/bin/sh")) {
      throw new Error("System-published task executable allowlist cannot contain interpreters or dispatch launchers");
    }
    if (options.systemPublishedExecutablePathAccepted !== undefined && typeof options.systemPublishedExecutablePathAccepted !== "boolean") {
      throw new Error("System-published task executable acceptance is invalid");
    }
    if (this.executionBoundary === "system-published" && options.supervisor !== undefined) {
      throw new Error("System-published task execution cannot use an injected supervisor");
    }
    this.systemPublishedExecutableAllowlist = new Set(executableAllowlist);
    const usesHostProcessSupervisor = options.supervisor === undefined;
    this.supervisor = options.supervisor ?? new ProcessSupervisor({
      allowedEnvironmentKeys: options.allowedEnvironmentKeys ?? [],
      ...(this.executionBoundary === "system-published"
        ? {
          requireRootOwnedExecutable: true,
          requireSystemPublishedExecutable: true
        }
        : {
          // A host sandbox is not a complete executable-selection boundary.
          // Keep descriptor-mode task admission closed until the native
          // descriptor launcher is available and independently attested.
          requireDescriptorExecution: true
        })
    });
    this.sandboxProfileOptions = normalizeTaskSandboxProfileOptions({
      ...(options.protectedFilesystemRoots === undefined ? {} : { protectedFilesystemRoots: [...options.protectedFilesystemRoots] })
    });
    this.filesystemIdentityObserver = options.filesystemIdentityObserver ?? ((rootPath) => {
      const native = loadNativePeerAdapter() as unknown as NativeTaskFilesystemIdentityAdapter;
      return native.statStorageVolumeWithinRoot(rootPath);
    });
    // The current sandbox evidence covers only the no-fork single-process
    // profile. Keep the owned-group variant unavailable until a separate
    // process-tree ownership and escape-resistance proof is accepted.
    const executableSelectionAvailable = !usesHostProcessSupervisor ||
      (this.executionBoundary === "system-published"
        ? options.systemPublishedExecutablePathAccepted === true &&
          this.systemPublishedExecutableAllowlist.size > 0 &&
          inspectSystemPublishedExecutablePath("/usr/bin/sandbox-exec")
        : inspectProcessDescriptorExecutionCapability().available);
    this.available = options.enabled === true && options.hostEvidenceAccepted === true &&
      proof?.sandboxMechanism === "sandbox-exec" &&
      proof?.processTreePolicy === "single_process" && process.platform === "darwin" &&
      executableSelectionAvailable;
    // sandbox-exec is deprecated on macOS and remains a staging-only probe;
    // it must never satisfy the production public-capability gate.
    this.publicEnablement = this.available ? "staging-only" : "unavailable";
  }

  close(): Promise<void> {
    return this.supervisor.close?.() ?? Promise.resolve();
  }

  async run(profile: ResolvedTaskProfile, control: TaskExecutionControl): Promise<TaskExecutionResult> {
    if (!this.available || this.isolationProof === null) {
      throw new BrokerError("POLICY_DENIED", "Task isolation boundary is not enabled");
    }
    requireTaskIsolationProof(this.isolationProof, profile, this.mechanism);
    const executionKind = profile.executionKind ?? "binary";
    if (executionKind === "posix-sh-script") {
      if (profile.process.executable !== "/bin/sh" ||
          (this.executionBoundary === "system-published" && !this.systemPublishedExecutableAllowlist.has("/bin/sh"))) {
        throw new BrokerError("POLICY_DENIED", "Broker-owned shell script is not admitted by this executable boundary");
      }
      await assertSystemPublishedExecutablePath("/bin/sh");
      await assertSystemPublishedExecutablePath("/bin/bash");
    } else if (profile.process.executable === "/bin/sh") {
      throw new BrokerError("POLICY_DENIED", "The shell interpreter requires a Broker-owned script profile");
    }
    if (this.executionBoundary === "system-published") {
      if (this.isolationProof.executableSelection !== "system-published-root-owned-v1" ||
          !this.systemPublishedExecutableAllowlist.has(profile.process.executable)) {
        throw new BrokerError("POLICY_DENIED", "Task executable is not in the system-published profile allowlist");
      }
      await assertSystemPublishedExecutablePath(profile.process.executable);
    }
    const taskExecutableIdentity = await captureTaskProcessPathIdentity(profile.process.executable, "executable");
    const taskCwdIdentity = await captureTaskProcessPathIdentity(profile.cwd, "directory");
    const taskFilesystemRootIdentities = await captureTaskFilesystemRootIdentities(profile.filesystemRoots);
    const filesystemIdentity = captureTaskFilesystemIdentity(profile, this.filesystemIdentityObserver);
    const args = buildSandboxExecArguments(profile, this.sandboxProfileOptions);
    const requiresOwnershipPersistence = control.onProcessStarted !== undefined || control.onProcessOwnershipChanged !== undefined;
    const ownershipProof = profile.processTreePolicy === "single_process"
      ? "sandbox-exec-no-fork-v1" as const
      : undefined;
    const annotateOwnership = (snapshot: ProcessOwnershipSnapshot): ProcessOwnershipSnapshot =>
      ownershipProof === undefined ? snapshot : { ...snapshot, ownershipProof };
    const onStarted = requiresOwnershipPersistence
      ? async (snapshot: ProcessOwnershipSnapshot): Promise<void> => {
        assertTaskFilesystemIdentityStable(profile, filesystemIdentity, this.filesystemIdentityObserver);
        await assertProcessPathIdentityStable(profile.process.executable, taskExecutableIdentity, "executable");
        await assertProcessPathIdentityStable(profile.cwd, taskCwdIdentity, "directory");
        await assertTaskFilesystemRootIdentitiesStable(profile.filesystemRoots, taskFilesystemRootIdentities);
        control.onProcessStarted?.(annotateOwnership(snapshot));
      }
      : undefined;
    const onOwnershipChanged = control.onProcessOwnershipChanged === undefined
      ? undefined
      : (snapshot: ProcessOwnershipSnapshot): void => {
        control.onProcessOwnershipChanged?.(annotateOwnership(snapshot));
      };
    let result: ProcessExecutionResult;
    try {
      result = await this.supervisor.run({
        executable: "/usr/bin/sandbox-exec",
        args,
        cwd: profile.cwd,
        ...(profile.process.environment === undefined ? {} : { environment: profile.process.environment }),
        timeoutMs: Math.min(control.timeoutMs, profile.process.timeoutMs),
        outputCapBytes: profile.process.outputCapBytes,
        requireCleanExitProof: true,
        ...(executionKind === "posix-sh-script" ? { stdin: profile.scriptContent! } : {}),
        shouldCancel: control.shouldCancel,
        ...(onStarted === undefined ? {} : { onStarted }),
        ...(onOwnershipChanged === undefined ? {} : { onOwnershipChanged })
      });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("EXECUTION_FAILED", "Sandboxed task could not be started");
    }
    await assertProcessPathIdentityStable(profile.process.executable, taskExecutableIdentity, "executable");
    await assertProcessPathIdentityStable(profile.cwd, taskCwdIdentity, "directory");
    await assertTaskFilesystemRootIdentitiesStable(profile.filesystemRoots, taskFilesystemRootIdentities);
    assertTaskFilesystemIdentityStable(profile, filesystemIdentity, this.filesystemIdentityObserver);
    return mapProcessResult(result);
  }
}

/**
 * Narrow descriptor-registry boundary required by the root-helper runner.
 * The registry owns the actual descriptors; the runner receives only a
 * one-shot handoff during the authenticated helper exchange.
 */
export interface DescriptorSnapshotTaskRegistry {
  readonly available: boolean;
  prepare(input: DescriptorSnapshotPreparationInput): Promise<PreparedDescriptorSnapshot>;
  withSnapshot<T>(
    snapshot: PreparedDescriptorSnapshot,
    callback: (handoff: DescriptorSnapshotHandoff) => Promise<T> | T
  ): Promise<T>;
  close(): Promise<void>;
}

export interface RootHelperSnapshotTaskRunnerOptions {
  /** Explicit opt-in; production remains disabled until root-domain evidence is accepted. */
  enabled?: boolean;
  /** Independent host evidence gate; MCP arguments cannot supply it. */
  hostEvidenceAccepted?: boolean;
  isolationProof?: TaskIsolationProof | null;
  executor?: Pick<RootHelperSnapshotTaskExecutor, "available" | "publicEnablement" | "run" | "close">;
  snapshotRegistry?: DescriptorSnapshotTaskRegistry;
}

/**
 * Broker TaskRunner adapter for the authenticated root-helper snapshot path.
 * It binds the resolved profile to one-shot descriptors and forwards helper
 * process-ownership events so the existing Broker Job recovery ledger remains
 * authoritative. No pathname or caller-selected executable crosses IPC.
 */
export class RootHelperSnapshotTaskRunner implements TaskRunner {
  readonly available: boolean;
  readonly publicEnablement: TaskRunnerPublicEnablement;
  readonly mechanism: TaskIsolationMechanism = "sandbox-exec";
  readonly isolationProof: TaskIsolationProof | null;
  private readonly executor: Pick<RootHelperSnapshotTaskExecutor, "available" | "run" | "close"> | undefined;
  private readonly snapshotRegistry: DescriptorSnapshotTaskRegistry | undefined;

  constructor(options: RootHelperSnapshotTaskRunnerOptions = {}) {
    const proof = options.isolationProof === null || options.isolationProof === undefined
      ? null
      : validateTaskIsolationProof(options.isolationProof);
    this.isolationProof = proof;
    this.executor = options.executor;
    this.snapshotRegistry = options.snapshotRegistry;
    this.available = process.platform === "darwin" &&
      options.enabled === true &&
      options.hostEvidenceAccepted === true &&
      proof?.sandboxMechanism === "sandbox-exec" &&
      proof.processTreePolicy === "single_process" &&
      proof.executableSelection === "descriptor-snapshot-root-helper-v1" &&
      options.executor?.available === true &&
      options.snapshotRegistry?.available === true;
    this.publicEnablement = this.available && options.executor?.publicEnablement === "production"
      ? "production"
      : this.available
        ? "staging-only"
        : "unavailable";
  }

  async close(): Promise<void> {
    let firstError: unknown;
    try {
      await this.executor?.close();
    } catch (error) {
      firstError = error;
    }
    try {
      await this.snapshotRegistry?.close();
    } catch (error) {
      firstError ??= error;
    }
    if (firstError !== undefined) throw firstError;
  }

  async run(profile: ResolvedTaskProfile, control: TaskExecutionControl): Promise<TaskExecutionResult> {
    if (!this.available || this.isolationProof === null || this.executor === undefined || this.snapshotRegistry === undefined) {
      throw new BrokerError("POLICY_DENIED", "Root helper snapshot task boundary is not enabled");
    }
    requireTaskIsolationProof(this.isolationProof, profile, this.mechanism);
    if (this.isolationProof.executableSelection !== "descriptor-snapshot-root-helper-v1") {
      throw new BrokerError("POLICY_DENIED", "Root helper executable-selection proof is unavailable");
    }
    if (control.rootHelperSnapshotRequestAuthority === undefined ||
        typeof control.rootHelperSnapshotRequestAuthority.admit !== "function" ||
        typeof control.rootHelperSnapshotRequestAuthority.release !== "function") {
      throw new BrokerError("PRIVILEGE_DENIED", "Root helper task admission is not bound to the Broker authority");
    }
    const environment = { ...(profile.process.environment ?? {}) };
    const args = [...profile.process.args];
    const snapshot = await this.snapshotRegistry.prepare({
      profile: profile.profile,
      executablePath: profile.process.executable,
      cwdPath: profile.cwd,
      taskDescriptorDigest: taskDescriptorDigest(profile),
      argsDigest: sha256(canonicalJson(args)),
      environmentDigest: sha256(canonicalJson(environment)),
      filesystemRootsDigest: sha256(canonicalJson(profile.filesystemRoots)),
      sandboxProfile: profile.sandboxProfile,
      networkPolicy: profile.networkPolicy,
      processTreePolicy: profile.processTreePolicy
    });
    const timeoutMs = Math.min(control.timeoutMs, profile.process.timeoutMs);
    try {
      return await this.snapshotRegistry.withSnapshot(snapshot, async (handoff) => {
        const request: RootHelperSnapshotTaskRequest = validateRootHelperSnapshotTaskRequest({
          schemaVersion: "0.1",
          signedAttestation: handoff.attestation,
          executableFd: handoff.executableFd,
          cwdFd: handoff.cwdFd,
          args,
          environment,
          timeoutMs,
          outputCapBytes: profile.process.outputCapBytes
        });
        const result = await this.executor!.run(request, {
          timeoutMs,
          shouldCancel: control.shouldCancel,
          ...(control.rootHelperSnapshotRequestAuthority === undefined
            ? {}
            : { requestAuthority: control.rootHelperSnapshotRequestAuthority }),
          ...(control.onProcessStarted === undefined ? {} : { onProcessStarted: control.onProcessStarted }),
          ...(control.onProcessOwnershipChanged === undefined ? {} : { onProcessOwnershipChanged: control.onProcessOwnershipChanged })
        });
        return mapProcessResult(result);
      });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("UNKNOWN_OUTCOME", "Root helper task outcome could not be established", true);
    }
  }
}

export interface AppSandboxTaskExecutionRequest {
  schemaVersion: "0.1";
  signedAttestation: DescriptorSnapshotHandoff["attestation"];
  executableFd: number;
  cwdFd: number;
  filesystemRoots: readonly string[];
  executionKind: "binary" | "posix-sh-script";
  scriptFd?: number;
  scriptContentSha256?: string;
  args: readonly string[];
  environment: Readonly<Record<string, string>>;
  networkPolicy: "none" | "allowlist";
  networkAllowlist: readonly string[];
  timeoutMs: number;
  outputCapBytes: number;
}

export interface AppSandboxTaskExecutor {
  readonly available: boolean;
  readonly publicEnablement?: TaskRunnerPublicEnablement;
  run(
    request: AppSandboxTaskExecutionRequest,
    control: Pick<TaskExecutionControl, "timeoutMs" | "shouldCancel" | "onProcessStarted" | "onProcessOwnershipChanged">
  ): Promise<ProcessExecutionResult>;
  close?(): Promise<void>;
}

export interface AppSandboxTaskRunnerOptions {
  /** Explicit opt-in; production remains disabled until the helper is released. */
  enabled?: boolean;
  /** Independent host evidence gate; MCP arguments cannot supply it. */
  hostEvidenceAccepted?: boolean;
  isolationProof?: TaskIsolationProof | null;
  executor?: Pick<AppSandboxTaskExecutor, "available" | "publicEnablement" | "run" | "close">;
  snapshotRegistry?: DescriptorSnapshotTaskRegistry;
}

/**
 * Broker seam for an App Sandbox helper. The native executor is supplied by
 * the startup assembly only after independent host evidence is accepted; it
 * materializes the one-shot descriptor handoff inside the helper container and
 * returns authenticated bounded output. No host pathname crosses this boundary.
 */
export class AppSandboxTaskRunner implements TaskRunner {
  readonly mechanism: TaskIsolationMechanism = "app-sandbox";
  readonly isolationProof: TaskIsolationProof | null;
  private readonly configuredAvailable: boolean;
  private readonly executor: Pick<AppSandboxTaskExecutor, "available" | "run" | "close"> | undefined;
  private readonly snapshotRegistry: DescriptorSnapshotTaskRegistry | undefined;

  constructor(options: AppSandboxTaskRunnerOptions = {}) {
    const proof = options.isolationProof === null || options.isolationProof === undefined
      ? null
      : validateTaskIsolationProof(options.isolationProof);
    this.isolationProof = proof;
    this.executor = options.executor;
    this.snapshotRegistry = options.snapshotRegistry;
    this.configuredAvailable = process.platform === "darwin" &&
      options.enabled === true &&
      options.hostEvidenceAccepted === true &&
      proof?.sandboxMechanism === "app-sandbox" &&
      proof.processTree === "observer-only" &&
      proof.processTreePolicy === "single_process" &&
      proof.executableSelection === "app-sandbox-helper-v1" &&
      options.executor?.available === true &&
      options.snapshotRegistry?.available === true;
    // The physical double-fork probe demonstrated that App Sandbox plus the
    // helper's process-event observer does not enforce the declared
    // single-process policy. Keep this runner staging-only until an
    // OS-enforced process-tree boundary replaces that observer.
  }

  get available(): boolean {
    return this.configuredAvailable && this.executor?.available === true && this.snapshotRegistry?.available === true;
  }

  get publicEnablement(): TaskRunnerPublicEnablement {
    return this.available ? "staging-only" : "unavailable";
  }

  async close(): Promise<void> {
    let firstError: unknown;
    try {
      await this.executor?.close?.();
    } catch (error) {
      firstError = error;
    }
    try {
      await this.snapshotRegistry?.close();
    } catch (error) {
      firstError ??= error;
    }
    if (firstError !== undefined) throw firstError;
  }

  async run(profile: ResolvedTaskProfile, control: TaskExecutionControl): Promise<TaskExecutionResult> {
    if (!this.available || this.isolationProof === null || this.executor === undefined ||
        this.executor.available !== true || this.snapshotRegistry === undefined) {
      throw new BrokerError("POLICY_DENIED", "App Sandbox task boundary is not enabled");
    }
    requireTaskIsolationProof(this.isolationProof, profile, this.mechanism);
    if (this.isolationProof.executableSelection !== "app-sandbox-helper-v1") {
      throw new BrokerError("POLICY_DENIED", "App Sandbox helper executable-selection proof is unavailable");
    }
    const environment = { ...(profile.process.environment ?? {}) };
    const args = [...profile.process.args];
    const executionKind = profile.executionKind ?? "binary";
    if (executionKind === "posix-sh-script" && profile.scriptPath === undefined) {
      throw new BrokerError("POLICY_DENIED", "App Sandbox script profile is missing its Broker-owned script");
    }
    const snapshot = await this.snapshotRegistry.prepare({
      audience: "mac-operator-app-sandbox-helper-v0.1",
      profile: profile.profile,
      executablePath: profile.process.executable,
      cwdPath: profile.cwd,
      ...(profile.scriptPath === undefined ? {} : { scriptPath: profile.scriptPath }),
      taskDescriptorDigest: taskDescriptorDigest(profile),
      argsDigest: sha256(canonicalJson(args)),
      environmentDigest: sha256(canonicalJson(environment)),
      filesystemRootsDigest: sha256(canonicalJson(profile.filesystemRoots)),
      sandboxProfile: profile.sandboxProfile,
      networkPolicy: profile.networkPolicy,
      processTreePolicy: profile.processTreePolicy
    });
    const timeoutMs = Math.min(control.timeoutMs, profile.process.timeoutMs);
    try {
      return await this.snapshotRegistry.withSnapshot(snapshot, async (handoff) => {
        if (handoff.attestation.payload.audience !== "mac-operator-app-sandbox-helper-v0.1") {
          throw new BrokerError("POLICY_DENIED", "App Sandbox snapshot attestation audience is invalid");
        }
        if (executionKind === "posix-sh-script" &&
            (handoff.scriptFd === undefined || handoff.scriptContentSha256 === undefined)) {
          throw new BrokerError("POLICY_DENIED", "App Sandbox script descriptor is unavailable");
        }
        const result = await this.executor!.run({
          schemaVersion: "0.1",
          signedAttestation: handoff.attestation,
          executableFd: handoff.executableFd,
          cwdFd: handoff.cwdFd,
          filesystemRoots: [...profile.filesystemRoots],
          executionKind,
          ...(executionKind === "posix-sh-script"
            ? { scriptFd: handoff.scriptFd!, scriptContentSha256: handoff.scriptContentSha256! }
            : {}),
          args,
          environment,
          networkPolicy: profile.networkPolicy,
          networkAllowlist: [...profile.networkAllowlist],
          timeoutMs,
          outputCapBytes: profile.process.outputCapBytes
        }, {
          timeoutMs,
          shouldCancel: control.shouldCancel,
          ...(control.onProcessStarted === undefined ? {} : { onProcessStarted: control.onProcessStarted }),
          ...(control.onProcessOwnershipChanged === undefined ? {} : { onProcessOwnershipChanged: control.onProcessOwnershipChanged })
        });
        return mapProcessResult(result);
      });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("UNKNOWN_OUTCOME", "App Sandbox task outcome could not be established", true);
    }
  }
}

export interface VirtualizationTaskExecutionRequest {
  readonly profile: ResolvedTaskProfile;
  readonly control: TaskExecutionControl;
  readonly guestIdentity: VirtualizationGuestIdentity;
}

/**
 * Digest of the Broker-owned policy material sent to a guest by reference.
 * The digest is safe to cross the guest boundary; the underlying paths,
 * executable, arguments, and environment never leave the Broker.
 */
export function virtualizationProfileDigest(profile: ResolvedTaskProfile): string {
  return virtualizationGuestProfileDigest(profile);
}

/** Digest of one exact resolved task, including its Broker-owned process limits. */
export function virtualizationTaskDigest(
  profile: ResolvedTaskProfile,
  profileDigest = virtualizationProfileDigest(profile)
): string {
  return virtualizationGuestTaskDigest({
    profile: profile.profile,
    sandboxProfile: profile.sandboxProfile,
    filesystemRoots: profile.filesystemRoots,
    networkPolicy: profile.networkPolicy,
    networkAllowlist: profile.networkAllowlist,
    credentialPolicy: profile.credentialPolicy,
    processTreePolicy: profile.processTreePolicy,
    verificationStrategy: profile.verificationStrategy,
    executable: profile.process.executable,
    args: profile.process.args,
    cwd: profile.process.cwd,
    ...(profile.process.environment === undefined ? {} : { environment: profile.process.environment }),
    timeoutMs: profile.process.timeoutMs,
    outputCapBytes: profile.process.outputCapBytes
  }, profileDigest);
}

/** Digest of the exact local task descriptor persisted with a running Job. */
export function taskDescriptorDigest(profile: ResolvedTaskProfile): string {
  const baseDigest = profile.containerExecution === undefined ? virtualizationTaskDigest(profile) :
    sha256(canonicalJson({ base: virtualizationTaskDigest(profile), container: profile.containerExecution }));
  if (profile.executionKind !== "posix-sh-script" || profile.scriptPath === undefined || profile.scriptContentSha256 === undefined) {
    return baseDigest;
  }
  return sha256(canonicalJson({
    baseDigest,
    executionKind: profile.executionKind,
    scriptPath: profile.scriptPath,
    scriptContentSha256: profile.scriptContentSha256
  }));
}

/**
 * Native Virtualization.framework adapter seam. The adapter owns VM creation,
 * guest boot, and guest-side evidence; the TypeScript Broker never accepts a
 * caller-supplied image path or launches a host process as a substitute.
 */
export interface VirtualizationTaskExecutor {
  readonly available: boolean;
  readonly guestIdentity: VirtualizationGuestIdentity | null;
  readonly attestation: VirtualizationGuestAttestation | null;
  /** Optional cryptographic provenance for hosts that enable signed attestations. */
  readonly signedAttestation?: SignedVirtualizationGuestAttestation;
  run(request: VirtualizationTaskExecutionRequest): Promise<TaskExecutionResult>;
  recoverUnknownTask?(request: TaskRecoveryRequest): Promise<TaskExecutionResult>;
  close?(): Promise<void>;
}

/**
 * Minimal transport surface required by the Broker-owned guest executor.
 * A native Virtualization.framework implementation can satisfy this interface
 * without exposing its VM or virtio details to the TypeScript Broker.
 */
export interface VirtualizationGuestTransport {
  execute(input: VirtualizationGuestRequestInput, options?: VirtualizationGuestExchangeOptions): Promise<UnsignedVirtualizationGuestResponse>;
  lookup?(input: VirtualizationGuestStatusLookupInput, options?: VirtualizationGuestExchangeOptions): Promise<UnsignedVirtualizationGuestStatusResponse>;
  close(): void;
}

export interface VirtualizationGuestTransportExecutorOptions {
  /** Explicit host-evidence gate; false keeps the executor unavailable. */
  available: boolean;
  transport: VirtualizationGuestTransport;
  guestIdentity: VirtualizationGuestIdentity;
  attestation: VirtualizationGuestAttestation;
  signedAttestation?: SignedVirtualizationGuestAttestation;
}

/**
 * Adapts the authenticated guest transport to the TaskRunner contract.
 * It sends only policy/task digests and bounded budgets; the guest response is
 * accepted only after the transport has verified its request binding and HMAC.
 */
export class VirtualizationGuestTransportExecutor implements VirtualizationTaskExecutor {
  readonly available: boolean;
  readonly guestIdentity: VirtualizationGuestIdentity;
  readonly attestation: VirtualizationGuestAttestation;
  readonly signedAttestation?: SignedVirtualizationGuestAttestation;
  private readonly transport: VirtualizationGuestTransport;
  private closed = false;

  constructor(options: VirtualizationGuestTransportExecutorOptions) {
    if (typeof options.available !== "boolean" || options.transport === undefined ||
        typeof options.transport.execute !== "function" || typeof options.transport.close !== "function") {
      throw new Error("Virtualization guest transport executor options are invalid");
    }
    const guestIdentity = parseVirtualizationGuestIdentity(options.guestIdentity);
    const attestation = validateVirtualizationGuestAttestation(options.attestation);
    if (!sameVirtualizationGuestIdentity(guestIdentity, attestation.guestIdentity)) {
      throw new Error("Virtualization guest transport identity does not match its attestation");
    }
    this.available = options.available;
    this.transport = options.transport;
    this.guestIdentity = freezeRuntimeSnapshot(guestIdentity);
    this.attestation = freezeRuntimeSnapshot(attestation);
    if (options.signedAttestation !== undefined) {
      this.signedAttestation = snapshotSignedVirtualizationGuestAttestation(options.signedAttestation);
    }
  }

  async run(request: VirtualizationTaskExecutionRequest): Promise<TaskExecutionResult> {
    if (this.closed || !this.available) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest transport executor is not available");
    }
    const profileDigest = virtualizationProfileDigest(request.profile);
    const taskDigest = virtualizationTaskDigest(request.profile, profileDigest);
    const response = await this.transport.execute({
      guestIdentity: this.guestIdentity,
      sandboxProfile: request.profile.sandboxProfile,
      profileDigest,
      taskDigest,
      processTreePolicy: request.profile.processTreePolicy,
      timeoutMs: Math.min(request.control.timeoutMs, request.profile.process.timeoutMs),
      outputCapBytes: request.profile.process.outputCapBytes
    }, {
      shouldCancel: request.control.shouldCancel,
      onRequestAdmitted: (admitted) => request.control.onGuestRequestAdmitted?.(freezeRuntimeSnapshot({
        requestId: admitted.requestId,
        nonce: admitted.nonce,
        requestDigest: virtualizationGuestRequestDigest(admitted),
        guestIdentity: { ...admitted.guestIdentity },
        profileDigest: admitted.profileDigest,
        taskDigest: admitted.taskDigest,
        timeoutMs: admitted.timeoutMs,
        outputCapBytes: admitted.outputCapBytes
      }))
    });
    const taskResult = mapVirtualizationGuestResponse(response, this.guestIdentity);
    request.control.onGuestResultVerified?.(taskResult);
    return taskResult;
  }

  async recoverUnknownTask(request: TaskRecoveryRequest): Promise<TaskExecutionResult> {
    if (this.closed || !this.available) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest transport executor is not available");
    }
    if (typeof this.transport.lookup !== "function") {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest status lookup is not enabled");
    }
    const metadata = request.metadata;
    const response = await this.transport.lookup({
      guestIdentity: { ...metadata.guestIdentity },
      originalRequestId: metadata.requestId,
      originalNonce: metadata.nonce,
      originalRequestDigest: metadata.requestDigest,
      timeoutMs: metadata.timeoutMs,
      outputCapBytes: metadata.outputCapBytes
    }, {
      ...(request.shouldCancel === undefined ? {} : { shouldCancel: request.shouldCancel }),
      authorizeStatusLookup: request.authorizeStatusLookup
    });
    return mapVirtualizationGuestStatusResponse(response, this.guestIdentity, metadata);
  }

  async close(): Promise<void> {
    this.closed = true;
    this.transport.close();
  }
}

export interface VirtualizationTaskRunnerOptions {
  /** Explicit opt-in; production remains disabled until host evidence review. */
  enabled?: boolean;
  /** External evidence gate; this is not supplied by the MCP request. */
  hostEvidenceAccepted?: boolean;
  isolationProof?: TaskIsolationProof | null;
  executor?: VirtualizationTaskExecutor;
  /** Host-startup image preflight; caller/MCP arguments cannot supply this. */
  guestImage?: LoadedVirtualizationGuestImage | null;
  /** Broker-owned lifecycle required to bound each guest operation. */
  vmLifecycle?: VirtualizationGuestVmLifecycle;
  /** Optional host-owned verifier required when signed guest provenance is enabled. */
  attestationVerifier?: VirtualizationGuestAttestationVerifier;
}

/**
 * Disabled-by-default Virtualization.framework runner boundary.
 *
 * This class deliberately contains no VM implementation. Startup must bind a
 * Broker-owned lifecycle and native adapter; without that lifecycle or with a
 * missing, malformed, or changed guest identity, the runner stays unavailable.
 */
export class VirtualizationTaskRunner implements TaskRunner {
  readonly available: boolean;
  readonly publicEnablement: TaskRunnerPublicEnablement;
  readonly mechanism: TaskIsolationMechanism = "virtualization";
  readonly isolationProof: TaskIsolationProof | null;
  private readonly executor: VirtualizationTaskExecutor | undefined;
  private readonly guestImage: LoadedVirtualizationGuestImage | undefined;
  private readonly vmLifecycle: VirtualizationGuestVmLifecycle | undefined;
  private readonly attestationVerifier: VirtualizationGuestAttestationVerifier | undefined;
  private readonly signedAttestation: SignedVirtualizationGuestAttestation | undefined;

  constructor(options: VirtualizationTaskRunnerOptions = {}) {
    const proof = options.isolationProof === null || options.isolationProof === undefined
      ? null
      : validateTaskIsolationProof(options.isolationProof);
    this.isolationProof = proof;
    this.executor = options.executor;
    this.guestImage = options.guestImage === null || options.guestImage === undefined
      ? undefined
      : snapshotLoadedGuestImage(options.guestImage);
    this.vmLifecycle = options.vmLifecycle;
    this.attestationVerifier = options.attestationVerifier;
    this.signedAttestation = options.executor?.signedAttestation === undefined
      ? undefined
      : snapshotSignedVirtualizationGuestAttestation(options.executor.signedAttestation);
    const guest = proof?.virtualizationGuest;
    this.available = process.platform === "darwin" &&
      options.enabled === true &&
      options.hostEvidenceAccepted === true &&
      options.executor?.available === true &&
      this.guestImage !== undefined &&
      this.vmLifecycle?.available === true &&
      guest !== undefined &&
      sameVirtualizationGuestIdentity(guest, this.vmLifecycle.expectedGuestIdentity) &&
      sameVirtualizationGuestIdentity(guest, this.guestImage.guestIdentity) &&
      options.executor.guestIdentity !== null &&
      sameVirtualizationGuestIdentity(guest, options.executor.guestIdentity) &&
      options.executor.attestation !== null &&
      virtualizationAttestationMatchesProof(options.executor.attestation, proof) &&
      (this.attestationVerifier === undefined || signedAttestationMatches(
        this.signedAttestation,
        options.executor.attestation,
        this.attestationVerifier
      ));
    // The current Virtualization.framework seam is evidence-gated staging
    // infrastructure; production exposure requires a separate release review.
    this.publicEnablement = this.available ? "staging-only" : "unavailable";
  }

  close(): Promise<void> {
    return this.executor?.close?.() ?? Promise.resolve();
  }

  async run(profile: ResolvedTaskProfile, control: TaskExecutionControl): Promise<TaskExecutionResult> {
    if (!this.available || this.isolationProof === null || this.executor === undefined || this.vmLifecycle === undefined) {
      throw new BrokerError("POLICY_DENIED", "Virtualization task boundary is not enabled");
    }
    await this.assertGuestImageStable();
    this.assertGuestAttestationStable();
    const guestIdentity = this.isolationProof.virtualizationGuest;
    if (guestIdentity === undefined || !this.executor.available ||
        this.executor.guestIdentity === null ||
        !sameVirtualizationGuestIdentity(guestIdentity, this.executor.guestIdentity) ||
        this.executor.attestation === null ||
        !virtualizationAttestationMatchesProof(this.executor.attestation, this.isolationProof)) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest identity is unavailable or changed");
    }
    requireTaskIsolationProof(this.isolationProof, profile, this.mechanism);
    try {
      return await this.vmLifecycle.runTask(() => this.executor!.run({ profile, control, guestIdentity }));
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("UNKNOWN_OUTCOME", "Virtualized task outcome could not be established", true);
    }
  }

  async recoverUnknownTask(request: TaskRecoveryRequest): Promise<TaskExecutionResult> {
    if (!this.available || this.isolationProof === null || this.executor === undefined || this.vmLifecycle === undefined ||
        typeof this.executor.recoverUnknownTask !== "function") {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest status recovery is not enabled");
    }
    await this.assertGuestImageStable();
    this.assertGuestAttestationStable();
    const guestIdentity = this.isolationProof.virtualizationGuest;
    if (guestIdentity === undefined || !sameVirtualizationGuestIdentity(guestIdentity, this.executor.guestIdentity) ||
        this.executor.attestation === null || !virtualizationAttestationMatchesProof(this.executor.attestation, this.isolationProof) ||
        !sameVirtualizationGuestIdentity(guestIdentity, request.metadata.guestIdentity)) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest identity is unavailable or changed");
    }
    try {
      return await this.vmLifecycle.runTask(() => this.executor!.recoverUnknownTask!(request));
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("UNKNOWN_OUTCOME", "Virtualized task status could not be established", true);
    }
  }

  private async assertGuestImageStable(): Promise<void> {
    if (this.guestImage === undefined) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest image preflight is unavailable");
    }
    try {
      await verifyVirtualizationGuestImage(this.guestImage);
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("POLICY_DENIED", "Virtualization guest image identity could not be verified");
    }
  }

  private assertGuestAttestationStable(): void {
    if (this.attestationVerifier === undefined) return;
    if (!signedAttestationMatches(this.signedAttestation, this.executor?.attestation, this.attestationVerifier)) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest attestation is unavailable, revoked, or changed");
    }
  }
}

function signedAttestationMatches(
  signed: SignedVirtualizationGuestAttestation | undefined,
  attestation: VirtualizationGuestAttestation | null | undefined,
  verifier: VirtualizationGuestAttestationVerifier
): boolean {
  if (signed === undefined || attestation === null || attestation === undefined) return false;
  try {
    return canonicalJson(verifier.verify(signed).attestation) === canonicalJson(attestation);
  } catch {
    return false;
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

async function captureTaskProcessPathIdentity(
  path: string,
  kind: "executable" | "directory"
): Promise<ProcessPathIdentity> {
  try {
    return await captureProcessPathIdentity(path, kind);
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("POLICY_DENIED", "Task process path identity could not be established");
  }
}

async function captureTaskFilesystemRootIdentities(
  roots: readonly string[]
): Promise<readonly { rootPath: string; identity: ProcessPathIdentity }[]> {
  const uniqueRoots = [...new Set(roots)].sort();
  if (uniqueRoots.length === 0) throw new BrokerError("POLICY_DENIED", "Task filesystem roots are unavailable");
  return Promise.all(uniqueRoots.map(async (rootPath) => ({
    rootPath,
    identity: await captureTaskProcessPathIdentity(rootPath, "directory")
  })));
}

async function assertTaskFilesystemRootIdentitiesStable(
  roots: readonly string[],
  expected: readonly { rootPath: string; identity: ProcessPathIdentity }[]
): Promise<void> {
  const uniqueRoots = [...new Set(roots)].sort();
  if (uniqueRoots.length !== expected.length || uniqueRoots.some((rootPath, index) => rootPath !== expected[index]?.rootPath)) {
    throw new BrokerError("POLICY_DENIED", "Task filesystem roots changed after authorization");
  }
  for (const [index, rootPath] of uniqueRoots.entries()) {
    const prior = expected[index];
    if (prior === undefined) throw new BrokerError("POLICY_DENIED", "Task filesystem roots changed after authorization");
    try {
      await assertProcessPathIdentityStable(rootPath, prior.identity, "directory");
    } catch {
      throw new BrokerError("POLICY_DENIED", "Task filesystem root changed after authorization");
    }
  }
}

export function validateTaskIsolationProof(value: unknown): TaskIsolationProof {
  if (!isPlainDataRecord(value)) {
    throw new BrokerError("POLICY_DENIED", "Task isolation proof is unavailable");
  }
  const proof = value as Partial<TaskIsolationProof>;
  const allowedKeys = new Set(["schemaVersion", "sandboxMechanism", "sandboxProfile", "filesystem", "network", "credentials", "persistence", "credentialIsolation", "processTree", "processTreePolicy", "evidenceRef", "executableSelection", "virtualizationGuest", "containerImage"]);
  const expectedCredentialIsolation = proof.sandboxMechanism === "sandbox-exec"
    ? "sandbox-exec-empty-env-deny-secret-zones-v1"
    : proof.sandboxMechanism === "app-sandbox"
      ? "app-sandbox-container-no-host-credentials-v1"
      : proof.sandboxMechanism === "docker-container"
        ? "docker-container-no-host-credentials-v1"
        : "virtualization-no-host-credentials-v1";
  const expectedProcessTree = proof.sandboxMechanism === "app-sandbox" ? "observer-only" : "owned";
  if (
    Object.keys(value).some((key) => !allowedKeys.has(key)) ||
    proof.schemaVersion !== "0.1" ||
    (proof.sandboxMechanism !== "sandbox-exec" && proof.sandboxMechanism !== "app-sandbox" && proof.sandboxMechanism !== "virtualization" && proof.sandboxMechanism !== "docker-container") ||
    typeof proof.sandboxProfile !== "string" ||
    !SANDBOX_PROFILE_PATTERN.test(proof.sandboxProfile) ||
    proof.filesystem !== "enforced" ||
    proof.network !== "enforced" ||
    proof.credentials !== "isolated" ||
    proof.persistence !== "isolated" ||
    proof.credentialIsolation !== expectedCredentialIsolation ||
    proof.processTree !== expectedProcessTree ||
    (proof.processTreePolicy !== "single_process" && proof.processTreePolicy !== "owned_group") ||
    typeof proof.evidenceRef !== "string" ||
    !EVIDENCE_REFERENCE_PATTERN.test(proof.evidenceRef) ||
    (proof.executableSelection !== undefined && proof.executableSelection !== "system-published-root-owned-v1" &&
      proof.executableSelection !== "descriptor-snapshot-root-helper-v1" && proof.executableSelection !== "app-sandbox-helper-v1") ||
    (proof.sandboxMechanism !== "virtualization" && proof.virtualizationGuest !== undefined) ||
    (proof.sandboxMechanism === "app-sandbox" && proof.executableSelection !== "app-sandbox-helper-v1") ||
    (proof.sandboxMechanism !== "app-sandbox" && proof.executableSelection === "app-sandbox-helper-v1") ||
    (proof.sandboxMechanism !== "docker-container" && proof.containerImage !== undefined) ||
    (proof.sandboxMechanism === "docker-container" &&
      (proof.executableSelection !== undefined || !isPlainDataRecord(proof.containerImage) ||
       !hasExactKeys(proof.containerImage, ["imageId", "engineId"]) ||
       typeof proof.containerImage.imageId !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(proof.containerImage.imageId) ||
       typeof proof.containerImage.engineId !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(proof.containerImage.engineId))) ||
    (proof.sandboxMechanism === "virtualization" &&
      (proof.executableSelection !== undefined || !isVirtualizationGuestIdentity(proof.virtualizationGuest)))
  ) {
    throw new BrokerError("POLICY_DENIED", "Task isolation proof is not complete");
  }
  return freezeTaskIsolationProof({
    schemaVersion: "0.1",
    sandboxMechanism: proof.sandboxMechanism,
    sandboxProfile: proof.sandboxProfile,
    filesystem: "enforced",
    network: "enforced",
    credentials: "isolated",
    persistence: "isolated",
    credentialIsolation: proof.credentialIsolation,
    processTree: proof.processTree,
    processTreePolicy: proof.processTreePolicy,
    evidenceRef: proof.evidenceRef,
    ...(proof.executableSelection === undefined ? {} : { executableSelection: proof.executableSelection }),
    ...(proof.sandboxMechanism === "docker-container" ? { containerImage: { ...proof.containerImage! } } : {}),
    ...(proof.sandboxMechanism === "virtualization"
      ? { virtualizationGuest: parseVirtualizationGuestIdentity(proof.virtualizationGuest) }
      : {})
  });
}

/**
 * Proof data is retained by long-lived runners and exposed through a readonly
 * TypeScript property. Freeze the complete data graph so that readonly does
 * not become a mutable runtime authorization surface.
 */
function freezeTaskIsolationProof(proof: TaskIsolationProof): TaskIsolationProof {
  const seen = new Set<object>();
  const freeze = (value: unknown): void => {
    if (value === null || typeof value !== "object" || seen.has(value)) return;
    seen.add(value);
    if (Array.isArray(value)) {
      for (const item of value) freeze(item);
    } else {
      for (const child of Object.values(value)) freeze(child);
    }
    Object.freeze(value);
  };
  freeze(proof);
  return proof;
}

/**
 * Guest identity and attestation are retained by a long-lived executor and
 * consulted for every exchange. Freeze the validated copies so readonly
 * TypeScript fields cannot become a mutable runtime authorization surface.
 */
function freezeRuntimeSnapshot<T>(value: T): T {
  const seen = new Set<object>();
  const freeze = (candidate: unknown): void => {
    if (candidate === null || typeof candidate !== "object" || seen.has(candidate)) return;
    seen.add(candidate);
    if (Array.isArray(candidate)) {
      for (const item of candidate) freeze(item);
    } else {
      for (const child of Object.values(candidate)) freeze(child);
    }
    Object.freeze(candidate);
  };
  freeze(value);
  return value;
}

/**
 * The startup image binding is retained across asynchronous VM dispatches.
 * Copy and freeze it so a caller cannot swap its path, digest, or captured
 * filesystem identity after the constructor's admission checks.
 */
function snapshotLoadedGuestImage(value: LoadedVirtualizationGuestImage): LoadedVirtualizationGuestImage {
  const candidate = value as unknown;
  if (!isPlainDataRecord(candidate) || !hasRequiredKeys(
    candidate,
    ["path", "guestIdentity", "device", "inode", "sizeBytes"],
    ["path", "guestIdentity", "device", "inode", "sizeBytes", "publication"]
  ) ||
      typeof candidate.path !== "string" || !isAbsolute(candidate.path) || resolve(candidate.path) !== candidate.path || candidate.path.length > 4_096 || candidate.path.includes("\0") ||
      typeof candidate.device !== "string" || !/^\d+$/u.test(candidate.device) ||
      typeof candidate.inode !== "string" || !/^\d+$/u.test(candidate.inode) ||
      !Number.isSafeInteger(candidate.sizeBytes) || (candidate.sizeBytes as number) < 1 ||
      (candidate.publication !== undefined && candidate.publication !== "broker-owned" && candidate.publication !== "system-published")) {
    throw new Error("Virtualization guest image binding is malformed");
  }
  const guestIdentity = parseVirtualizationGuestIdentity(candidate.guestIdentity);
  const path = candidate.path as string;
  const device = candidate.device as string;
  const inode = candidate.inode as string;
  const sizeBytes = candidate.sizeBytes as number;
  return freezeRuntimeSnapshot({
    path,
    guestIdentity,
    device,
    inode,
    sizeBytes,
    ...(candidate.publication === undefined ? {} : { publication: candidate.publication })
  });
}

function virtualizationAttestationMatchesProof(
  value: unknown,
  proof: TaskIsolationProof | null
): boolean {
  if (proof === null || proof.sandboxMechanism !== "virtualization" || proof.virtualizationGuest === undefined) return false;
  try {
    const attestation = validateVirtualizationGuestAttestation(value);
    return sameVirtualizationGuestIdentity(proof.virtualizationGuest, attestation.guestIdentity) &&
      attestation.sandboxProfile === proof.sandboxProfile &&
      attestation.processTreePolicy === proof.processTreePolicy &&
      attestation.evidenceRef === proof.evidenceRef;
  } catch {
    return false;
  }
}

function isCanonicalTaskPath(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 4_096 &&
    isAbsolute(value) && resolve(value) === value && !value.includes("\0") && !value.includes("\n");
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
  if (expectedMechanism === "docker-container" && (profile.containerExecution === undefined ||
      profile.containerExecution.imageId !== validated.containerImage?.imageId ||
      profile.containerExecution.engineId !== validated.containerImage?.engineId)) {
    throw new BrokerError("POLICY_DENIED", "Container profile image/Engine identity does not match accepted evidence");
  }
  if (expectedMechanism !== "docker-container" && profile.containerExecution !== undefined) {
    throw new BrokerError("POLICY_DENIED", "A container descriptor cannot be executed on the host");
  }
  return validated;
}

export function validateTaskExecutionResult(value: unknown): TaskExecutionResult {
  if (!isPlainDataRecord(value) ||
      !hasRequiredKeys(value, ["state", "resultClass", "exitCode", "stdout", "stderr", "truncated", "durationMs", "verification"],
      ["state", "resultClass", "exitCode", "stdout", "stderr", "truncated", "durationMs", "verification", "containerCleanupVerified", "changedPaths"])) {
    throw new BrokerError("EXECUTION_FAILED", "Task runner returned a malformed result");
  }
  const state = value.state;
  const resultClass = value.resultClass;
  const exitCode = value.exitCode;
  const stdout = value.stdout;
  const stderr = value.stderr;
  const truncated = value.truncated;
  const durationMs = value.durationMs;
  const verification = value.verification;
  if (typeof state !== "string" || !(["completed", "failed", "cancelled", "timed_out", "unknown"] as readonly string[]).includes(state) ||
      typeof resultClass !== "string" || !(["SUCCEEDED", "EXECUTION_FAILED", "CANCELLED", "TIMEOUT", "OUTPUT_LIMIT", "UNKNOWN_OUTCOME"] as readonly string[]).includes(resultClass) ||
      (exitCode !== null && (typeof exitCode !== "number" || !Number.isInteger(exitCode) || exitCode < -2_147_483_648 || exitCode > 2_147_483_647)) ||
      typeof stdout !== "string" || typeof stderr !== "string" ||
      Buffer.byteLength(stdout, "utf8") + Buffer.byteLength(stderr, "utf8") > MAX_TASK_RESULT_OUTPUT_BYTES ||
      typeof truncated !== "boolean" || typeof durationMs !== "number" || !Number.isSafeInteger(durationMs) || durationMs < 0 || durationMs > MAX_TASK_RESULT_DURATION_MS ||
      !isPlainDataRecord(verification) || !hasRequiredKeys(verification, ["status"], ["status", "summary"]) ||
      typeof verification.status !== "string" || !(["verified", "failed", "unknown", "not_run"] as readonly string[]).includes(verification.status)) {
    throw new BrokerError("EXECUTION_FAILED", "Task runner returned a malformed result");
  }
  if (value.containerCleanupVerified !== undefined && typeof value.containerCleanupVerified !== "boolean" ||
      value.changedPaths !== undefined && (!Array.isArray(value.changedPaths) || value.changedPaths.length > 10000 ||
        value.changedPaths.some(path => typeof path !== "string" || !path || path.startsWith("/") || path.split("/").some((part: string) => part === ".." || part === ".git") || /[\x00-\x1f]/u.test(path)))) {
    throw new BrokerError("EXECUTION_FAILED", "Container task result metadata is malformed");
  }
  const summary = verification.summary;
  if (summary !== undefined &&
      (typeof summary !== "string" || Buffer.byteLength(summary, "utf8") > MAX_TASK_RESULT_SUMMARY_BYTES || summary.includes("\0"))) {
    throw new BrokerError("EXECUTION_FAILED", "Task runner returned a malformed verification summary");
  }
  return {
    ...(value.containerCleanupVerified === undefined ? {} : { containerCleanupVerified: value.containerCleanupVerified as boolean }),
    ...(value.changedPaths === undefined ? {} : { changedPaths: [...value.changedPaths as string[]] }),
    state: state as TaskExecutionResult["state"],
    resultClass: resultClass as TaskExecutionResult["resultClass"],
    exitCode: exitCode as number | null,
    stdout,
    stderr,
    truncated,
    durationMs,
    verification: {
      status: verification.status as TaskVerificationStatus,
      ...(summary === undefined ? {} : { summary })
    }
  };
}

function hasExactKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  const expected = [...allowed].sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function hasRequiredKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  allowed: readonly string[]
): boolean {
  const keys = Object.keys(value);
  const allowedSet = new Set(allowed);
  return required.every((key) => keys.includes(key)) && keys.every((key) => allowedSet.has(key));
}

function mapProcessResult(result: ProcessExecutionResult): TaskExecutionResult {
  // A signal-terminated task may have performed an unobserved partial write.
  // Keep that outcome unresolved even when the process group drained cleanly;
  // only explicit budget/cancellation classes may claim their bounded result.
  const crashed = result.resultClass === "EXECUTION_FAILED" && result.signal !== null;
  const state = crashed ? "unknown" : result.state;
  const resultClass = crashed ? "UNKNOWN_OUTCOME" : result.resultClass;
  return {
    state,
    resultClass,
    exitCode: result.exitCode,
    stdout: result.stdout,
    stderr: result.stderr,
    truncated: result.truncated,
    durationMs: result.durationMs,
    verification: resultClass === "SUCCEEDED"
      ? { status: "verified", summary: "sandboxed process exited successfully" }
      : resultClass === "UNKNOWN_OUTCOME"
        ? { status: "unknown", summary: crashed ? "sandboxed process terminated by signal; task side effects are unresolved" : "sandboxed process termination was not observed" }
        : { status: "failed", summary: "sandboxed process did not satisfy exit-status verification" }
  };
}

function mapVirtualizationGuestResponse(
  response: UnsignedVirtualizationGuestResponse,
  expectedGuestIdentity: VirtualizationGuestIdentity
): TaskExecutionResult {
  validateUnsignedVirtualizationGuestResponse(response);
  if (!sameVirtualizationGuestIdentity(response.guestIdentity, expectedGuestIdentity)) {
    throw new BrokerError("VERIFICATION_FAILED", "Virtualization guest response identity does not match the executor");
  }
  if (response.resultClass === "SUCCEEDED" &&
      (response.state !== "completed" || response.verification.status !== "verified")) {
    throw new BrokerError("VERIFICATION_FAILED", "Virtualization guest success was not postcondition verified");
  }
  if (response.resultClass === "SUCCEEDED") {
    return validateTaskExecutionResult({
      state: response.state,
      resultClass: "SUCCEEDED",
      exitCode: response.exitCode,
      stdout: response.stdout,
      stderr: response.stderr,
      truncated: response.truncated,
      durationMs: response.durationMs,
      verification: response.verification
    });
  }
  if (response.resultClass === "VERIFICATION_FAILED") {
    return validateTaskExecutionResult({
      state: "failed",
      resultClass: "EXECUTION_FAILED",
      exitCode: response.exitCode,
      stdout: response.stdout,
      stderr: response.stderr,
      truncated: response.truncated,
      durationMs: response.durationMs,
      verification: {
        status: "failed",
        ...(response.verification.summary === undefined ? {} : { summary: response.verification.summary })
      }
    });
  }
  const resultClass = response.resultClass;
  if (resultClass === "EXECUTION_FAILED" || resultClass === "CANCELLED" ||
      resultClass === "TIMEOUT" || resultClass === "OUTPUT_LIMIT" ||
      resultClass === "UNKNOWN_OUTCOME") {
    return validateTaskExecutionResult({
      state: response.state,
      resultClass,
      exitCode: response.exitCode,
      stdout: response.stdout,
      stderr: response.stderr,
      truncated: response.truncated,
      durationMs: response.durationMs,
      verification: response.verification
    });
  }
  throw new BrokerError("EXECUTION_FAILED", "Virtualization guest returned an unsupported result class");
}

function mapVirtualizationGuestStatusResponse(
  response: UnsignedVirtualizationGuestStatusResponse,
  expectedGuestIdentity: VirtualizationGuestIdentity,
  expectedMetadata?: GuestTaskJobMetadata
): TaskExecutionResult {
  validateUnsignedVirtualizationGuestStatusResponse(response);
  if (expectedMetadata !== undefined &&
      (response.originalRequestId !== expectedMetadata.requestId ||
       response.originalNonce !== expectedMetadata.nonce ||
       response.originalRequestDigest !== expectedMetadata.requestDigest)) {
    throw new BrokerError("CONFLICT", "Virtualization guest status response is not bound to the persisted Job");
  }
  return mapVirtualizationGuestResponse({
    schemaVersion: response.schemaVersion,
    protocolVersion: response.protocolVersion,
    contractVersion: response.contractVersion,
    kind: "virtualization_guest_task_result",
    requestId: response.originalRequestId,
    nonce: response.originalNonce,
    guestIdentity: response.guestIdentity,
    requestDigest: response.originalRequestDigest,
    state: response.state,
    resultClass: response.resultClass,
    exitCode: response.exitCode,
    stdout: response.stdout,
    stderr: response.stderr,
    truncated: response.truncated,
    durationMs: response.durationMs,
    outputPolicy: response.outputPolicy,
    verification: response.verification
  }, expectedGuestIdentity);
}
