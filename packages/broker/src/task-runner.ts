import { BrokerError, canonicalJson } from "@mac-operator/contracts";
import type { GuestTaskJobMetadata } from "./persistence.js";
import {
  assertProcessPathIdentityStable,
  captureProcessPathIdentity,
  ProcessSupervisor,
  type ProcessExecutionResult,
  type ProcessOwnershipSnapshot,
  type ProcessPathIdentity
} from "./process-supervisor.js";
import { loadNativePeerAdapter } from "./peer-credentials.js";
import { buildSandboxExecArguments } from "./sandbox-profile.js";
import type { ResolvedTaskProfile } from "./task-profile.js";
import {
  isVirtualizationGuestIdentity,
  parseVirtualizationGuestIdentity,
  sameVirtualizationGuestIdentity,
  validateVirtualizationGuestAttestation,
  type SignedVirtualizationGuestAttestation,
  type VirtualizationGuestAttestation,
  type VirtualizationGuestAttestationVerifier,
  type VirtualizationGuestIdentity
} from "./virtualization-guest-attestation.js";
import { verifyVirtualizationGuestImage, type LoadedVirtualizationGuestImage } from "./virtualization-guest-image.js";
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

export type {
  SignedVirtualizationGuestAttestation,
  VirtualizationGuestAttestation,
  VirtualizationGuestIdentity
} from "./virtualization-guest-attestation.js";
export { validateVirtualizationGuestAttestation } from "./virtualization-guest-attestation.js";

/** Mechanisms with a governed runner contract; availability remains evidence-gated. */
export type TaskIsolationMechanism = "sandbox-exec" | "virtualization";
export type TaskCredentialIsolationProof =
  | "sandbox-exec-empty-env-deny-secret-zones-v1"
  | "virtualization-no-host-credentials-v1";

export interface TaskExecutionControl {
  timeoutMs: number;
  shouldCancel: () => boolean;
  onProcessStarted?: (snapshot: ProcessOwnershipSnapshot) => void;
  onProcessOwnershipChanged?: (snapshot: ProcessOwnershipSnapshot) => void;
  onGuestRequestAdmitted?: (admission: VirtualizationGuestTaskAdmission) => void;
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
  processTree: "owned";
  processTreePolicy: "single_process" | "owned_group";
  evidenceRef: string;
  /** Required for Virtualization.framework guests; absent for host sandboxes. */
  virtualizationGuest?: VirtualizationGuestIdentity;
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
  recoverUnknownTask?(request: TaskRecoveryRequest): Promise<TaskExecutionResult>;
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
    const taskExecutableIdentity = await captureTaskProcessPathIdentity(profile.process.executable, "executable");
    const taskCwdIdentity = await captureTaskProcessPathIdentity(profile.cwd, "directory");
    const filesystemIdentity = captureTaskFilesystemIdentity(profile, this.filesystemIdentityObserver);
    const args = buildSandboxExecArguments(profile);
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
    assertTaskFilesystemIdentityStable(profile, filesystemIdentity, this.filesystemIdentityObserver);
    return mapProcessResult(result);
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
    this.guestIdentity = guestIdentity;
    this.attestation = attestation;
    if (options.signedAttestation !== undefined) this.signedAttestation = options.signedAttestation;
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
      onRequestAdmitted: (admitted) => request.control.onGuestRequestAdmitted?.({
        requestId: admitted.requestId,
        nonce: admitted.nonce,
        requestDigest: virtualizationGuestRequestDigest(admitted),
        guestIdentity: { ...admitted.guestIdentity },
        profileDigest: admitted.profileDigest,
        taskDigest: admitted.taskDigest,
        timeoutMs: admitted.timeoutMs,
        outputCapBytes: admitted.outputCapBytes
      })
    });
    return mapVirtualizationGuestResponse(response, this.guestIdentity);
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
  /** Optional host-owned verifier required when signed guest provenance is enabled. */
  attestationVerifier?: VirtualizationGuestAttestationVerifier;
}

/**
 * Disabled-by-default Virtualization.framework runner boundary.
 *
 * This class deliberately contains no VM implementation. A future native
 * adapter must provide an immutable guest identity and verified result; a
 * missing, malformed, or changed identity keeps the Broker fail closed.
 */
export class VirtualizationTaskRunner implements TaskRunner {
  readonly available: boolean;
  readonly mechanism: TaskIsolationMechanism = "virtualization";
  readonly isolationProof: TaskIsolationProof | null;
  private readonly executor: VirtualizationTaskExecutor | undefined;
  private readonly guestImage: LoadedVirtualizationGuestImage | undefined;
  private readonly attestationVerifier: VirtualizationGuestAttestationVerifier | undefined;

  constructor(options: VirtualizationTaskRunnerOptions = {}) {
    const proof = options.isolationProof === null || options.isolationProof === undefined
      ? null
      : validateTaskIsolationProof(options.isolationProof);
    this.isolationProof = proof;
    this.executor = options.executor;
    this.guestImage = options.guestImage === null ? undefined : options.guestImage;
    this.attestationVerifier = options.attestationVerifier;
    const guest = proof?.virtualizationGuest;
    this.available = process.platform === "darwin" &&
      options.enabled === true &&
      options.hostEvidenceAccepted === true &&
      options.executor?.available === true &&
      this.guestImage !== undefined &&
      guest !== undefined &&
      sameVirtualizationGuestIdentity(guest, this.guestImage.guestIdentity) &&
      options.executor.guestIdentity !== null &&
      sameVirtualizationGuestIdentity(guest, options.executor.guestIdentity) &&
      options.executor.attestation !== null &&
      virtualizationAttestationMatchesProof(options.executor.attestation, proof) &&
      (this.attestationVerifier === undefined || signedAttestationMatches(
        options.executor.signedAttestation,
        options.executor.attestation,
        this.attestationVerifier
      ));
  }

  close(): Promise<void> {
    return this.executor?.close?.() ?? Promise.resolve();
  }

  async run(profile: ResolvedTaskProfile, control: TaskExecutionControl): Promise<TaskExecutionResult> {
    if (!this.available || this.isolationProof === null || this.executor === undefined) {
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
      return await this.executor.run({ profile, control, guestIdentity });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("UNKNOWN_OUTCOME", "Virtualized task outcome could not be established", true);
    }
  }

  async recoverUnknownTask(request: TaskRecoveryRequest): Promise<TaskExecutionResult> {
    if (!this.available || this.isolationProof === null || this.executor === undefined ||
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
      return await this.executor.recoverUnknownTask(request);
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
    if (!signedAttestationMatches(this.executor?.signedAttestation, this.executor?.attestation, this.attestationVerifier)) {
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

export function validateTaskIsolationProof(value: unknown): TaskIsolationProof {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("POLICY_DENIED", "Task isolation proof is unavailable");
  }
  const proof = value as Partial<TaskIsolationProof>;
  const allowedKeys = new Set(["schemaVersion", "sandboxMechanism", "sandboxProfile", "filesystem", "network", "credentials", "persistence", "credentialIsolation", "processTree", "processTreePolicy", "evidenceRef", "virtualizationGuest"]);
  const expectedCredentialIsolation = proof.sandboxMechanism === "sandbox-exec"
    ? "sandbox-exec-empty-env-deny-secret-zones-v1"
    : "virtualization-no-host-credentials-v1";
  if (
    Object.keys(value).some((key) => !allowedKeys.has(key)) ||
    proof.schemaVersion !== "0.1" ||
    (proof.sandboxMechanism !== "sandbox-exec" && proof.sandboxMechanism !== "virtualization") ||
    typeof proof.sandboxProfile !== "string" ||
    !SANDBOX_PROFILE_PATTERN.test(proof.sandboxProfile) ||
    proof.filesystem !== "enforced" ||
    proof.network !== "enforced" ||
    proof.credentials !== "isolated" ||
    proof.persistence !== "isolated" ||
    proof.credentialIsolation !== expectedCredentialIsolation ||
    proof.processTree !== "owned" ||
    (proof.processTreePolicy !== "single_process" && proof.processTreePolicy !== "owned_group") ||
    typeof proof.evidenceRef !== "string" ||
    !EVIDENCE_REFERENCE_PATTERN.test(proof.evidenceRef) ||
    (proof.sandboxMechanism === "sandbox-exec" && proof.virtualizationGuest !== undefined) ||
    (proof.sandboxMechanism === "virtualization" && !isVirtualizationGuestIdentity(proof.virtualizationGuest))
  ) {
    throw new BrokerError("POLICY_DENIED", "Task isolation proof is not complete");
  }
  return {
    schemaVersion: "0.1",
    sandboxMechanism: proof.sandboxMechanism,
    sandboxProfile: proof.sandboxProfile,
    filesystem: "enforced",
    network: "enforced",
    credentials: "isolated",
    persistence: "isolated",
    credentialIsolation: proof.credentialIsolation,
    processTree: "owned",
    processTreePolicy: proof.processTreePolicy,
    evidenceRef: proof.evidenceRef,
    ...(proof.sandboxMechanism === "virtualization"
      ? { virtualizationGuest: parseVirtualizationGuestIdentity(proof.virtualizationGuest) }
      : {})
  };
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
