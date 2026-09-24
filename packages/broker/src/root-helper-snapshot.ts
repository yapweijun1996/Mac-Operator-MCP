import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import type { ProcessExecutionResult, ProcessOwnershipSnapshot } from "./process-supervisor.js";
import type { TaskRunnerPublicEnablement } from "./task-runner.js";
import {
  DescriptorSnapshotAttestationVerifier,
  snapshotSignedDescriptorSnapshotAttestation,
  type SignedDescriptorSnapshotAttestation
} from "./descriptor-snapshot-attestation.js";
import { isPlainDataRecord } from "./plain-record.js";
import { assertArgumentsDoNotContainSecrets, assertEnvironmentValuesDoNotContainSecrets } from "./secret-policy.js";
import { isSafeProcessEnvironmentKey } from "./process-environment.js";
import {
  assertRootHelperSnapshotReleaseArtifactStable,
  validateRootHelperSnapshotReleaseEvidence,
  type RootHelperSnapshotReleaseEvidence
} from "./root-helper-snapshot-release.js";
import type { CodeSignatureExpectation } from "./macos-install-plan.js";

const ROOT_HELPER_SNAPSHOT_SCHEMA_VERSION = "0.1" as const;
const ROOT_HELPER_SNAPSHOT_MECHANISM = "darwin-root-helper-snapshot-v1" as const;
const EVIDENCE_REFERENCE_PATTERN = /^[A-Za-z0-9._:/-]{1,256}$/u;
const SANDBOX_PROFILE_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
const MAX_ARGUMENTS = 128;
const MAX_ARGUMENT_BYTES = 64 * 1024;
const MAX_ENVIRONMENT_KEYS = 64;
const MAX_ENVIRONMENT_BYTES = 64 * 1024;
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_TIMEOUT_MS = 600_000;
const MAX_DURATION_MS = 1_200_000;

/**
 * Host-owned evidence required before a root helper may materialize a task
 * executable snapshot. The default and every incomplete projection are
 * unavailable; no pathname-based fallback is permitted.
 */
export interface RootHelperSnapshotCapability {
  schemaVersion: typeof ROOT_HELPER_SNAPSHOT_SCHEMA_VERSION;
  mechanism: typeof ROOT_HELPER_SNAPSHOT_MECHANISM;
  available: boolean;
  fdIdentity: "verified" | "unproven";
  immutableSelection: "enforced" | "unproven";
  snapshotOwnership: "root-owned-private" | "unproven";
  closeOnExec: "enforced" | "unproven";
  helperAuthentication: "native-peer-and-hmac" | "unproven";
  helperReleaseMode: "development-probe" | "production" | "unproven";
  productionRelease: "developer-id-notarized" | "unproven";
  /** Independent proof that the selected production sandbox mechanism is supported. */
  sandboxIsolation: "supported-production" | "unproven";
  sandboxEvidenceRef?: string;
  /** Independent proof that native code cryptographically verifies the attestation. */
  attestationVerification: "native-ed25519" | "unproven";
  attestationEvidenceRef?: string;
  evidenceRef?: string;
}

/**
 * Only Broker-resolved data crosses the future helper adapter. Executable and
 * cwd paths are intentionally absent; the native helper receives their
 * already-open descriptors through the authenticated handoff channel.
 */
export interface RootHelperSnapshotTaskRequest {
  schemaVersion: typeof ROOT_HELPER_SNAPSHOT_SCHEMA_VERSION;
  signedAttestation: SignedDescriptorSnapshotAttestation;
  executableFd: number;
  cwdFd: number;
  args: readonly string[];
  environment: Readonly<Record<string, string>>;
  timeoutMs: number;
  outputCapBytes: number;
}

/**
 * One-shot authority lease supplied by the final Broker task admission.
 * The helper transport may only create a digest lease through this seam; the
 * root-domain authority poller then rechecks the same digest until completion.
 */
export interface RootHelperSnapshotRequestAdmission {
  admit(requestDigest: string, expiresAtMs: number): void;
  release(requestDigest: string): void;
}

export interface RootHelperSnapshotExecutionControl {
  timeoutMs: number;
  shouldCancel: () => boolean;
  /** Final Broker authority gate for the exact signed helper envelope. */
  requestAuthority?: RootHelperSnapshotRequestAdmission;
  /** Helper-observed ownership is authenticated before Broker persistence. */
  onProcessStarted?: (snapshot: ProcessOwnershipSnapshot) => void;
  onProcessOwnershipChanged?: (snapshot: ProcessOwnershipSnapshot) => void;
}

/** Native/root-helper transport; no implementation is enabled by this module. */
export interface RootHelperSnapshotTransport {
  readonly capability: RootHelperSnapshotCapability;
  execute(
    request: RootHelperSnapshotTaskRequest,
    control: RootHelperSnapshotExecutionControl
  ): Promise<ProcessExecutionResult>;
  close?(): Promise<void> | void;
}

/**
 * Explicit disabled transport used by startup assembly. It carries no key,
 * socket, or host capability and cannot accidentally become an execution
 * fallback when a profile selects the root-helper runner.
 */
export class DisabledRootHelperSnapshotTransport implements RootHelperSnapshotTransport {
  readonly capability: RootHelperSnapshotCapability = Object.freeze({
    schemaVersion: ROOT_HELPER_SNAPSHOT_SCHEMA_VERSION,
    mechanism: ROOT_HELPER_SNAPSHOT_MECHANISM,
    available: false,
    fdIdentity: "unproven",
    immutableSelection: "unproven",
    snapshotOwnership: "unproven",
    closeOnExec: "unproven",
    helperAuthentication: "unproven",
    helperReleaseMode: "unproven",
    productionRelease: "unproven",
    sandboxIsolation: "unproven",
    attestationVerification: "unproven"
  });

  async execute(
    _request: RootHelperSnapshotTaskRequest,
    _control: RootHelperSnapshotExecutionControl
  ): Promise<ProcessExecutionResult> {
    throw new BrokerError("POLICY_DENIED", "Root helper snapshot transport is disabled");
  }

  close(): void {}
}

export interface RootHelperSnapshotTaskExecutorOptions {
  /** Explicit capability opt-in; production defaults remain disabled. */
  enabled?: boolean;
  /** Independent host evidence acceptance; MCP arguments cannot provide it. */
  hostEvidenceAccepted?: boolean;
  /** Explicit release provenance mode for the exact root-helper executable. */
  releaseMode?: "development-probe" | "production";
  /** Required with production mode; generated by the read-only release preflight. */
  productionReleaseEvidence?: RootHelperSnapshotReleaseEvidence;
  /** Required with production mode; pins the Developer ID identity. */
  productionReleaseSignature?: CodeSignatureExpectation;
  /** Required with production mode; exact native helper executable path. */
  productionReleaseArtifactPath?: string;
  transport?: RootHelperSnapshotTransport;
  /** Verifies the Broker-signed snapshot before transport dispatch. */
  attestationVerifier?: DescriptorSnapshotAttestationVerifier;
}

/**
 * Fail-closed adapter for the future authenticated root snapshot helper.
 * It validates the signed plan, recomputes argument/environment digests, and
 * validates the helper result. It never launches a pathname and never falls
 * back to ProcessSupervisor or the current system-published boundary.
 */
export class RootHelperSnapshotTaskExecutor {
  readonly available: boolean;
  readonly publicEnablement: TaskRunnerPublicEnablement;
  readonly capability: RootHelperSnapshotCapability;
  private readonly transport: RootHelperSnapshotTransport | undefined;
  private readonly attestationVerifier: DescriptorSnapshotAttestationVerifier | undefined;
  private readonly releaseMode: "development-probe" | "production" | undefined;
  private readonly productionReleaseEvidence: RootHelperSnapshotReleaseEvidence | undefined;
  private readonly productionReleaseArtifactPath: string | undefined;
  private closed = false;

  constructor(options: RootHelperSnapshotTaskExecutorOptions = {}) {
    validateTaskExecutorOptions(options);
    this.transport = options.transport;
    this.attestationVerifier = options.attestationVerifier;
    this.releaseMode = options.releaseMode;
    if (options.releaseMode === "production") {
      if (options.productionReleaseEvidence === undefined || options.productionReleaseSignature === undefined ||
          options.productionReleaseArtifactPath === undefined) {
        throw new Error("Production root-helper tasks require Developer ID release evidence");
      }
      validateRootHelperSnapshotReleaseEvidence(options.productionReleaseEvidence, {
        helperPath: options.productionReleaseArtifactPath,
        artifactPath: options.productionReleaseArtifactPath,
        signature: options.productionReleaseSignature
      });
      this.productionReleaseEvidence = options.productionReleaseEvidence;
      this.productionReleaseArtifactPath = options.productionReleaseArtifactPath;
    }
    this.capability = options.transport === undefined
      ? unavailableRootHelperSnapshotCapability()
      : parseRootHelperSnapshotCapability(options.transport.capability);
    this.available = options.enabled === true && options.hostEvidenceAccepted === true &&
      this.transport !== undefined && this.attestationVerifier !== undefined &&
      options.releaseMode !== undefined && (options.releaseMode === "development-probe" || this.productionReleaseEvidence !== undefined) &&
      this.capability.available && rootHelperSnapshotCapabilityIsComplete(this.capability) &&
      this.capability.helperReleaseMode === options.releaseMode &&
      (options.releaseMode === "development-probe" || this.capability.productionRelease === "developer-id-notarized");
    this.publicEnablement = this.available && options.releaseMode === "production" &&
      this.capability.productionRelease === "developer-id-notarized"
      ? "production"
      : this.available
        ? "staging-only"
        : "unavailable";
  }

  async run(
    request: RootHelperSnapshotTaskRequest,
    control: RootHelperSnapshotExecutionControl
  ): Promise<ProcessExecutionResult> {
    if (this.closed || !this.available || this.transport === undefined || this.attestationVerifier === undefined) {
      throw new BrokerError("POLICY_DENIED", "Root helper snapshot execution is not enabled");
    }
    const safeRequest = validateRootHelperSnapshotTaskRequest(request);
    if (this.releaseMode === "production") {
      try {
        if (this.productionReleaseArtifactPath !== this.productionReleaseEvidence?.artifact.artifactPath) {
          throw new Error("Production root-helper release path is not identity-bound");
        }
        await assertRootHelperSnapshotReleaseArtifactStable(this.productionReleaseEvidence!);
      } catch {
        throw new BrokerError("POLICY_DENIED", "Production root-helper release artifact is unavailable or changed");
      }
    }
    if (typeof control?.shouldCancel !== "function" ||
        !Number.isSafeInteger(control.timeoutMs) || control.timeoutMs < 25 || control.timeoutMs > MAX_TIMEOUT_MS ||
        (control.requestAuthority !== undefined &&
         (typeof control.requestAuthority.admit !== "function" || typeof control.requestAuthority.release !== "function")) ||
        (control.onProcessStarted !== undefined && typeof control.onProcessStarted !== "function") ||
        (control.onProcessOwnershipChanged !== undefined && typeof control.onProcessOwnershipChanged !== "function")) {
      throw new BrokerError("PRECONDITION_FAILED", "Root helper snapshot execution control is invalid");
    }
    const verified = this.attestationVerifier.verify(safeRequest.signedAttestation);
    if (verified.attestation.audience !== "mac-operator-descriptor-helper-v0.1") {
      throw new BrokerError("POLICY_DENIED", "Root helper snapshot attestation audience is invalid");
    }
    if (sha256(canonicalJson(safeRequest.args)) !== verified.attestation.argsDigest ||
        sha256(canonicalJson(safeRequest.environment)) !== verified.attestation.environmentDigest) {
      throw new BrokerError("POLICY_DENIED", "Root helper snapshot plan digest does not match the attestation");
    }
    if (control.timeoutMs > safeRequest.timeoutMs) {
      throw new BrokerError("PRECONDITION_FAILED", "Root helper snapshot control exceeds the task budget");
    }
    let result: ProcessExecutionResult;
    try {
      result = await this.transport.execute(safeRequest, {
        timeoutMs: control.timeoutMs,
        shouldCancel: control.shouldCancel,
        ...(control.requestAuthority === undefined ? {} : { requestAuthority: control.requestAuthority }),
        ...(control.onProcessStarted === undefined ? {} : {
          onProcessStarted: (snapshot) => control.onProcessStarted!(validateRootHelperSnapshotProcessOwnershipSnapshot(snapshot))
        }),
        ...(control.onProcessOwnershipChanged === undefined ? {} : {
          onProcessOwnershipChanged: (snapshot) => control.onProcessOwnershipChanged!(validateRootHelperSnapshotProcessOwnershipSnapshot(snapshot))
        })
      });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("UNKNOWN_OUTCOME", "Root helper snapshot outcome could not be established", true);
    }
    return validateRootHelperSnapshotProcessResult(result);
  }

  async close(): Promise<void> {
    this.closed = true;
    await this.transport?.close?.();
  }
}

export function parseRootHelperSnapshotCapability(value: unknown): RootHelperSnapshotCapability {
  if (!isPlainDataRecord(value)) throw new BrokerError("POLICY_DENIED", "Root helper snapshot capability is malformed");
  const capability = value as Partial<RootHelperSnapshotCapability>;
  const allowed = new Set([
    "available", "closeOnExec", "evidenceRef", "fdIdentity", "helperAuthentication",
    "helperReleaseMode", "productionRelease", "immutableSelection", "mechanism", "sandboxEvidenceRef", "sandboxIsolation",
    "attestationEvidenceRef", "attestationVerification", "schemaVersion", "snapshotOwnership"
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key)) ||
      capability.schemaVersion !== ROOT_HELPER_SNAPSHOT_SCHEMA_VERSION ||
      capability.mechanism !== ROOT_HELPER_SNAPSHOT_MECHANISM ||
      typeof capability.available !== "boolean" ||
      (capability.fdIdentity !== "verified" && capability.fdIdentity !== "unproven") ||
      (capability.immutableSelection !== "enforced" && capability.immutableSelection !== "unproven") ||
      (capability.snapshotOwnership !== "root-owned-private" && capability.snapshotOwnership !== "unproven") ||
      (capability.closeOnExec !== "enforced" && capability.closeOnExec !== "unproven") ||
      (capability.helperAuthentication !== "native-peer-and-hmac" && capability.helperAuthentication !== "unproven") ||
      (capability.helperReleaseMode !== "development-probe" && capability.helperReleaseMode !== "production" && capability.helperReleaseMode !== "unproven") ||
      (capability.productionRelease !== "developer-id-notarized" && capability.productionRelease !== "unproven") ||
      (capability.helperReleaseMode === "production" && capability.productionRelease !== "developer-id-notarized") ||
      (capability.sandboxIsolation !== "supported-production" && capability.sandboxIsolation !== "unproven") ||
      (capability.sandboxIsolation === "supported-production" && capability.sandboxEvidenceRef === undefined) ||
      (capability.sandboxEvidenceRef !== undefined &&
       (typeof capability.sandboxEvidenceRef !== "string" || !EVIDENCE_REFERENCE_PATTERN.test(capability.sandboxEvidenceRef))) ||
      (capability.attestationVerification !== "native-ed25519" && capability.attestationVerification !== "unproven") ||
      (capability.attestationVerification === "native-ed25519" && capability.attestationEvidenceRef === undefined) ||
      (capability.attestationEvidenceRef !== undefined &&
       (typeof capability.attestationEvidenceRef !== "string" || !EVIDENCE_REFERENCE_PATTERN.test(capability.attestationEvidenceRef))) ||
      (capability.evidenceRef !== undefined &&
       (typeof capability.evidenceRef !== "string" || !EVIDENCE_REFERENCE_PATTERN.test(capability.evidenceRef)))) {
    throw new BrokerError("POLICY_DENIED", "Root helper snapshot capability is malformed");
  }
  const normalized: RootHelperSnapshotCapability = {
    schemaVersion: ROOT_HELPER_SNAPSHOT_SCHEMA_VERSION,
    mechanism: ROOT_HELPER_SNAPSHOT_MECHANISM,
    available: capability.available,
    fdIdentity: capability.fdIdentity,
    immutableSelection: capability.immutableSelection,
    snapshotOwnership: capability.snapshotOwnership,
    closeOnExec: capability.closeOnExec,
    helperAuthentication: capability.helperAuthentication,
    helperReleaseMode: capability.helperReleaseMode,
    productionRelease: capability.productionRelease,
    sandboxIsolation: capability.sandboxIsolation,
    ...(capability.sandboxEvidenceRef === undefined ? {} : { sandboxEvidenceRef: capability.sandboxEvidenceRef }),
    attestationVerification: capability.attestationVerification,
    ...(capability.attestationEvidenceRef === undefined ? {} : { attestationEvidenceRef: capability.attestationEvidenceRef }),
    ...(capability.evidenceRef === undefined ? {} : { evidenceRef: capability.evidenceRef })
  };
  if (normalized.available && !rootHelperSnapshotCapabilityIsComplete(normalized)) {
    throw new BrokerError("POLICY_DENIED", "Root helper snapshot capability is incomplete");
  }
  return Object.freeze(normalized);
}

export function rootHelperSnapshotCapabilityIsComplete(value: RootHelperSnapshotCapability): boolean {
  return value.available && value.fdIdentity === "verified" && value.immutableSelection === "enforced" &&
    value.snapshotOwnership === "root-owned-private" && value.closeOnExec === "enforced" &&
    value.helperAuthentication === "native-peer-and-hmac" && value.helperReleaseMode !== "unproven" &&
    (value.helperReleaseMode === "development-probe" || value.productionRelease === "developer-id-notarized") &&
    value.sandboxIsolation === "supported-production" &&
    value.sandboxEvidenceRef !== undefined && value.attestationVerification === "native-ed25519" &&
    value.attestationEvidenceRef !== undefined && value.evidenceRef !== undefined;
}

export function validateRootHelperSnapshotTaskRequest(value: unknown): RootHelperSnapshotTaskRequest {
  if (!isPlainDataRecord(value) || Object.keys(value).sort().join(",") !==
      "args,cwdFd,environment,executableFd,outputCapBytes,schemaVersion,signedAttestation,timeoutMs") {
    throw new BrokerError("PRECONDITION_FAILED", "Root helper snapshot task request is malformed");
  }
  const request = value as Partial<RootHelperSnapshotTaskRequest>;
  if (request.schemaVersion !== ROOT_HELPER_SNAPSHOT_SCHEMA_VERSION ||
      !Number.isSafeInteger(request.executableFd) || (request.executableFd as number) < 0 ||
      !Number.isSafeInteger(request.cwdFd) || (request.cwdFd as number) < 0 ||
      !Array.isArray(request.args) || Object.getPrototypeOf(request.args) !== Array.prototype ||
      request.args.length > MAX_ARGUMENTS || request.args.some((arg) => typeof arg !== "string" || arg.includes("\0") || arg.includes("\n")) ||
      Buffer.byteLength(JSON.stringify(request.args), "utf8") > MAX_ARGUMENT_BYTES ||
      !isPlainDataRecord(request.environment) || Object.keys(request.environment).length > MAX_ENVIRONMENT_KEYS ||
      Object.entries(request.environment).some(([key, entry]) => !isSafeProcessEnvironmentKey(key) || typeof entry !== "string" || entry.includes("\0")) ||
      Buffer.byteLength(JSON.stringify(request.environment), "utf8") > MAX_ENVIRONMENT_BYTES ||
      !Number.isSafeInteger(request.timeoutMs) || (request.timeoutMs as number) < 25 || (request.timeoutMs as number) > MAX_TIMEOUT_MS ||
      !Number.isSafeInteger(request.outputCapBytes) || (request.outputCapBytes as number) < 1 || (request.outputCapBytes as number) > MAX_OUTPUT_BYTES) {
    throw new BrokerError("PRECONDITION_FAILED", "Root helper snapshot task request is outside bounds");
  }
  const signedAttestation = snapshotSignedDescriptorSnapshotAttestation(request.signedAttestation);
  assertArgumentsDoNotContainSecrets(request.args as readonly string[]);
  assertEnvironmentValuesDoNotContainSecrets(request.environment as Readonly<Record<string, string>>);
  return Object.freeze({
    schemaVersion: ROOT_HELPER_SNAPSHOT_SCHEMA_VERSION,
    signedAttestation,
    executableFd: request.executableFd as number,
    cwdFd: request.cwdFd as number,
    args: Object.freeze([...(request.args as readonly string[])]),
    environment: Object.freeze({ ...(request.environment as Record<string, string>) }),
    timeoutMs: request.timeoutMs as number,
    outputCapBytes: request.outputCapBytes as number
  });
}

export function validateRootHelperSnapshotProcessResult(value: unknown): ProcessExecutionResult {
  if (!isPlainDataRecord(value) || Object.keys(value).sort().join(",") !==
      "durationMs,exitCode,processGroupId,processId,resultClass,signal,state,stderr,stdout,terminationObserved,truncated") {
    throw new BrokerError("EXECUTION_FAILED", "Root helper snapshot result is malformed");
  }
  const result = value as Partial<ProcessExecutionResult>;
  const states = new Set(["completed", "failed", "cancelled", "timed_out", "unknown"]);
  const classes = new Set(["SUCCEEDED", "EXECUTION_FAILED", "CANCELLED", "TIMEOUT", "OUTPUT_LIMIT", "UNKNOWN_OUTCOME"]);
  if (typeof result.state !== "string" || !states.has(result.state) ||
      typeof result.resultClass !== "string" || !classes.has(result.resultClass) ||
      (result.exitCode !== null && (!Number.isSafeInteger(result.exitCode) || (result.exitCode as number) < -2_147_483_648 || (result.exitCode as number) > 2_147_483_647)) ||
      (result.signal !== null && typeof result.signal !== "string") ||
      typeof result.stdout !== "string" || typeof result.stderr !== "string" ||
      Buffer.byteLength(result.stdout, "utf8") + Buffer.byteLength(result.stderr, "utf8") > MAX_OUTPUT_BYTES ||
      typeof result.truncated !== "boolean" ||
      !Number.isSafeInteger(result.durationMs) || (result.durationMs as number) < 0 || (result.durationMs as number) > MAX_DURATION_MS ||
      !Number.isSafeInteger(result.processId) || (result.processId as number) < 1 ||
      !Number.isSafeInteger(result.processGroupId) || (result.processGroupId as number) < 1 ||
      typeof result.terminationObserved !== "boolean") {
    throw new BrokerError("EXECUTION_FAILED", "Root helper snapshot result is malformed");
  }
  if (result.resultClass === "SUCCEEDED" && result.state !== "completed") {
    throw new BrokerError("VERIFICATION_FAILED", "Root helper snapshot success state is inconsistent");
  }
  if (result.state === "unknown" && result.resultClass !== "UNKNOWN_OUTCOME") {
    throw new BrokerError("UNKNOWN_OUTCOME", "Root helper snapshot unresolved state is inconsistent", true);
  }
  if (result.state !== "unknown" && result.terminationObserved !== true) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Root helper snapshot termination was not observed", true);
  }
  return {
    state: result.state as ProcessExecutionResult["state"],
    resultClass: result.resultClass as ProcessExecutionResult["resultClass"],
    exitCode: result.exitCode as number | null,
    signal: result.signal as NodeJS.Signals | null,
    stdout: result.stdout as string,
    stderr: result.stderr as string,
    truncated: result.truncated as boolean,
    durationMs: result.durationMs as number,
    processId: result.processId as number,
    processGroupId: result.processGroupId as number,
    terminationObserved: result.terminationObserved as boolean
  };
}

/**
 * Validates the helper's process-ownership event before it reaches the Broker
 * Job ledger. The helper is allowed to observe the process, but the Broker
 * still owns the persistence decision and rejects malformed identities.
 */
export function validateRootHelperSnapshotProcessOwnershipSnapshot(value: unknown): ProcessOwnershipSnapshot {
  if (!isPlainDataRecord(value) || Object.keys(value).some((key) => !["identity", "descendants", "ownershipProof"].includes(key)) ||
      !isPlainDataRecord(value.identity) || !Array.isArray(value.descendants) ||
      Object.getPrototypeOf(value.descendants) !== Array.prototype) {
    throw new BrokerError("EXECUTION_FAILED", "Root helper process ownership event is malformed");
  }
  const identity = value.identity as Record<string, unknown>;
  if (Object.keys(identity).sort().join(",") !== "pid,processGroupId,startTimeMicros" ||
      !isPositiveSafeInteger(identity.pid) || !isPositiveSafeInteger(identity.processGroupId) ||
      !isPositiveSafeInteger(identity.startTimeMicros) || value.descendants.length > 128 ||
      value.descendants.some((entry) => !isPlainDataRecord(entry) || Object.keys(entry).sort().join(",") !== "pid,startTimeMicros" ||
        !isPositiveSafeInteger((entry as Record<string, unknown>).pid) ||
        !isPositiveSafeInteger((entry as Record<string, unknown>).startTimeMicros)) ||
      (value.ownershipProof !== undefined && value.ownershipProof !== "sandbox-exec-no-fork-v1") ||
      (value.ownershipProof === "sandbox-exec-no-fork-v1" && value.descendants.length > 0)) {
    throw new BrokerError("EXECUTION_FAILED", "Root helper process ownership event is malformed");
  }
  const descendants = (value.descendants as readonly Record<string, unknown>[]).map((entry) => ({
    pid: entry.pid as number,
    startTimeMicros: entry.startTimeMicros as number
  }));
  return {
    identity: {
      pid: identity.pid as number,
      processGroupId: identity.processGroupId as number,
      startTimeMicros: identity.startTimeMicros as number
    },
    descendants,
    ...(value.ownershipProof === undefined ? {} : { ownershipProof: value.ownershipProof })
  };
}

function unavailableRootHelperSnapshotCapability(): RootHelperSnapshotCapability {
  return {
    schemaVersion: ROOT_HELPER_SNAPSHOT_SCHEMA_VERSION,
    mechanism: ROOT_HELPER_SNAPSHOT_MECHANISM,
    available: false,
    fdIdentity: "unproven",
    immutableSelection: "unproven",
    snapshotOwnership: "unproven",
    closeOnExec: "unproven",
    helperAuthentication: "unproven",
    helperReleaseMode: "unproven",
    productionRelease: "unproven",
    sandboxIsolation: "unproven",
    attestationVerification: "unproven"
  };
}

function validateTaskExecutorOptions(options: RootHelperSnapshotTaskExecutorOptions): void {
  if (options === null || typeof options !== "object" ||
      (options.releaseMode !== undefined && options.releaseMode !== "development-probe" && options.releaseMode !== "production") ||
      (options.productionReleaseArtifactPath !== undefined &&
       (typeof options.productionReleaseArtifactPath !== "string" || !options.productionReleaseArtifactPath.startsWith("/") ||
        options.productionReleaseArtifactPath.includes("\0") || options.productionReleaseArtifactPath.includes("\n") ||
        options.productionReleaseArtifactPath.includes("\r")))) {
    throw new Error("Root helper snapshot task executor options are invalid");
  }
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}
