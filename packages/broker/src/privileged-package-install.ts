import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import {
  AllowlistedPrivilegedHelper,
  type PrivilegedHelperAdapter,
  type PrivilegedHelperExecutionControl,
  type PrivilegedHelperExecutionResult,
  type PrivilegedHelperJobReadback,
  type UnsignedPrivilegedHelperJobReadbackRequest,
  type UnsignedPrivilegedHelperCommand
} from "./privileged-helper.js";
import { inspectSystemPublishedExecutablePath } from "./system-published-executable.js";
import { ProcessSupervisor, type ProcessExecutionRequest, type ProcessExecutionResult } from "./process-supervisor.js";
import { validatePrivilegedHelperPayload, type PrivilegedHelperPayload } from "./persistence.js";
import { isPlainDataRecord } from "./plain-record.js";

const INSTALLER_PATH = "/usr/sbin/installer";
const PKGUTIL_PATH = "/usr/sbin/pkgutil";
const COMMAND_CWD = "/";
const RECEIPT_TIMEOUT_MS = 5_000;
const RECEIPT_OUTPUT_CAP_BYTES = 128 * 1024;
const INSTALL_OUTPUT_CAP_BYTES = 1024 * 1024;
const MAX_OPERATION_TIMEOUT_MS = 600_000;
const MAX_CATALOG_ENTRIES = 256;
const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024;
const TOKEN_PATTERN = /^[A-Za-z0-9._:@/+-]{1,255}$/u;
const VERSION_PATTERN = /^[A-Za-z0-9._:+-]{1,128}$/u;
const SOURCE_PROFILE_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;

export interface ApprovedPackageArtifact {
  packageId: string;
  version: string;
  artifactId: string;
  artifactPath: string;
  artifactSha256: string;
  sourceProfile: string;
}

export interface InstalledPackageReadback {
  packageId: string;
  version: string;
}

export interface PrivilegedPackageInstallCommandRunner {
  run(request: ProcessExecutionRequest): Promise<ProcessExecutionResult>;
}

export interface PrivilegedPackageArtifactVerifier {
  verify(artifact: ApprovedPackageArtifact): Promise<void>;
}

export interface PrivilegedPackageReceiptReader {
  read(packageId: string, control: PrivilegedHelperExecutionControl): Promise<InstalledPackageReadback | undefined>;
}

export interface PrivilegedPackageInstallAdapterOptions {
  /** Explicit host enablement. Omitted means disabled. */
  enabled?: boolean;
  /** Host-owned approved package catalog; never derived from MCP arguments. */
  catalog?: readonly ApprovedPackageArtifact[];
  /** Test-only command seam; production uses fixed system-published tools. */
  commandRunner?: PrivilegedPackageInstallCommandRunner;
  /** Explicit operator acceptance of the fixed system-published boundary. */
  systemPublishedExecutablePathAccepted?: boolean;
  /** Test-only artifact identity seam. */
  artifactVerifier?: PrivilegedPackageArtifactVerifier;
  /** Test-only receipt readback seam. */
  receiptReader?: PrivilegedPackageReceiptReader;
  now?: () => number;
}

/**
 * Installs only an artifact selected by a host-owned package catalog. The MCP
 * payload supplies an identity, never a path, executable, installer argument,
 * or source URL. The production adapter remains unavailable unless it is
 * explicitly enabled by a root helper release and both fixed macOS utilities
 * pass the system-published executable gate.
 */
export class PrivilegedPackageInstallAdapter implements PrivilegedHelperAdapter {
  readonly available: boolean;
  readonly enabledCapabilities: readonly string[];
  private readonly catalog: readonly ApprovedPackageArtifact[];
  private readonly commandRunner: PrivilegedPackageInstallCommandRunner;
  private readonly artifactVerifier: PrivilegedPackageArtifactVerifier;
  private readonly receiptReader: PrivilegedPackageReceiptReader;
  private readonly now: () => number;

  constructor(options: PrivilegedPackageInstallAdapterOptions = {}) {
    const enabled = options.enabled ?? false;
    if (typeof enabled !== "boolean") throw new Error("Privileged package-install enablement is invalid");
    if (options.commandRunner !== undefined && typeof options.commandRunner.run !== "function") {
      throw new Error("Privileged package-install command runner is invalid");
    }
    if (options.systemPublishedExecutablePathAccepted !== undefined && typeof options.systemPublishedExecutablePathAccepted !== "boolean") {
      throw new Error("Privileged package-install system-published executable acceptance is invalid");
    }
    if (options.artifactVerifier !== undefined && typeof options.artifactVerifier.verify !== "function") {
      throw new Error("Privileged package-install artifact verifier is invalid");
    }
    if (options.receiptReader !== undefined && typeof options.receiptReader.read !== "function") {
      throw new Error("Privileged package-install receipt reader is invalid");
    }
    if (options.commandRunner === undefined && (options.artifactVerifier !== undefined || options.receiptReader !== undefined)) {
      throw new Error("Privileged package-install test seams require an injected command runner");
    }
    this.catalog = normalizeCatalog(options.catalog ?? []);
    this.now = options.now ?? Date.now;
    if (typeof this.now !== "function") throw new Error("Privileged package-install clock is invalid");

    const supervisor = options.commandRunner === undefined
      ? new ProcessSupervisor({
        maxConcurrent: 1,
        maxConcurrentPerExecutable: 1,
        allowedEnvironmentKeys: [],
        requireRootOwnedExecutable: true,
        requireSystemPublishedExecutable: true
      })
      : undefined;
    this.commandRunner = options.commandRunner ?? supervisor!;
    this.artifactVerifier = options.artifactVerifier ?? { verify: verifyProtectedArtifact };
    this.receiptReader = options.receiptReader ?? {
      read: (packageId, control) => readInstalledPackage(this.commandRunner, packageId, control)
    };
    const hostReady = options.commandRunner !== undefined ||
      (isRootProcess() && options.systemPublishedExecutablePathAccepted === true &&
        inspectSystemPublishedExecutablePath(INSTALLER_PATH) && inspectSystemPublishedExecutablePath(PKGUTIL_PATH));
    this.available = enabled && hostReady && this.catalog.length > 0;
    this.enabledCapabilities = this.available ? ["mac_priv_package_install"] : [];
  }

  async execute(command: UnsignedPrivilegedHelperCommand, control: PrivilegedHelperExecutionControl): Promise<PrivilegedHelperExecutionResult> {
    const payload = packagePayload(command);
    const timeoutMs = boundedTimeout(control);
    const startedAtMs = this.now();
    if (!Number.isSafeInteger(startedAtMs) || startedAtMs < 0) {
      throw new BrokerError("PRECONDITION_FAILED", "Privileged package-install clock is invalid");
    }
    const deadlineMs = startedAtMs + timeoutMs;
    const boundedControl: PrivilegedHelperExecutionControl = {
      timeoutMs,
      shouldCancel: () => control.shouldCancel() || this.now() >= deadlineMs
    };
    checkControl(control, deadlineMs, this.now);

    const artifact = this.resolveArtifact(payload);
    await this.artifactVerifier.verify(artifact);
    checkControl(control, deadlineMs, this.now);

    const preState = await this.receiptReader.read(payload.package_id, boundedControl);
    checkControl(control, deadlineMs, this.now);
    const alreadyInstalled = preState !== undefined;
    const matchedVersion = preState?.version === artifact.version;
    if (!alreadyInstalled || !matchedVersion) {
      let result: ProcessExecutionResult;
      try {
        result = await this.commandRunner.run({
          executable: INSTALLER_PATH,
          args: ["-pkg", artifact.artifactPath, "-target", "/"],
          cwd: COMMAND_CWD,
          environment: {},
          timeoutMs: remaining(deadlineMs, this.now),
          outputCapBytes: INSTALL_OUTPUT_CAP_BYTES,
          shouldCancel: boundedControl.shouldCancel
        });
      } catch (error) {
        if (error instanceof BrokerError) throw error;
        throw new BrokerError("EXECUTION_FAILED", "Privileged package installer could not be started");
      }
      const unresolved = mapCommandResult(result, "Privileged package installer");
      if (unresolved) return unresolved(command, preState, artifact, alreadyInstalled, matchedVersion);
      checkControl(control, deadlineMs, this.now);
      try {
        await this.artifactVerifier.verify(artifact);
      } catch {
        return unknownOutcome(command, preState, artifact, alreadyInstalled, matchedVersion, "Approved package artifact changed during installation");
      }
    }

    let postState: InstalledPackageReadback | undefined;
    try {
      postState = await this.receiptReader.read(payload.package_id, boundedControl);
    } catch {
      return unknownOutcome(command, preState, artifact, alreadyInstalled, matchedVersion, "Installed package receipt readback was unavailable");
    }
    if (postState === undefined) {
      return unknownOutcome(command, preState, artifact, alreadyInstalled, matchedVersion, "Installed package receipt was not found after the operation");
    }
    const readbackHash = sha256(canonicalJson({ packageId: postState.packageId, version: postState.version, artifactId: artifact.artifactId }));
    const evidence = {
      installed_version: postState.version,
      artifact_id: artifact.artifactId,
      already_installed: alreadyInstalled,
      matched_version: matchedVersion,
      state: alreadyInstalled && matchedVersion ? "already_installed" : "installed"
    } as const;
    if (postState.packageId !== payload.package_id || postState.version !== artifact.version) {
      return {
        operation: "package_install",
        targetRef: command.targetRef,
        state: "failed",
        resultClass: "VERIFICATION_FAILED",
        evidence,
        warnings: [],
        truncated: false,
        verification: {
          status: "failed",
          strategy: "allowlisted_postcondition",
          summary: "Installed package receipt did not match the approved package version",
          readbackHash
        }
      };
    }
    return {
      operation: "package_install",
      targetRef: command.targetRef,
      state: "completed",
      resultClass: "SUCCEEDED",
      evidence,
      warnings: [],
      truncated: false,
      verification: {
        status: "verified",
        strategy: "allowlisted_postcondition",
        summary: alreadyInstalled && matchedVersion ? "Approved package version was already installed" : "Installed package receipt matched the approved version",
        readbackHash
      }
    };
  }

  async readback(request: UnsignedPrivilegedHelperJobReadbackRequest, control: PrivilegedHelperExecutionControl): Promise<PrivilegedHelperJobReadback> {
    const payload = packagePayload(request);
    const timeoutMs = boundedTimeout(control);
    const startedAtMs = this.now();
    if (!Number.isSafeInteger(startedAtMs) || startedAtMs < 0) {
      throw new BrokerError("PRECONDITION_FAILED", "Privileged package-install readback clock is invalid");
    }
    const deadlineMs = startedAtMs + timeoutMs;
    const boundedControl: PrivilegedHelperExecutionControl = {
      timeoutMs,
      shouldCancel: () => control.shouldCancel() || this.now() >= deadlineMs
    };
    try {
      checkControl(control, deadlineMs, this.now);
      const artifact = this.resolveArtifact(payload);
      const installed = await this.receiptReader.read(payload.package_id, boundedControl);
      checkControl(control, deadlineMs, this.now);
      if (installed === undefined) {
        return {
          operation: "package_install",
          targetRef: request.targetRef,
          postcondition: "mismatch",
          evidence: { installed: false, expected_version: artifact.version },
          warnings: [],
          summary: "Approved package receipt is absent"
        };
      }
      const postcondition = installed.packageId === payload.package_id && installed.version === artifact.version ? "matches" : "mismatch";
      const readbackHash = sha256(canonicalJson({ packageId: installed.packageId, version: installed.version, artifactId: artifact.artifactId }));
      return {
        operation: "package_install",
        targetRef: request.targetRef,
        postcondition,
        evidence: { installed: true, installed_version: installed.version, expected_version: artifact.version, artifact_id: artifact.artifactId },
        warnings: [],
        summary: postcondition === "matches" ? "Installed package receipt matches the approved catalog entry" : "Installed package receipt does not match the approved catalog entry",
        readbackHash
      };
    } catch (error) {
      if (error instanceof BrokerError && (error.errorClass === "CANCELLED" || error.errorClass === "TIMEOUT")) throw error;
      return {
        operation: "package_install",
        targetRef: request.targetRef,
        postcondition: "unavailable",
        evidence: { state: "unavailable" },
        warnings: ["Installed package receipt readback was unavailable"],
        summary: "Installed package receipt readback was unavailable"
      };
    }
  }

  private resolveArtifact(payload: Extract<PrivilegedHelperPayload, { operation: "package_install" }>): ApprovedPackageArtifact {
    const candidates = this.catalog.filter((entry) => entry.packageId === payload.package_id)
      .filter((entry) => payload.version === undefined || entry.version === payload.version)
      .filter((entry) => payload.source_profile === undefined || entry.sourceProfile === payload.source_profile);
    if (candidates.length === 0) throw new BrokerError("TARGET_NOT_FOUND", "Approved package identity or version was not found");
    if (candidates.length !== 1) throw new BrokerError("CONFLICT", "Approved package selection is ambiguous");
    return candidates[0]!;
  }
}

/** Convenience factory that exposes only the package operation when available. */
export function createPrivilegedPackageInstallHelper(options: PrivilegedPackageInstallAdapterOptions = {}): PrivilegedHelperAdapter {
  const adapter = new PrivilegedPackageInstallAdapter(options);
  return new AllowlistedPrivilegedHelper({
    ...(adapter.available ? {
      package_install: (command, control) => adapter.execute(command, control),
      package_install_readback: (request, control) => adapter.readback(request, control)
    } : {})
  });
}

function packagePayload(command: Pick<UnsignedPrivilegedHelperCommand | UnsignedPrivilegedHelperJobReadbackRequest, "operation" | "payload" | "targetRef">): Extract<PrivilegedHelperPayload, { operation: "package_install" }> {
  if (command.operation !== "package_install" || command.payload.operation !== "package_install") {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged package-install command payload is invalid");
  }
  try { validatePrivilegedHelperPayload(command.payload); }
  catch { throw new BrokerError("PRECONDITION_FAILED", "Privileged package-install command payload is invalid"); }
  if (command.targetRef !== `package:${command.payload.package_id}`) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged package-install command target is invalid");
  }
  return command.payload;
}

function normalizeCatalog(catalog: readonly ApprovedPackageArtifact[]): readonly ApprovedPackageArtifact[] {
  if (!Array.isArray(catalog) || catalog.length > MAX_CATALOG_ENTRIES || catalog.some((entry) => !isPlainDataRecord(entry))) {
    throw new Error("Privileged package catalog is invalid");
  }
  const normalized = catalog.map((entry) => {
    const value = entry as Record<string, unknown>;
    if (Object.keys(value).sort().join(",") !== "artifactId,artifactPath,artifactSha256,packageId,sourceProfile,version" ||
        typeof value.packageId !== "string" || !TOKEN_PATTERN.test(value.packageId) ||
        typeof value.version !== "string" || !VERSION_PATTERN.test(value.version) ||
        typeof value.artifactId !== "string" || !TOKEN_PATTERN.test(value.artifactId) ||
        typeof value.artifactPath !== "string" || !isAbsolute(value.artifactPath) || resolve(value.artifactPath) !== value.artifactPath ||
        typeof value.artifactSha256 !== "string" || !SHA256_PATTERN.test(value.artifactSha256) ||
        typeof value.sourceProfile !== "string" || !SOURCE_PROFILE_PATTERN.test(value.sourceProfile)) {
      throw new Error("Privileged package catalog entry is invalid");
    }
    return Object.freeze({
      packageId: value.packageId,
      version: value.version,
      artifactId: value.artifactId,
      artifactPath: value.artifactPath,
      artifactSha256: value.artifactSha256,
      sourceProfile: value.sourceProfile
    });
  });
  const identities = new Set<string>();
  for (const entry of normalized) {
    const identity = `${entry.packageId}\0${entry.version}\0${entry.sourceProfile}`;
    if (identities.has(identity)) throw new Error("Privileged package catalog contains duplicate identities");
    identities.add(identity);
  }
  return Object.freeze(normalized);
}

async function verifyProtectedArtifact(artifact: ApprovedPackageArtifact): Promise<void> {
  const before = await validateProtectedArtifactPath(artifact.artifactPath);
  const hash = createHash("sha256");
  let bytes = 0;
  for await (const chunk of createReadStream(artifact.artifactPath, { highWaterMark: 1024 * 1024 })) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += buffer.byteLength;
    if (bytes > MAX_ARTIFACT_BYTES) throw new BrokerError("OUTPUT_LIMIT", "Approved package artifact exceeds its size limit");
    hash.update(buffer);
  }
  const after = await validateProtectedArtifactPath(artifact.artifactPath);
  if (!sameArtifactIdentity(before, after) || hash.digest("hex") !== artifact.artifactSha256) {
    throw new BrokerError("POLICY_DENIED", "Approved package artifact identity changed or digest mismatched");
  }
}

interface ArtifactIdentity {
  device: number;
  inode: number;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
}

async function validateProtectedArtifactPath(path: string): Promise<ArtifactIdentity> {
  const parts = path.split("/").filter((part) => part.length > 0);
  let current = "/";
  for (const part of parts) {
    current = current === "/" ? `/${part}` : `${current}/${part}`;
    const stats = await lstat(current);
    if (stats.isSymbolicLink()) throw new BrokerError("PATH_DENIED", "Approved package artifact path contains a symlink");
    if (current !== path && !stats.isDirectory()) throw new BrokerError("PATH_DENIED", "Approved package artifact parent is not a directory");
    if (stats.uid !== 0 || (stats.mode & 0o022) !== 0) {
      throw new BrokerError("PATH_DENIED", "Approved package artifact path is not root-protected");
    }
  }
  const stats = await lstat(path);
  if (!stats.isFile()) throw new BrokerError("PATH_DENIED", "Approved package artifact is not a regular file");
  return { device: stats.dev, inode: stats.ino, size: stats.size, mtimeMs: stats.mtimeMs, ctimeMs: stats.ctimeMs };
}

function sameArtifactIdentity(left: ArtifactIdentity, right: ArtifactIdentity): boolean {
  return left.device === right.device && left.inode === right.inode && left.size === right.size &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

async function readInstalledPackage(
  commandRunner: PrivilegedPackageInstallCommandRunner,
  packageId: string,
  control: PrivilegedHelperExecutionControl
): Promise<InstalledPackageReadback | undefined> {
  const result = await commandRunner.run({
    executable: PKGUTIL_PATH,
    args: ["--pkg-info", packageId],
    cwd: COMMAND_CWD,
    environment: {},
    timeoutMs: Math.min(control.timeoutMs, RECEIPT_TIMEOUT_MS),
    outputCapBytes: RECEIPT_OUTPUT_CAP_BYTES,
    shouldCancel: control.shouldCancel
  });
  if (result.resultClass !== "SUCCEEDED") {
    if (/no receipt|not installed|not found/iu.test(`${result.stdout}\n${result.stderr}`)) return undefined;
    if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", "Privileged package receipt readback was cancelled");
    if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", "Privileged package receipt readback timed out");
    if (result.resultClass === "OUTPUT_LIMIT") throw new BrokerError("OUTPUT_LIMIT", "Privileged package receipt readback exceeded its output limit");
    if (result.resultClass === "UNKNOWN_OUTCOME") throw new BrokerError("UNKNOWN_OUTCOME", "Privileged package receipt readback is unresolved", true);
    throw new BrokerError("EXECUTION_FAILED", "Privileged package receipt readback failed");
  }
  if (result.truncated) throw new BrokerError("OUTPUT_LIMIT", "Privileged package receipt exceeded its output limit");
  const packageMatch = /^package-id:\s*([^\r\n]+)\s*$/mu.exec(result.stdout);
  const versionMatch = /^version:\s*([^\r\n]+)\s*$/mu.exec(result.stdout);
  const readbackPackageId = packageMatch?.[1]?.trim();
  const version = versionMatch?.[1]?.trim();
  if (readbackPackageId !== packageId || version === undefined || !VERSION_PATTERN.test(version)) {
    throw new BrokerError("EXECUTION_FAILED", "Privileged package receipt readback is malformed");
  }
  return { packageId: readbackPackageId, version };
}

function mapCommandResult(result: ProcessExecutionResult, label: string): ((
  command: UnsignedPrivilegedHelperCommand,
  preState: InstalledPackageReadback | undefined,
  artifact: ApprovedPackageArtifact,
  alreadyInstalled: boolean,
  matchedVersion: boolean
) => PrivilegedHelperExecutionResult) | undefined {
  if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", `${label} was cancelled`);
  if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", `${label} timed out`);
  if (result.resultClass === "OUTPUT_LIMIT") throw new BrokerError("OUTPUT_LIMIT", `${label} exceeded its output limit`);
  if (result.resultClass === "UNKNOWN_OUTCOME") {
    return (command, preState, artifact, alreadyInstalled, matchedVersion) => unknownOutcome(
      command,
      preState,
      artifact,
      alreadyInstalled,
      matchedVersion,
      `${label} outcome is unresolved`
    );
  }
  if (result.resultClass !== "SUCCEEDED") throw new BrokerError("EXECUTION_FAILED", `${label} failed`);
  return undefined;
}

function unknownOutcome(
  command: UnsignedPrivilegedHelperCommand,
  preState: InstalledPackageReadback | undefined,
  artifact: ApprovedPackageArtifact,
  alreadyInstalled: boolean,
  matchedVersion: boolean,
  summary: string
): PrivilegedHelperExecutionResult {
  return {
    operation: "package_install",
    targetRef: command.targetRef,
    state: "unknown",
    resultClass: "UNKNOWN_OUTCOME",
    evidence: {
      installed_version: preState?.version ?? "unknown",
      artifact_id: artifact.artifactId,
      already_installed: alreadyInstalled,
      matched_version: matchedVersion,
      state: "failed"
    },
    warnings: [summary],
    truncated: false,
    verification: { status: "unknown", strategy: "allowlisted_postcondition", summary }
  };
}

function boundedTimeout(control: PrivilegedHelperExecutionControl): number {
  if (!control || typeof control.shouldCancel !== "function" || !Number.isSafeInteger(control.timeoutMs) || control.timeoutMs < 1) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged package-install execution budget is invalid");
  }
  return Math.min(control.timeoutMs, MAX_OPERATION_TIMEOUT_MS);
}

function checkControl(control: PrivilegedHelperExecutionControl, deadlineMs: number, now: () => number): void {
  if (control.shouldCancel()) throw new BrokerError("CANCELLED", "Privileged package-install operation was cancelled");
  if (now() >= deadlineMs) throw new BrokerError("TIMEOUT", "Privileged package-install operation timed out");
}

function remaining(deadlineMs: number, now: () => number): number {
  const value = deadlineMs - now();
  if (value <= 0) throw new BrokerError("TIMEOUT", "Privileged package-install operation timed out");
  return value;
}

function isRootProcess(): boolean {
  try { return typeof process.getuid === "function" && process.getuid() === 0; }
  catch { return false; }
}
