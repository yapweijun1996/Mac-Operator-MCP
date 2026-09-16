import { lstat } from "node:fs/promises";
import { createHash, randomBytes } from "node:crypto";
import { realpathSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { FilesystemInspector, type FilesystemIdentityPrecondition, type FilesystemPathPlan } from "./filesystem-inspector.js";
import type { BrokerServiceMetadata, BrokerServiceReadback } from "./service-entrypoint.js";
import { capturePeerProcessIdentity, type PeerProcessIdentity } from "./peer-credentials.js";
import { LaunchdReadbackError, readLaunchdJobReadback, type LaunchdJobReadback, type LaunchdReadbackExecutor } from "./launchd-readback.js";
import { normalizeLaunchdServiceConfig, renderLaunchdPlist, type LaunchdServiceConfig, type LaunchdServiceReadback } from "./launchd.js";
import { ProcessSupervisor, type ProcessExecutionResult } from "./process-supervisor.js";
import { readBrokerStatus, type BrokerStatusClientOptions } from "./broker-status-ipc.js";
import { isPlainDataRecord } from "./plain-record.js";

const LAUNCHCTL_PATH = "/bin/launchctl";
const SERVICE_TIMEOUT_MS = 5_000;
const SERVICE_OUTPUT_CAP_BYTES = 131_072 as const;
const MAX_PLAN_BYTES = 512 * 1024;
const MAX_CAPABILITIES = 128;

export type MacOsInstallOperation = "install" | "upgrade" | "rollback" | "uninstall";
export type MacOsSignaturePolicy = "developer-id" | "development-ad-hoc";

export type MacOsInstallPlanErrorCode =
  | "INVALID_ARGUMENT"
  | "INVALID_USER_DOMAIN"
  | "INVALID_INSTALL_ROOT"
  | "INVALID_PLIST_PATH"
  | "INVALID_PACKAGE_PATH"
  | "INVALID_SIGNATURE_EXPECTATION"
  | "INVALID_METADATA"
  | "FILESYSTEM_MISMATCH"
  | "INVALID_READBACK"
  | "SIGNATURE_MISMATCH"
  | "SERVICE_MISMATCH"
  | "CONFIRMATION_REQUIRED"
  | "AUTHORITY_FAILED"
  | "AUTHORITY_MISMATCH"
  | "COMMAND_FAILED"
  | "READBACK_FAILED"
  | "RECOVERY_FAILED";

export class MacOsInstallPlanError extends Error {
  readonly code: MacOsInstallPlanErrorCode;

  constructor(code: MacOsInstallPlanErrorCode, message: string) {
    super(message);
    this.name = "MacOsInstallPlanError";
    this.code = code;
  }
}

export interface CodeSignatureExpectation {
  identifier: string;
  teamIdentifier?: string;
  cdHash?: string;
}

export interface CodeSignatureReadback {
  artifactPath: string;
  valid: boolean;
  identifier: string | null;
  teamIdentifier: string | null;
  cdHash: string | null;
}

export interface LaunchdCommandSpec {
  executable: "/bin/launchctl";
  args: readonly string[];
  cwd: "/";
  environment: Readonly<Record<string, string>>;
  timeoutMs: 5_000;
  outputCapBytes: 131_072;
}

export interface CodeSignatureCommandSpec {
  executable: "/usr/bin/codesign";
  args: readonly ["--verify", "--strict", "--deep", string];
  cwd: "/";
  environment: Readonly<Record<string, string>>;
  timeoutMs: 5_000;
  outputCapBytes: 131_072;
}

export interface CodeSignatureDetailsCommandSpec {
  executable: "/usr/bin/codesign";
  args: readonly ["-dv", "--verbose=4", string];
  cwd: "/";
  environment: Readonly<Record<string, string>>;
  timeoutMs: 5_000;
  outputCapBytes: 131_072;
}

export interface InstallFileAction {
  kind: "write-plist" | "restore-plist" | "remove-plist";
  path: string;
  mode: 0o600;
  backupPath?: string;
  content?: string;
}

export interface MacOsInstallPlanInput {
  operation?: MacOsInstallOperation;
  uid: number;
  userHome: string;
  installRoot: string;
  plistPath: string;
  service: LaunchdServiceConfig;
  metadata: BrokerServiceMetadata;
  signature: CodeSignatureExpectation;
  /** Production is the default; ad-hoc artifacts require an explicit test/development mode. */
  signaturePolicy?: MacOsSignaturePolicy;
  signedArtifactPath: string;
  enabledCapabilities?: readonly string[];
  expectedPreviousSourceRevision?: string;
}

/** Metadata emitted by the packaged Edge process. Kept structural here so the
 * Broker package does not depend on the Edge package at runtime. */
export interface MacOsEdgeServiceMetadata {
  component: "mac-operator-edge";
  sourceRevision: string;
  contractVersion: string;
  policyVersion: string;
}

export interface MacOsEdgeInstallPlanInput extends Omit<MacOsInstallPlanInput, "metadata"> {
  metadata: MacOsEdgeServiceMetadata;
  bindHost: string;
  bindPort: number;
}

export type MacOsServiceMetadata = BrokerServiceMetadata | MacOsEdgeServiceMetadata;

type MacOsServiceInstallPlanInput = Omit<MacOsInstallPlanInput, "metadata"> & {
  metadata: MacOsServiceMetadata;
};

/** Common, component-neutral LaunchAgent plan fields. */
export interface MacOsServiceInstallPlanBase {
  operation: MacOsInstallOperation;
  component: MacOsServiceMetadata["component"];
  domain: string;
  label: string;
  userHome: string;
  installRoot: string;
  plistPath: string;
  entrypointPath: string;
  backupPath: string;
  metadata: MacOsServiceMetadata;
  edgeListener?: { bindHost: string; bindPort: number };
  signature: CodeSignatureExpectation;
  signaturePolicy: MacOsSignaturePolicy;
  signedArtifactPath: string;
  enabledCapabilities: readonly string[];
  expectedPreviousSourceRevision?: string;
  launchd: MacOsLaunchdServiceReadback;
  renderedPlist: string;
  preflight: readonly string[];
  signatureVerify: CodeSignatureCommandSpec;
  install: {
    file: InstallFileAction;
    bootstrap: LaunchdCommandSpec;
  };
  rollback: {
    bootout: LaunchdCommandSpec;
    file: InstallFileAction;
    bootstrap: LaunchdCommandSpec;
  };
  uninstall: {
    bootout: LaunchdCommandSpec;
    file: InstallFileAction;
  };
}

/**
 * LaunchAgent configuration plus the identity fields that must survive into
 * the composed install readback. Generic launchd configuration intentionally
 * omits service-domain/type details; macOS install validation cannot.
 */
export interface MacOsLaunchdServiceReadback extends LaunchdServiceReadback {
  domain: `gui/${number}`;
  type: "LaunchAgent";
}

export interface MacOsInstallPlan extends MacOsServiceInstallPlanBase {
  component: "mac-operator-broker";
  metadata: BrokerServiceMetadata;
}

export type MacOsEdgeInstallPlan = MacOsServiceInstallPlanBase & {
  component: "mac-operator-edge";
  metadata: MacOsEdgeServiceMetadata;
};

export interface MacOsInstallReadback {
  domain: string;
  label: string;
  plistPath: string;
  /** PID from launchd, bound to the native start-time identity readback. */
  pid: number;
  processIdentity: PeerProcessIdentity;
  plist: MacOsPlistReadback;
  launchd: MacOsLaunchdServiceReadback;
  broker: BrokerServiceReadback;
  signature: CodeSignatureReadback;
}

export interface MacOsInstallReadbackSources {
  launchd: LaunchdJobReadback;
  processIdentity: PeerProcessIdentity;
  plist: MacOsPlistReadback;
  broker: BrokerServiceReadback;
  signature: CodeSignatureReadback;
}

export interface MacOsInstallReadbackObserver {
  readLaunchd(serviceId: string): Promise<LaunchdJobReadback>;
  readProcessIdentity(pid: number): Promise<PeerProcessIdentity> | PeerProcessIdentity;
  readPlist(plan: MacOsInstallPlan): Promise<MacOsPlistReadback>;
  readBroker(): Promise<BrokerServiceReadback>;
  readSignature(): Promise<CodeSignatureReadback>;
}

export interface MacOsEdgeServiceReadback {
  component: "mac-operator-edge";
  state: "stopped" | "starting" | "running" | "stopping" | "failed";
  sourceRevision: string;
  contractVersion: string;
  policyVersion: string;
  bindHost: string;
  bindPort: number;
  listening: boolean;
}

export interface MacOsEdgeInstallReadback {
  domain: string;
  label: string;
  plistPath: string;
  pid: number;
  processIdentity: PeerProcessIdentity;
  plist: MacOsPlistReadback;
  launchd: MacOsLaunchdServiceReadback;
  edge: MacOsEdgeServiceReadback;
  signature: CodeSignatureReadback;
}

export interface MacOsEdgeInstallReadbackSources {
  launchd: LaunchdJobReadback;
  processIdentity: PeerProcessIdentity;
  plist: MacOsPlistReadback;
  edge: MacOsEdgeServiceReadback;
  signature: CodeSignatureReadback;
}

export interface MacOsEdgeInstallReadbackObserver {
  readLaunchd(serviceId: string): Promise<LaunchdJobReadback>;
  readProcessIdentity(pid: number): Promise<PeerProcessIdentity> | PeerProcessIdentity;
  readPlist(plan: MacOsEdgeInstallPlan): Promise<MacOsPlistReadback>;
  readEdge(): Promise<MacOsEdgeServiceReadback>;
  readSignature(): Promise<CodeSignatureReadback>;
}

export interface MacOsInstallHostObserverOptions {
  /**
   * Must be an authenticated or same-process Broker-owned status source. A
   * preassembled install readback is intentionally not accepted.
   */
  readBroker?: () => Promise<BrokerServiceReadback>;
  brokerStatusClient?: BrokerStatusClientOptions;
  launchdExecutor?: LaunchdReadbackExecutor;
  signatureExecutor?: MacOsInstallCommandExecutor;
  processIdentityReader?: (pid: number) => PeerProcessIdentity;
  readPlist?: (plan: MacOsInstallPlan) => Promise<MacOsPlistReadback>;
  readSignature?: (plan: MacOsInstallPlan) => Promise<CodeSignatureReadback>;
}

export interface MacOsEdgeInstallHostObserverOptions {
  /** Edge readback must come from the same Edge process or an authenticated
   * owner-only channel; a caller-supplied final readback is not accepted. */
  readEdge: () => Promise<MacOsEdgeServiceReadback>;
  launchdExecutor?: LaunchdReadbackExecutor;
  signatureExecutor?: MacOsInstallCommandExecutor;
  processIdentityReader?: (pid: number) => PeerProcessIdentity;
  readPlist?: (plan: MacOsEdgeInstallPlan) => Promise<MacOsPlistReadback>;
  readSignature?: (plan: MacOsEdgeInstallPlan) => Promise<CodeSignatureReadback>;
}

export interface ExistingServiceReadback {
  present: boolean;
  sourceRevision: string | null;
}

export interface MacOsExistingServiceReadbackObserver {
  readLaunchd(serviceId: string): Promise<LaunchdJobReadback>;
  /** Required for upgrade, rollback, and uninstall; omitted for install probes. */
  readSourceRevision?: () => Promise<string> | string;
}

/**
 * Creates the host-owned existing-service source used before a LaunchAgent
 * mutation. Launchd presence is authoritative; a prior source revision is
 * read from the same authenticated Broker/Edge status channel for non-install
 * operations. MCP arguments are never consulted.
 */
export function createMacOsExistingServiceReader(
  plan: MacOsServiceInstallPlanBase,
  observer: MacOsExistingServiceReadbackObserver
): () => Promise<ExistingServiceReadback> {
  if (observer === null || typeof observer !== "object" || typeof observer.readLaunchd !== "function") {
    fail("INVALID_ARGUMENT", "existing-service observer is malformed");
  }
  if (plan.operation !== "install" && typeof observer.readSourceRevision !== "function") {
    fail("INVALID_ARGUMENT", "non-install existing-service observer requires a source revision reader");
  }
  const serviceId = `${plan.domain}/${plan.label}`;
  return async () => {
    let launchd: LaunchdJobReadback;
    try {
      launchd = await observer.readLaunchd(serviceId);
    } catch (error) {
      if (error instanceof LaunchdReadbackError && error.code === "UNAVAILABLE") {
        return { present: false, sourceRevision: null };
      }
      if (error instanceof MacOsInstallPlanError) throw error;
      fail("READBACK_FAILED", "existing-service launchd readback failed");
    }
    if (!isRecord(launchd)) {
      fail("INVALID_READBACK", "existing-service launchd readback is malformed");
    }
    const launchdArguments: unknown = launchd.arguments;
    const validArguments = launchdArguments === null ||
      (Array.isArray(launchdArguments) && launchdArguments.every((value) => typeof value === "string"));
    if (!validArguments) {
      fail("INVALID_READBACK", "existing-service launchd readback is malformed");
    }
    if (launchd.serviceId !== serviceId || launchd.domain !== plan.domain || launchd.label !== plan.label ||
        launchd.type !== "LaunchAgent" || launchd.truncated !== false ||
        launchd.program !== plan.launchd.program ||
        !sameStrings((launchd.arguments ?? []) as readonly string[], plan.launchd.programArguments) ||
        launchd.plistPath !== plan.plistPath) {
      fail("SERVICE_MISMATCH", "existing-service launchd identity does not match the plan");
    }
    if (plan.operation === "install") return { present: true, sourceRevision: null };
    let sourceRevision: string;
    try {
      sourceRevision = await observer.readSourceRevision!();
    } catch (error) {
      if (error instanceof MacOsInstallPlanError) throw error;
      fail("READBACK_FAILED", "existing-service runtime revision readback failed");
    }
    if (typeof sourceRevision !== "string" || !/^[0-9a-f]{7,64}$/u.test(sourceRevision)) {
      fail("SERVICE_MISMATCH", "existing-service source revision is malformed");
    }
    return { present: true, sourceRevision };
  };
}

/** Samples a host precondition twice so a service replacement cannot race an
 * install, upgrade, rollback, or uninstall decision. */
export async function readMacOsExistingServiceSnapshot(
  reader: () => Promise<ExistingServiceReadback> | ExistingServiceReadback
): Promise<ExistingServiceReadback> {
  if (typeof reader !== "function") fail("INVALID_ARGUMENT", "existing-service reader is required");
  let first: ExistingServiceReadback;
  let second: ExistingServiceReadback;
  try {
    first = await reader();
    second = await reader();
  } catch (error) {
    if (error instanceof MacOsInstallPlanError) throw error;
    fail("READBACK_FAILED", "existing-service readback failed");
  }
  validateExistingServiceSnapshot(first);
  validateExistingServiceSnapshot(second);
  if (!sameExistingService(first, second)) {
    fail("SERVICE_MISMATCH", "existing-service identity changed during preflight");
  }
  return first;
}

export interface InstallFilesystemOptions {
  ownerUid: number;
  requirePlist?: boolean;
}

export interface InstallFilesystemEntryReadback {
  path: string;
  kind: "file" | "directory";
  ownerUid: number;
  mode: number;
  device: number;
  inode: number;
}

export interface InstallFilesystemReadback {
  ownerUid: number;
  entries: readonly InstallFilesystemEntryReadback[];
}

export interface MacOsPlistApplyOptions {
  ownerUid: number;
  inspector?: FilesystemInspector;
}

export interface MacOsPlistApplyResult {
  operation: "install" | "upgrade" | "rollback" | "uninstall";
  path: string;
  bytesWritten: number;
  sha256: string | null;
  created: boolean;
  backupPath: string | null;
  backupSha256: string | null;
  device: string;
  inode: string;
}

export interface MacOsPlistReadback {
  path: string;
  bytes: number;
  sha256: string;
  device: string;
  inode: string;
}

export interface MacOsInstallCommandExecutor {
  run(command: LaunchdCommandSpec | CodeSignatureCommandSpec | CodeSignatureDetailsCommandSpec): Promise<ProcessExecutionResult>;
}

export interface MacOsInstallExecutionOptions extends MacOsPlistApplyOptions {
  /** Host-only confirmation; it must exactly match the planned operation. */
  confirmOperation: MacOsInstallOperation;
  /** Optional caller snapshot retained only as a consistency hint. */
  existingService?: ExistingServiceReadback;
  /** Host-owned, read-only precondition source. It is sampled twice before mutation. */
  readExistingService: () => Promise<ExistingServiceReadback> | ExistingServiceReadback;
  commandExecutor?: MacOsInstallCommandExecutor;
  /** Returns only independently observed sources; execution composes them. */
  readback: () => Promise<MacOsInstallReadbackSources | null>;
}

export interface MacOsInstallExecutionResult {
  operation: MacOsInstallOperation;
  readback: MacOsInstallReadback | null;
  plist: MacOsPlistApplyResult;
}

export interface MacOsEdgeInstallExecutionOptions extends MacOsPlistApplyOptions {
  confirmOperation: MacOsInstallOperation;
  /** Optional caller snapshot retained only as a consistency hint. */
  existingService?: ExistingServiceReadback;
  /** Host-owned, read-only precondition source. It is sampled twice before mutation. */
  readExistingService: () => Promise<ExistingServiceReadback> | ExistingServiceReadback;
  commandExecutor?: MacOsInstallCommandExecutor;
  readback: () => Promise<MacOsEdgeInstallReadbackSources | null>;
}

export interface MacOsEdgeInstallExecutionResult {
  operation: MacOsInstallOperation;
  readback: MacOsEdgeInstallReadback | null;
  plist: MacOsPlistApplyResult;
}

type ExpectedFilesystemKind = "file" | "directory" | "file-or-directory";

/**
 * Builds a reviewable, non-executing LaunchAgent installation plan.
 *
 * The plan contains only fixed argv and explicit file actions. It never calls
 * launchctl, writes a plist, signs code, or changes launchd state.
 */
export function buildMacOsInstallPlan(input: MacOsInstallPlanInput): MacOsInstallPlan {
  return buildMacOsServiceInstallPlan(input, "mac-operator-broker") as MacOsInstallPlan;
}

/** Builds the reviewed LaunchAgent plan for the HTTPS Edge component. */
export function buildMacOsEdgeInstallPlan(input: MacOsEdgeInstallPlanInput): MacOsEdgeInstallPlan {
  return buildMacOsServiceInstallPlan(input, "mac-operator-edge") as MacOsEdgeInstallPlan;
}

function buildMacOsServiceInstallPlan(
  input: MacOsServiceInstallPlanInput,
  component: MacOsServiceMetadata["component"]
): MacOsServiceInstallPlanBase {
  if (input === null || typeof input !== "object") fail("INVALID_ARGUMENT", "macOS install plan input is malformed");
  const operation = input.operation ?? "install";
  if (!["install", "upgrade", "rollback", "uninstall"].includes(operation)) {
    fail("INVALID_ARGUMENT", "macOS install operation is invalid");
  }
  if (!Number.isSafeInteger(input.uid) || input.uid < 1 || input.uid > 2_147_483_647) {
    fail("INVALID_USER_DOMAIN", "a positive non-root launchd uid is required");
  }
  const service = normalizeLaunchdServiceConfig(input.service);
  const expectedLabel = component === "mac-operator-broker" ? "com.mac-operator.broker" : "com.mac-operator.edge";
  if (service.label !== expectedLabel) {
    fail("INVALID_METADATA", `service label must be ${expectedLabel} for ${component}`);
  }
  const userHome = canonicalPath(input.userHome, "user home");
  const installRoot = canonicalPath(input.installRoot, "install root");
  if (userHome === "/" || installRoot === "/" || !isDescendant(userHome, installRoot)) {
    fail("INVALID_INSTALL_ROOT", "install root must be a non-root descendant of the user home");
  }
  const expectedPlistPath = join(userHome, "Library", "LaunchAgents", `${service.label}.plist`);
  const plistPath = canonicalPath(input.plistPath, "plist path");
  if (plistPath !== expectedPlistPath || plistPath.startsWith("/Library/LaunchDaemons/")) {
    fail("INVALID_PLIST_PATH", "plist path must be the exact per-user LaunchAgent path");
  }
  if (!isDescendant(installRoot, service.program) || !isWithin(installRoot, service.workingDirectory, true) ||
      !isDescendant(installRoot, service.stdoutPath) || !isDescendant(installRoot, service.stderrPath)) {
    fail("INVALID_PACKAGE_PATH", "program, working directory, and logs must remain inside the install root");
  }
  if (dirname(service.stdoutPath) !== dirname(service.stderrPath)) {
    fail("INVALID_PACKAGE_PATH", "stdout and stderr must use the same package-owned log directory");
  }
  const signedArtifactPath = canonicalPath(input.signedArtifactPath, "signed artifact path");
  if (!isDescendant(installRoot, signedArtifactPath)) {
    fail("INVALID_PACKAGE_PATH", "signed artifact must remain inside the install root");
  }
  const entrypoint = service.programArguments[1];
  if (service.programArguments.length !== 2 || typeof entrypoint !== "string" ||
      !isDescendant(installRoot, entrypoint) || !/\.(?:c|m)?js$/u.test(entrypoint)) {
    fail("INVALID_PACKAGE_PATH", "launchd must invoke exactly one package-owned JavaScript entrypoint");
  }
  const capabilities = normalizeCapabilities(input.enabledCapabilities ?? []);
  const metadata = normalizeServiceMetadata(input.metadata, component);
  const edgeListener = component === "mac-operator-edge" ? normalizeEdgeListener(input) : undefined;
  const signaturePolicy = normalizeSignaturePolicy(input.signaturePolicy);
  if (signaturePolicy === "development-ad-hoc" && capabilities.length > 0) {
    fail("INVALID_SIGNATURE_EXPECTATION", "development ad-hoc installs must not enable capabilities");
  }
  const signature = normalizeSignatureExpectation(input.signature, signaturePolicy, expectedLabel);
  const expectedPreviousSourceRevision = normalizePreviousRevision(input.expectedPreviousSourceRevision, operation);
  const renderedPlist = renderLaunchdPlist(service);
  if (Buffer.byteLength(renderedPlist, "utf8") > MAX_PLAN_BYTES) {
    fail("INVALID_ARGUMENT", "rendered launchd plist exceeds the plan budget");
  }
  const domain = `gui/${String(input.uid)}` as `gui/${number}`;
  const backupPath = `${plistPath}.previous`;
  const signatureVerify = codesignVerifyCommand(signedArtifactPath);
  const bootstrap = launchctlCommand(["bootstrap", domain, plistPath]);
  const bootout = launchctlCommand(["bootout", `${domain}/${service.label}`]);
  const file = { kind: "write-plist", path: plistPath, mode: 0o600, content: renderedPlist } as const;
  const restore = { kind: "restore-plist", path: plistPath, mode: 0o600, backupPath } as const;
  const remove = { kind: "remove-plist", path: plistPath, mode: 0o600 } as const;
  const launchd = {
    domain,
    type: "LaunchAgent" as const,
    label: service.label,
    program: service.program,
    programArguments: [...service.programArguments],
    workingDirectory: service.workingDirectory,
    stdoutPath: service.stdoutPath,
    stderrPath: service.stderrPath,
    runsAsUnprivilegedUser: true,
    usesEnvironmentVariables: false,
    usesShell: false,
    runAtLoad: service.runAtLoad,
    keepAlive: service.keepAlive,
    throttleIntervalSeconds: service.throttleIntervalSeconds
  } satisfies MacOsLaunchdServiceReadback;
  return {
    operation,
    component,
    domain,
    label: service.label,
    userHome,
    installRoot,
    plistPath,
    entrypointPath: entrypoint,
    backupPath,
    metadata,
    ...(edgeListener === undefined ? {} : { edgeListener }),
    signature,
    signaturePolicy,
    signedArtifactPath,
    enabledCapabilities: capabilities,
    ...(expectedPreviousSourceRevision === undefined ? {} : { expectedPreviousSourceRevision }),
    launchd,
    renderedPlist,
    signatureVerify,
    preflight: [
      "verify the signed artifact and native module code signatures before writing the plist",
      "verify owner-only modes on package files, plist parent directories, and log directory",
      operation === "install" ? "verify existing service readback is absent before installation" :
        operation === "uninstall" ? "verify existing service readback matches the approved uninstall target" :
          `verify existing service readback matches prior source revision ${expectedPreviousSourceRevision}`,
      `write the plist atomically, bootstrap the exact per-user domain, then verify launchd and ${component === "mac-operator-broker" ? "Broker" : "Edge"} readback`,
      "on any mismatch, bootout the exact label, restore the previous plist, and verify the service is absent or restored"
    ],
    install: { file, bootstrap },
    rollback: { bootout, file: restore, bootstrap },
    uninstall: { bootout, file: remove }
  };
}

export function validateCodeSignatureReadback(
  expected: CodeSignatureExpectation,
  actual: CodeSignatureReadback,
  expectedArtifactPath: string
): void {
  const candidate = expected !== null && typeof expected === "object" ? expected as Partial<CodeSignatureExpectation> : undefined;
  const normalizedExpected = normalizeSignatureExpectation(
    expected,
    candidate?.teamIdentifier === undefined || candidate.cdHash === undefined ? "development-ad-hoc" : "developer-id",
    typeof candidate?.identifier === "string" ? candidate.identifier : ""
  );
  if (actual === null || typeof actual !== "object" || actual.valid !== true ||
      actual.artifactPath !== expectedArtifactPath ||
      typeof actual.identifier !== "string" || actual.identifier !== normalizedExpected.identifier ||
      (normalizedExpected.teamIdentifier !== undefined && actual.teamIdentifier !== normalizedExpected.teamIdentifier) ||
      (normalizedExpected.cdHash !== undefined && actual.cdHash !== normalizedExpected.cdHash)) {
    fail("SIGNATURE_MISMATCH", "code signature readback does not match the expected package identity");
  }
}

/**
 * Verifies exact post-bootstrap identity. A successful launchctl command alone
 * is insufficient: the domain, paths, signature, Broker metadata, and native
 * transport requirement must all match before the service is considered ready.
 */
export function validateMacOsInstallReadback(plan: MacOsInstallPlan, readback: MacOsInstallReadback): void {
  if (plan.component !== "mac-operator-broker" || plan.metadata.component !== "mac-operator-broker" ||
      !isRecord(readback) || !isRecord(readback.launchd) || !isRecord(readback.broker) ||
      !isRecord(readback.signature) || !isRecord(readback.processIdentity) || !isRecord(readback.plist)) {
    fail("INVALID_READBACK", "service readback is malformed");
  }
  const expectedUid = plan.domain.slice("gui/".length);
  if (readback.domain !== plan.domain || readback.label !== plan.label || readback.plistPath !== plan.plistPath ||
      !/^\d+$/.test(expectedUid) || !Number.isSafeInteger(readback.pid) || readback.pid < 1 ||
      !Number.isSafeInteger(readback.processIdentity.pid) || readback.processIdentity.pid < 1 ||
      !Number.isSafeInteger(readback.processIdentity.startTimeMicros) || readback.processIdentity.startTimeMicros < 1 ||
      readback.processIdentity.pid !== readback.pid || readback.plist.path !== expectedPlistReadbackPath(plan) ||
      !Number.isSafeInteger(readback.plist.bytes) || readback.plist.bytes !== Buffer.byteLength(plan.renderedPlist, "utf8") ||
      typeof readback.plist.sha256 !== "string" || readback.plist.sha256 !== renderedPlistSha256(plan) ||
      typeof readback.plist.device !== "string" || !/^\d+$/u.test(readback.plist.device) ||
      typeof readback.plist.inode !== "string" || !/^\d+$/u.test(readback.plist.inode)) {
    fail("SERVICE_MISMATCH", "launchd readback does not match the planned per-user service");
  }
  if (readback.launchd.domain !== plan.domain || readback.launchd.type !== "LaunchAgent" ||
      readback.launchd.label !== plan.launchd.label || readback.launchd.program !== plan.launchd.program ||
      !sameStrings(readback.launchd.programArguments, plan.launchd.programArguments) ||
      readback.launchd.workingDirectory !== plan.launchd.workingDirectory ||
      readback.launchd.stdoutPath !== plan.launchd.stdoutPath || readback.launchd.stderrPath !== plan.launchd.stderrPath ||
      readback.launchd.runsAsUnprivilegedUser !== true || readback.launchd.usesEnvironmentVariables !== false ||
      readback.launchd.usesShell !== false || readback.launchd.runAtLoad !== plan.launchd.runAtLoad ||
      readback.launchd.keepAlive !== plan.launchd.keepAlive ||
      readback.launchd.throttleIntervalSeconds !== plan.launchd.throttleIntervalSeconds) {
    fail("SERVICE_MISMATCH", "launchd configuration readback does not match the plan");
  }
  if (readback.broker.component !== plan.metadata.component || readback.broker.state !== "running" ||
      readback.broker.runtimeState !== "running" || readback.broker.nativeTransportRequired !== true ||
      readback.broker.sourceRevision !== plan.metadata.sourceRevision ||
      readback.broker.contractVersion !== plan.metadata.contractVersion ||
      readback.broker.policyVersion !== plan.metadata.policyVersion ||
      !sameStrings(readback.broker.enabledCapabilities, plan.enabledCapabilities)) {
    fail("SERVICE_MISMATCH", "Broker service readback does not match the planned identity or capability set");
  }
  validateCodeSignatureReadback(plan.signature, readback.signature, plan.signedArtifactPath);
}

/**
 * Composes the final install readback only from independently observed
 * launchd, native process, Broker, and code-signature sources. The launchd
 * parser is the authority for service identity, state, PID, program, plist,
 * and LaunchAgent type; the planned launch configuration remains the source
 * for fields that launchctl does not expose in its stable print format.
 */
export function composeMacOsInstallReadback(
  plan: MacOsInstallPlan,
  sources: MacOsInstallReadbackSources
): MacOsInstallReadback {
  if (!isRecord(sources) || !isRecord(sources.launchd) || !isRecord(sources.processIdentity) ||
      !isRecord(sources.plist) || !isRecord(sources.broker) || !isRecord(sources.signature)) {
    fail("INVALID_READBACK", "install readback sources are malformed");
  }
  const expectedServiceId = `${plan.domain}/${plan.label}`;
  const launchd = sources.launchd;
  if (launchd.serviceId !== expectedServiceId || launchd.domain !== plan.domain || launchd.label !== plan.label ||
      launchd.state !== "running" || launchd.type !== "LaunchAgent" || launchd.pid === null ||
      launchd.program !== plan.launchd.program || launchd.plistPath !== expectedPlistReadbackPath(plan) ||
      !sameStrings(launchd.arguments ?? [], plan.launchd.programArguments) ||
      launchd.pid !== sources.processIdentity.pid) {
    fail("SERVICE_MISMATCH", "launchd readback sources do not match the planned Broker service");
  }
  const readback: MacOsInstallReadback = {
    domain: plan.domain,
    label: plan.label,
    plistPath: plan.plistPath,
    pid: launchd.pid,
    processIdentity: sources.processIdentity,
    plist: sources.plist,
    launchd: plan.launchd,
    broker: sources.broker,
    signature: sources.signature
  };
  validateMacOsInstallReadback(plan, readback);
  return readback;
}

/**
 * Collects raw install readback sources with replacement-resistant identity
 * checks. Launchd, process, and plist sources are sampled twice; the Broker
 * status and signature are kept as separate observations and are never
 * accepted as a caller-assembled final readback.
 */
export async function collectMacOsInstallReadbackSources(
  plan: MacOsInstallPlan,
  observer: MacOsInstallReadbackObserver
): Promise<MacOsInstallReadbackSources> {
  try {
    if (observer === null || typeof observer !== "object") {
      fail("INVALID_READBACK", "install readback observer is malformed");
    }
    const serviceId = `${plan.domain}/${plan.label}`;
    const launchdBefore = await readRunningLaunchd(observer.readLaunchd, serviceId);
    if (launchdBefore.pid === null) fail("SERVICE_MISMATCH", "install launchd readback has no running PID");
    const launchdBeforePid = launchdBefore.pid;
    const processBefore = await observer.readProcessIdentity(launchdBeforePid);
    const plistBefore = await observer.readPlist(plan);
    const broker = await observer.readBroker();
    const signature = await observer.readSignature();
    const launchdAfter = await readRunningLaunchd(observer.readLaunchd, serviceId);
    if (launchdAfter.pid === null) fail("SERVICE_MISMATCH", "install launchd readback has no running PID");
    if (!sameLaunchdIdentity(launchdBefore, launchdAfter)) {
      fail("SERVICE_MISMATCH", "install launchd identity changed during readback");
    }
    const launchdAfterPid = launchdAfter.pid;
    const processAfter = await observer.readProcessIdentity(launchdAfterPid);
    if (!sameProcessIdentity(processBefore, processAfter)) {
      fail("SERVICE_MISMATCH", "install process identity changed during readback");
    }
    const plistAfter = await observer.readPlist(plan);
    if (!samePlistIdentity(plistBefore, plistAfter)) {
      fail("FILESYSTEM_MISMATCH", "install plist identity changed during readback");
    }
    return {
      launchd: launchdAfter,
      processIdentity: processAfter,
      plist: plistAfter,
      broker,
      signature
    };
  } catch (error) {
    if (error instanceof MacOsInstallPlanError) throw error;
    fail("READBACK_FAILED", "macOS install host readback failed");
  }
}

async function readRunningLaunchd(
  readLaunchd: (serviceId: string) => Promise<LaunchdJobReadback>,
  serviceId: string
): Promise<LaunchdJobReadback> {
  let latest: LaunchdJobReadback | undefined;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    latest = await readLaunchd(serviceId);
    if (latest.state === "running" && latest.pid !== null) return latest;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
  }
  fail("SERVICE_MISMATCH", latest?.pid === null ? "install launchd readback has no running PID" : "install launchd service did not reach running state");
}

/** Collects and composes the final install readback for host-only callers. */
export async function observeMacOsInstallReadback(
  plan: MacOsInstallPlan,
  observer: MacOsInstallReadbackObserver
): Promise<MacOsInstallReadback> {
  return composeMacOsInstallReadback(plan, await collectMacOsInstallReadbackSources(plan, observer));
}

export function validateMacOsEdgeInstallReadback(
  plan: MacOsEdgeInstallPlan,
  readback: MacOsEdgeInstallReadback
): void {
  if (plan.component !== "mac-operator-edge" || plan.metadata.component !== "mac-operator-edge" ||
      plan.edgeListener === undefined ||
      !isRecord(readback) || !isRecord(readback.launchd) || !isRecord(readback.edge) ||
      !isRecord(readback.signature) || !isRecord(readback.processIdentity) || !isRecord(readback.plist)) {
    fail("INVALID_READBACK", "Edge service readback is malformed");
  }
  const expectedUid = plan.domain.slice("gui/".length);
  if (readback.domain !== plan.domain || readback.label !== plan.label || readback.plistPath !== plan.plistPath ||
      !/^\d+$/.test(expectedUid) || !Number.isSafeInteger(readback.pid) || readback.pid < 1 ||
      !Number.isSafeInteger(readback.processIdentity.pid) || readback.processIdentity.pid < 1 ||
      !Number.isSafeInteger(readback.processIdentity.startTimeMicros) || readback.processIdentity.startTimeMicros < 1 ||
      readback.processIdentity.pid !== readback.pid || readback.plist.path !== expectedPlistReadbackPath(plan) ||
      !Number.isSafeInteger(readback.plist.bytes) || readback.plist.bytes !== Buffer.byteLength(plan.renderedPlist, "utf8") ||
      typeof readback.plist.sha256 !== "string" || readback.plist.sha256 !== renderedPlistSha256(plan) ||
      typeof readback.plist.device !== "string" || !/^\d+$/u.test(readback.plist.device) ||
      typeof readback.plist.inode !== "string" || !/^\d+$/u.test(readback.plist.inode)) {
    fail("SERVICE_MISMATCH", "Edge launchd readback does not match the planned per-user service");
  }
  if (readback.launchd.domain !== plan.domain || readback.launchd.type !== "LaunchAgent" ||
      readback.launchd.label !== plan.launchd.label || readback.launchd.program !== plan.launchd.program ||
      !sameStrings(readback.launchd.programArguments, plan.launchd.programArguments) ||
      readback.launchd.workingDirectory !== plan.launchd.workingDirectory ||
      readback.launchd.stdoutPath !== plan.launchd.stdoutPath || readback.launchd.stderrPath !== plan.launchd.stderrPath ||
      readback.launchd.runsAsUnprivilegedUser !== true || readback.launchd.usesEnvironmentVariables !== false ||
      readback.launchd.usesShell !== false || readback.launchd.runAtLoad !== plan.launchd.runAtLoad ||
      readback.launchd.keepAlive !== plan.launchd.keepAlive ||
      readback.launchd.throttleIntervalSeconds !== plan.launchd.throttleIntervalSeconds) {
    fail("SERVICE_MISMATCH", "Edge launchd configuration readback does not match the plan");
  }
  if (readback.edge.component !== "mac-operator-edge" || readback.edge.state !== "running" ||
      readback.edge.listening !== true || readback.edge.sourceRevision !== plan.metadata.sourceRevision ||
      readback.edge.contractVersion !== plan.metadata.contractVersion ||
      readback.edge.policyVersion !== plan.metadata.policyVersion ||
      readback.edge.bindHost !== plan.edgeListener.bindHost ||
      readback.edge.bindPort !== plan.edgeListener.bindPort) {
    fail("SERVICE_MISMATCH", "Edge service readback does not match the planned identity or listener");
  }
  validateCodeSignatureReadback(plan.signature, readback.signature, plan.signedArtifactPath);
}

export function composeMacOsEdgeInstallReadback(
  plan: MacOsEdgeInstallPlan,
  sources: MacOsEdgeInstallReadbackSources
): MacOsEdgeInstallReadback {
  if (!isRecord(sources) || !isRecord(sources.launchd) || !isRecord(sources.processIdentity) ||
      !isRecord(sources.plist) || !isRecord(sources.edge) || !isRecord(sources.signature)) {
    fail("INVALID_READBACK", "Edge install readback sources are malformed");
  }
  const expectedServiceId = `${plan.domain}/${plan.label}`;
  const launchd = sources.launchd;
  if (launchd.serviceId !== expectedServiceId || launchd.domain !== plan.domain || launchd.label !== plan.label ||
      launchd.state !== "running" || launchd.type !== "LaunchAgent" || launchd.pid === null ||
      launchd.program !== plan.launchd.program || launchd.plistPath !== expectedPlistReadbackPath(plan) ||
      !sameStrings(launchd.arguments ?? [], plan.launchd.programArguments) ||
      launchd.pid !== sources.processIdentity.pid) {
    fail("SERVICE_MISMATCH", "launchd readback sources do not match the planned Edge service");
  }
  const readback: MacOsEdgeInstallReadback = {
    domain: plan.domain,
    label: plan.label,
    plistPath: plan.plistPath,
    pid: launchd.pid,
    processIdentity: sources.processIdentity,
    plist: sources.plist,
    launchd: plan.launchd,
    edge: sources.edge,
    signature: sources.signature
  };
  validateMacOsEdgeInstallReadback(plan, readback);
  return readback;
}

export async function collectMacOsEdgeInstallReadbackSources(
  plan: MacOsEdgeInstallPlan,
  observer: MacOsEdgeInstallReadbackObserver
): Promise<MacOsEdgeInstallReadbackSources> {
  try {
    if (observer === null || typeof observer !== "object") fail("INVALID_READBACK", "Edge install readback observer is malformed");
    const serviceId = `${plan.domain}/${plan.label}`;
    const launchdBefore = await readRunningLaunchd(observer.readLaunchd, serviceId);
    if (launchdBefore.pid === null) fail("SERVICE_MISMATCH", "Edge launchd readback has no running PID");
    const processBefore = await observer.readProcessIdentity(launchdBefore.pid);
    const plistBefore = await observer.readPlist(plan);
    const edge = await observer.readEdge();
    const signature = await observer.readSignature();
    const launchdAfter = await readRunningLaunchd(observer.readLaunchd, serviceId);
    if (launchdAfter.pid === null || !sameLaunchdIdentity(launchdBefore, launchdAfter)) {
      fail("SERVICE_MISMATCH", "Edge launchd identity changed during readback");
    }
    const processAfter = await observer.readProcessIdentity(launchdAfter.pid);
    if (!sameProcessIdentity(processBefore, processAfter)) fail("SERVICE_MISMATCH", "Edge process identity changed during readback");
    const plistAfter = await observer.readPlist(plan);
    if (!samePlistIdentity(plistBefore, plistAfter)) fail("FILESYSTEM_MISMATCH", "Edge plist identity changed during readback");
    return { launchd: launchdAfter, processIdentity: processAfter, plist: plistAfter, edge, signature };
  } catch (error) {
    if (error instanceof MacOsInstallPlanError) throw error;
    fail("READBACK_FAILED", "macOS Edge install host readback failed");
  }
}

export async function observeMacOsEdgeInstallReadback(
  plan: MacOsEdgeInstallPlan,
  observer: MacOsEdgeInstallReadbackObserver
): Promise<MacOsEdgeInstallReadback> {
  return composeMacOsEdgeInstallReadback(plan, await collectMacOsEdgeInstallReadbackSources(plan, observer));
}

/**
 * Creates the production-shaped host observer. Launchd and codesign use the
 * bounded empty-environment supervisor; process identity uses the native
 * Darwin adapter; plist content uses the descriptor-backed installer reader.
 * Broker status remains an explicit authenticated or same-process source.
 */
export function createMacOsInstallHostObserver(
  plan: MacOsInstallPlan,
  options: MacOsInstallHostObserverOptions
): MacOsInstallReadbackObserver {
  if (options === null || typeof options !== "object" ||
      (typeof options.readBroker !== "function" && options.brokerStatusClient === undefined)) {
    fail("INVALID_ARGUMENT", "install host observer requires a Broker-owned status source");
  }
  const readBroker = options.readBroker ?? (() => readBrokerStatus(options.brokerStatusClient!));
  const ownerUid = parseUid(plan.domain);
  return {
    readLaunchd: async (serviceId) => readLaunchdJobReadback(serviceId, options.launchdExecutor === undefined ? {} : { executor: options.launchdExecutor }),
    readProcessIdentity: (pid) => options.processIdentityReader?.(pid) ?? readStableProcessIdentity(pid),
    readPlist: options.readPlist ?? (async (candidate) => readMacOsPlistReadback(candidate, { ownerUid })),
    readBroker,
    readSignature: options.readSignature === undefined
      ? async () => readMacOsCodeSignature(plan, options.signatureExecutor)
      : async () => options.readSignature!(plan)
  };
}

/** Creates a production-shaped Edge observer. Unlike Broker readback there is
 * no status IPC fallback: the caller must provide an authenticated, process-
 * owned Edge lifecycle source. */
export function createMacOsEdgeInstallHostObserver(
  plan: MacOsEdgeInstallPlan,
  options: MacOsEdgeInstallHostObserverOptions
): MacOsEdgeInstallReadbackObserver {
  if (options === null || typeof options !== "object" || typeof options.readEdge !== "function") {
    fail("INVALID_ARGUMENT", "Edge install host observer requires an Edge-owned readback source");
  }
  const ownerUid = parseUid(plan.domain);
  return {
    readLaunchd: async (serviceId) => readLaunchdJobReadback(serviceId, options.launchdExecutor === undefined ? {} : { executor: options.launchdExecutor }),
    readProcessIdentity: (pid) => options.processIdentityReader?.(pid) ?? readStableProcessIdentity(pid),
    readPlist: options.readPlist ?? (async (candidate) => readMacOsPlistReadback(candidate, { ownerUid })),
    readEdge: options.readEdge,
    readSignature: options.readSignature === undefined
      ? async () => readMacOsCodeSignature(plan, options.signatureExecutor)
      : async () => options.readSignature!(plan)
  };
}

/**
 * Reads the exact planned plist through the descriptor-backed filesystem
 * boundary and returns only its stable path, identity, size, and digest. The
 * expected rendered bytes are checked before this source can participate in a
 * final launchd/Broker readback.
 */
export function readMacOsPlistReadback(
  plan: MacOsServiceInstallPlanBase,
  options: MacOsPlistApplyOptions
): MacOsPlistReadback {
  if (!Number.isSafeInteger(options.ownerUid) || options.ownerUid !== parseUid(plan.domain)) {
    fail("FILESYSTEM_MISMATCH", "plist readback owner does not match the planned user domain");
  }
  const inspector = options.inspector ?? createInstallInspector(plan);
  const targetPlan = inspector.planPath(plan.plistPath, "content_read");
  let read: ReturnType<FilesystemInspector["readPlanned"]>;
  try {
    read = inspector.readPlanned(targetPlan, 0, MAX_PLAN_BYTES);
  } catch {
    fail("FILESYSTEM_MISMATCH", "planned plist could not be read through the protected filesystem boundary");
  }
  if (read.truncated || read.path !== expectedPlistReadbackPath(plan) || read.content.byteLength !== Buffer.byteLength(plan.renderedPlist, "utf8")) {
    fail("FILESYSTEM_MISMATCH", "planned plist readback is truncated or has an unexpected identity");
  }
  const sha256 = createHash("sha256").update(read.content).digest("hex");
  if (!read.content.equals(Buffer.from(plan.renderedPlist, "utf8")) || sha256 !== renderedPlistSha256(plan)) {
    fail("FILESYSTEM_MISMATCH", "planned plist content does not match the rendered plan");
  }
  return { path: read.path, bytes: read.content.byteLength, sha256, device: read.device, inode: read.inode };
}

/** Reads only the bounded identity fields from the exact planned artifact. */
export async function readMacOsCodeSignature(
  plan: MacOsServiceInstallPlanBase,
  executor: MacOsInstallCommandExecutor = new ProcessSupervisor({ allowedEnvironmentKeys: [] })
): Promise<CodeSignatureReadback> {
  let verification: ProcessExecutionResult;
  let details: ProcessExecutionResult;
  try {
    verification = await executor.run(plan.signatureVerify);
    if (verification.resultClass !== "SUCCEEDED" || verification.truncated) {
      fail("SIGNATURE_MISMATCH", "code signature verification failed");
    }
    details = await executor.run({
      executable: "/usr/bin/codesign",
      args: ["-dv", "--verbose=4", plan.signedArtifactPath],
      cwd: "/",
      environment: {},
      timeoutMs: SERVICE_TIMEOUT_MS,
      outputCapBytes: SERVICE_OUTPUT_CAP_BYTES
    });
  } catch (error) {
    if (error instanceof MacOsInstallPlanError) throw error;
    fail("SIGNATURE_MISMATCH", "code signature readback failed");
  }
  if (details.resultClass !== "SUCCEEDED" || details.truncated) {
    fail("SIGNATURE_MISMATCH", "code signature details failed");
  }
  const output = `${details.stdout}\n${details.stderr}`;
  const readback: CodeSignatureReadback = {
    artifactPath: plan.signedArtifactPath,
    valid: true,
    identifier: readCodeSignatureField(output, "Identifier", /^[A-Za-z0-9._:-]{1,128}$/u),
    teamIdentifier: readCodeSignatureField(output, "TeamIdentifier", /^[A-Z0-9]{5,32}$/u),
    cdHash: readCodeSignatureField(output, "CDHash", /^[a-f0-9]{20,64}$/u)
  };
  validateCodeSignatureReadback(plan.signature, readback, plan.signedArtifactPath);
  return readback;
}

export function validateExistingServicePrecondition(plan: MacOsServiceInstallPlanBase, readback: ExistingServiceReadback): void {
  validateExistingServiceSnapshot(readback);
  if (plan.operation === "install") {
    if (readback.present || readback.sourceRevision !== null) fail("SERVICE_MISMATCH", "install requires an absent existing service");
    return;
  }
  if (!readback.present || readback.sourceRevision !== plan.expectedPreviousSourceRevision) {
    fail("SERVICE_MISMATCH", "existing service does not match the approved operation precondition");
  }
}

function validateExistingServiceSnapshot(value: ExistingServiceReadback): void {
  if (!isRecord(value) || typeof value.present !== "boolean" ||
      (value.sourceRevision !== null && (typeof value.sourceRevision !== "string" || !/^[0-9a-f]{7,64}$/u.test(value.sourceRevision)))) {
    fail("INVALID_READBACK", "existing service readback is malformed");
  }
}

function sameExistingService(left: ExistingServiceReadback, right: ExistingServiceReadback): boolean {
  return left.present === right.present && left.sourceRevision === right.sourceRevision;
}

/**
 * Performs the read-only filesystem portion of installer preflight. Every
 * checked path is lstat'ed twice and must retain its device/inode identity;
 * symlinks, foreign ownership, group/other write access, and unexpected types
 * fail closed. The caller must still use descriptor-relative atomic writes for
 * the actual installation step.
 */
export async function inspectMacOsInstallFilesystem(
  plan: MacOsServiceInstallPlanBase,
  options: InstallFilesystemOptions
): Promise<InstallFilesystemReadback> {
  if (!Number.isSafeInteger(options.ownerUid) || options.ownerUid < 1 || options.ownerUid !== parseUid(plan.domain)) {
    fail("FILESYSTEM_MISMATCH", "filesystem preflight owner does not match the planned user domain");
  }
  const paths = new Map<string, ExpectedFilesystemKind>();
  paths.set(plan.installRoot, "directory");
  paths.set(plan.launchd.workingDirectory, "directory");
  paths.set(plan.launchd.program, "file");
  paths.set(plan.signedArtifactPath, "file-or-directory");
  paths.set(plan.entrypointPath, "file");
  paths.set(dirname(plan.launchd.stdoutPath), "directory");
  paths.set(dirname(plan.plistPath), "directory");
  for (const protectedTarget of [
    plan.installRoot,
    dirname(plan.launchd.program),
    dirname(plan.entrypointPath),
    dirname(plan.signedArtifactPath),
    dirname(plan.launchd.stdoutPath)
  ]) {
    for (const ancestor of ancestorsThrough(plan.userHome, protectedTarget)) paths.set(ancestor, "directory");
  }
  for (const ancestor of ancestorsThrough(plan.userHome, dirname(plan.plistPath))) paths.set(ancestor, "directory");
  if (options.requirePlist || plan.operation !== "install") paths.set(plan.plistPath, "file");
  const entries: InstallFilesystemEntryReadback[] = [];
  for (const [path, expectedKind] of [...paths.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    const first = await readFilesystemEntry(path, expectedKind, options.ownerUid, path === plan.plistPath);
    const second = await readFilesystemEntry(path, expectedKind, options.ownerUid, path === plan.plistPath);
    if (first.device !== second.device || first.inode !== second.inode) {
      fail("FILESYSTEM_MISMATCH", "filesystem identity changed during install preflight");
    }
    entries.push(first);
  }
  return { ownerUid: options.ownerUid, entries };
}

/**
 * Applies only the plist portion of an install, upgrade, or rollback plan.
 * The native filesystem writer opens the authorized root and parent directory,
 * creates a same-directory O_EXCL temporary file, fsyncs it, commits with
 * renameat, and reopens the result for identity/content readback. No launchd
 * command is executed here.
 */
export async function applyMacOsPlistPlan(
  plan: MacOsServiceInstallPlanBase,
  options: MacOsPlistApplyOptions
): Promise<MacOsPlistApplyResult> {
  await inspectMacOsInstallFilesystem(plan, { ownerUid: options.ownerUid, requirePlist: plan.operation !== "install" });
  const inspector = options.inspector ?? createInstallInspector(plan);
  const targetPlan = inspector.planPath(plan.plistPath, "write");
  const current = optionalStat(inspector, targetPlan);
  if (plan.operation === "install") {
    const result = inspector.writePlanned(
      targetPlan,
      Buffer.from(plan.renderedPlist, "utf8"),
      undefined,
      true,
      temporaryName("plist"),
      identity(false)
    );
    return toApplyResult(plan.operation, result, null, null);
  }
  if (current === undefined) fail("FILESYSTEM_MISMATCH", "upgrade or rollback requires an existing plist");
  const currentIdentity = identityFromMetadata(current);
  if (plan.operation === "uninstall") {
    const currentContent = readExistingPlist(inspector, plan.plistPath).content;
    const backupPlan = inspector.planPath(plan.backupPath, "write");
    const backupCurrent = optionalStat(inspector, backupPlan);
    let result: { path: string; removed: boolean; device: string; inode: string };
    let backupRemoved = false;
    try {
      result = inspector.unlinkPlanned(targetPlan, currentIdentity);
      if (backupCurrent !== undefined) {
        inspector.unlinkPlanned(backupPlan, identityFromMetadata(backupCurrent));
        backupRemoved = true;
      }
    } catch (error) {
      if (optionalStat(inspector, targetPlan) === undefined) {
        try {
          inspector.writePlanned(targetPlan, currentContent, undefined, true, temporaryName("uninstall-restore"), identity(false));
        } catch (restoreError) {
          throw new AggregateError([error, restoreError], "macOS plist uninstall failed and restoration also failed");
        }
      }
      throw error;
    }
    if (optionalStat(inspector, targetPlan) !== undefined) {
      fail("FILESYSTEM_MISMATCH", "plist uninstall postcondition did not remove the target");
    }
    return {
      operation: "uninstall",
      path: result.path,
      bytesWritten: 0,
      sha256: null,
      created: false,
      backupPath: backupRemoved ? plan.backupPath : null,
      backupSha256: null,
      device: result.device,
      inode: result.inode
    };
  }
  if (plan.operation === "upgrade") {
    const original = readExistingPlist(inspector, plan.plistPath);
    const backupPlan = inspector.planPath(plan.backupPath, "write");
    const backupCurrent = optionalStat(inspector, backupPlan);
    const backupResult = inspector.writePlanned(
      backupPlan,
      original.content,
      undefined,
      false,
      temporaryName("backup"),
      backupCurrent === undefined ? identity(false) : identityFromMetadata(backupCurrent)
    );
    try {
      const result = inspector.writePlanned(
        targetPlan,
        Buffer.from(plan.renderedPlist, "utf8"),
        undefined,
        false,
        temporaryName("plist"),
        currentIdentity
      );
      return toApplyResult(plan.operation, result, plan.backupPath, backupResult.sha256);
    } catch (error) {
      try {
        inspector.writePlanned(
          targetPlan,
          original.content,
          undefined,
          false,
          temporaryName("restore"),
          currentIdentity
        );
      } catch (restoreError) {
        throw new AggregateError([error, restoreError], "macOS plist upgrade failed and restoration also failed");
      }
      throw error;
    }
  }
  const backup = readExistingPlist(inspector, plan.backupPath);
  const result = inspector.writePlanned(
    targetPlan,
    backup.content,
    undefined,
    false,
    temporaryName("rollback"),
    currentIdentity
  );
  return toApplyResult(plan.operation, result, plan.backupPath, null);
}

/**
 * Executes the bounded host-side portion of an installation plan.
 *
 * This is intentionally not called by MCP handlers. The caller must provide
 * an exact operation confirmation and an authoritative existing-service
 * readback. Commands use fixed argv, empty environments, and the same bounded
 * ProcessSupervisor contract as other Broker child processes. A successful
 * launchctl command is never treated as success without independent raw-source
 * readback; the executor composes the final readback itself. If readback fails
 * after bootstrap, the exact service is booted out and the plist is left for an
 * explicit rollback plan; no uncertain repair can overwrite a target that may
 * have changed under an external actor.
 */
export async function executeMacOsInstallPlan(
  plan: MacOsInstallPlan,
  options: MacOsInstallExecutionOptions
): Promise<MacOsInstallExecutionResult> {
  if (options === null || typeof options !== "object") {
    fail("INVALID_ARGUMENT", "install execution options are malformed");
  }
  if (options.confirmOperation !== plan.operation) {
    fail("CONFIRMATION_REQUIRED", "installation requires an explicit matching host operation confirmation");
  }
  const existingService = await readMacOsExistingServiceSnapshot(options.readExistingService);
  if (options.existingService !== undefined) {
    validateExistingServiceSnapshot(options.existingService);
    if (!sameExistingService(options.existingService, existingService)) {
      fail("SERVICE_MISMATCH", "caller existing-service hint does not match the host precondition readback");
    }
  }
  validateExistingServicePrecondition(plan, existingService);
  const executor = options.commandExecutor ?? new ProcessSupervisor({ allowedEnvironmentKeys: [] });
  if (plan.operation !== "uninstall") {
    await runInstallCommand(executor, plan.signatureVerify, "code signature verification failed");
  }
  let bootedOut = false;
  let plistApplied = false;
  let bootstrapped = false;
  let plist: MacOsPlistApplyResult;
  try {
    if (plan.operation !== "install") {
      await runInstallCommand(executor, plan.rollback.bootout, "existing launchd service could not be stopped");
      bootedOut = true;
    }
    plist = await applyMacOsPlistPlan(plan, options);
    plistApplied = true;
    if (plan.operation !== "uninstall") {
      await runInstallCommand(executor, plan.install.bootstrap, "launchd service could not be bootstrapped");
      bootstrapped = true;
    }
  } catch (error) {
    if (bootedOut && !plistApplied) {
      try {
        await runInstallCommand(executor, plan.install.bootstrap, "previous launchd service could not be restored");
      } catch (restoreError) {
        throw new AggregateError([error, restoreError], "installation failed and launchd recovery also failed");
      }
    }
    throw error;
  }
  let readback: MacOsInstallReadback | null;
  try {
    const sources = await options.readback();
    if (plan.operation === "uninstall") {
      if (sources !== null) fail("READBACK_FAILED", "uninstall readback still reports an installed service");
      readback = null;
    } else {
      if (sources === null) fail("READBACK_FAILED", "service readback is absent after bootstrap");
      readback = composeMacOsInstallReadback(plan, sources);
    }
  } catch (error) {
    if (bootstrapped) {
      try {
        await runInstallCommand(executor, plan.rollback.bootout, "mismatched launchd service could not be stopped");
      } catch (stopError) {
        throw new AggregateError([error, stopError], "installation readback failed and launchd recovery also failed");
      }
    }
    if (error instanceof MacOsInstallPlanError) throw error;
    fail("READBACK_FAILED", "service readback failed after installation");
  }
  return { operation: plan.operation, readback, plist };
}

/** Executes the bounded host-side Edge install flow using the same atomic plist
 * and launchd recovery boundary as Broker installation. Edge success requires
 * an independently observed running listener; launchctl success alone is not
 * sufficient. */
export async function executeMacOsEdgeInstallPlan(
  plan: MacOsEdgeInstallPlan,
  options: MacOsEdgeInstallExecutionOptions
): Promise<MacOsEdgeInstallExecutionResult> {
  if (options === null || typeof options !== "object") {
    fail("INVALID_ARGUMENT", "Edge install execution options are malformed");
  }
  if (options.confirmOperation !== plan.operation) fail("CONFIRMATION_REQUIRED", "installation requires an explicit matching host operation confirmation");
  const existingService = await readMacOsExistingServiceSnapshot(options.readExistingService);
  if (options.existingService !== undefined) {
    validateExistingServiceSnapshot(options.existingService);
    if (!sameExistingService(options.existingService, existingService)) {
      fail("SERVICE_MISMATCH", "caller existing-service hint does not match the host precondition readback");
    }
  }
  validateExistingServicePrecondition(plan, existingService);
  const executor = options.commandExecutor ?? new ProcessSupervisor({ allowedEnvironmentKeys: [] });
  if (plan.operation !== "uninstall") await runInstallCommand(executor, plan.signatureVerify, "code signature verification failed");
  let bootedOut = false;
  let plistApplied = false;
  let bootstrapped = false;
  let plist: MacOsPlistApplyResult;
  try {
    if (plan.operation !== "install") {
      await runInstallCommand(executor, plan.rollback.bootout, "existing launchd service could not be stopped");
      bootedOut = true;
    }
    plist = await applyMacOsPlistPlan(plan, options);
    plistApplied = true;
    if (plan.operation !== "uninstall") {
      await runInstallCommand(executor, plan.install.bootstrap, "launchd service could not be bootstrapped");
      bootstrapped = true;
    }
  } catch (error) {
    if (bootedOut && !plistApplied) {
      try {
        await runInstallCommand(executor, plan.install.bootstrap, "previous launchd service could not be restored");
      } catch (restoreError) {
        throw new AggregateError([error, restoreError], "installation failed and launchd recovery also failed");
      }
    }
    throw error;
  }
  let readback: MacOsEdgeInstallReadback | null;
  try {
    const sources = await options.readback();
    if (plan.operation === "uninstall") {
      if (sources !== null) fail("READBACK_FAILED", "uninstall readback still reports an installed Edge service");
      readback = null;
    } else {
      if (sources === null) fail("READBACK_FAILED", "Edge service readback is absent after bootstrap");
      readback = composeMacOsEdgeInstallReadback(plan, sources);
    }
  } catch (error) {
    if (bootstrapped) {
      try {
        await runInstallCommand(executor, plan.rollback.bootout, "mismatched Edge launchd service could not be stopped");
      } catch (stopError) {
        throw new AggregateError([error, stopError], "Edge installation readback failed and launchd recovery also failed");
      }
    }
    if (error instanceof MacOsInstallPlanError) throw error;
    fail("READBACK_FAILED", "Edge service readback failed after installation");
  }
  return { operation: plan.operation, readback, plist };
}

async function runInstallCommand(
  executor: MacOsInstallCommandExecutor,
  command: LaunchdCommandSpec | CodeSignatureCommandSpec,
  failureMessage: string
): Promise<void> {
  let result: ProcessExecutionResult;
  try {
    result = await executor.run(command);
  } catch {
    fail("COMMAND_FAILED", failureMessage);
  }
  if (result.resultClass !== "SUCCEEDED") fail("COMMAND_FAILED", failureMessage);
}

function launchctlCommand(args: readonly string[]): LaunchdCommandSpec {
  return {
    executable: LAUNCHCTL_PATH,
    args: [...args],
    cwd: "/",
    environment: {},
    timeoutMs: SERVICE_TIMEOUT_MS,
    outputCapBytes: SERVICE_OUTPUT_CAP_BYTES
  };
}

async function readFilesystemEntry(
  path: string,
  expectedKind: ExpectedFilesystemKind,
  ownerUid: number,
  requireOwnerOnlyFile: boolean
): Promise<InstallFilesystemEntryReadback> {
  let stats;
  try {
    stats = await lstat(path);
  } catch {
    fail("FILESYSTEM_MISMATCH", "required installation path is unavailable");
  }
  if (stats.isSymbolicLink() || stats.uid !== ownerUid || (stats.mode & 0o022) !== 0 ||
      (expectedKind === "file" && !stats.isFile()) ||
      (expectedKind === "directory" && !stats.isDirectory()) ||
      (expectedKind === "file-or-directory" && !stats.isFile() && !stats.isDirectory()) ||
      (requireOwnerOnlyFile && (stats.mode & 0o777) !== 0o600)) {
    fail("FILESYSTEM_MISMATCH", "installation path ownership, mode, symlink, or type is unsafe");
  }
  return {
    path,
    kind: stats.isFile() ? "file" : "directory",
    ownerUid: stats.uid,
    mode: stats.mode & 0o777,
    device: stats.dev,
    inode: stats.ino
  };
}

function ancestorsThrough(root: string, target: string): readonly string[] {
  const result: string[] = [];
  let current = target;
  while (true) {
    if (!isWithin(root, current, true)) fail("FILESYSTEM_MISMATCH", "plist parent escapes the user home");
    result.push(current);
    if (current === root) break;
    const parent = dirname(current);
    if (parent === current) fail("FILESYSTEM_MISMATCH", "plist parent cannot reach the user home");
    current = parent;
  }
  return result;
}

function parseUid(domain: string): number {
  const value = Number(domain.slice("gui/".length));
  return Number.isSafeInteger(value) ? value : -1;
}

function createInstallInspector(plan: MacOsServiceInstallPlanBase): FilesystemInspector {
  return new FilesystemInspector([{
    rootId: "macos-install-user-home",
    path: plan.userHome,
    metadata: true,
    contentRead: true,
    write: true,
    denyRelativePaths: []
  }]);
}

function optionalStat(inspector: FilesystemInspector, plan: FilesystemPathPlan) {
  try {
    return inspector.statPlanned(plan, false);
  } catch {
    return undefined;
  }
}

function readExistingPlist(inspector: FilesystemInspector, path: string): { content: Buffer; device: string; inode: string } {
  const plan = inspector.planPath(path, "content_read");
  const read = inspector.readPlanned(plan, 0, 1_048_576);
  if (read.truncated) fail("FILESYSTEM_MISMATCH", "plist content exceeds the bounded rollback budget");
  return { content: read.content, device: read.device, inode: read.inode };
}

function identity(present: boolean, device = "0", inode = "0"): FilesystemIdentityPrecondition {
  return { present, device, inode };
}

function identityFromMetadata(metadata: { device: string; inode: string }): FilesystemIdentityPrecondition {
  return identity(true, metadata.device, metadata.inode);
}

function temporaryName(kind: string): string {
  return `.mac-operator-write-${kind}-${randomBytes(12).toString("hex")}`;
}

function toApplyResult(
  operation: "install" | "upgrade" | "rollback",
  result: { path: string; bytesWritten: number; sha256: string; created: boolean; device: string; inode: string },
  backupPath: string | null,
  backupSha256: string | null
): MacOsPlistApplyResult {
  return {
    operation,
    path: result.path,
    bytesWritten: result.bytesWritten,
    sha256: result.sha256,
    created: result.created,
    backupPath,
    backupSha256,
    device: result.device,
    inode: result.inode
  };
}

function codesignVerifyCommand(path: string): CodeSignatureCommandSpec {
  return {
    executable: "/usr/bin/codesign",
    args: ["--verify", "--strict", "--deep", path],
    cwd: "/",
    environment: {},
    timeoutMs: SERVICE_TIMEOUT_MS,
    outputCapBytes: SERVICE_OUTPUT_CAP_BYTES
  };
}

function canonicalPath(value: unknown, label: string): string {
  if (typeof value !== "string" || !isAbsolute(value) || value.includes("\0") || resolve(value) !== value) {
    fail("INVALID_ARGUMENT", `${label} must be a canonical absolute path`);
  }
  return value;
}

function isDescendant(root: string, target: string): boolean {
  return isWithin(root, target, false);
}

function isWithin(root: string, target: string, allowEqual: boolean): boolean {
  if (!isAbsolute(target) || target.includes("\0") || resolve(target) !== target) return false;
  const relativePath = relative(root, target);
  return (allowEqual || relativePath.length > 0) && relativePath !== ".." && !relativePath.startsWith("../") && !relativePath.startsWith("/");
}

function normalizeSignaturePolicy(value: MacOsSignaturePolicy | undefined): MacOsSignaturePolicy {
  if (value !== undefined && value !== "developer-id" && value !== "development-ad-hoc") {
    fail("INVALID_SIGNATURE_EXPECTATION", "code signature policy is invalid");
  }
  return value ?? "developer-id";
}

function normalizeSignatureExpectation(
  value: CodeSignatureExpectation,
  policy: MacOsSignaturePolicy,
  expectedIdentifier: string
): CodeSignatureExpectation {
  if (value === null || typeof value !== "object" || typeof value.identifier !== "string" ||
      !/^[A-Za-z0-9.-]{1,128}$/u.test(value.identifier)) {
    fail("INVALID_SIGNATURE_EXPECTATION", "code signature identifier is invalid");
  }
  if (value.identifier !== expectedIdentifier) {
    fail("INVALID_SIGNATURE_EXPECTATION", `code signature identifier must be ${expectedIdentifier}`);
  }
  if (value.teamIdentifier !== undefined && !/^[A-Z0-9]{10}$/u.test(value.teamIdentifier)) {
    fail("INVALID_SIGNATURE_EXPECTATION", "code signature team identifier is invalid");
  }
  if (value.cdHash !== undefined && !/^[A-Fa-f0-9]{20,64}$/u.test(value.cdHash)) {
    fail("INVALID_SIGNATURE_EXPECTATION", "code signature cdhash is invalid");
  }
  if (policy === "developer-id" && (value.teamIdentifier === undefined || value.cdHash === undefined)) {
    fail("INVALID_SIGNATURE_EXPECTATION", "production install requires a Developer ID team identifier and CDHash");
  }
  return { identifier: value.identifier, ...(value.teamIdentifier === undefined ? {} : { teamIdentifier: value.teamIdentifier }), ...(value.cdHash === undefined ? {} : { cdHash: value.cdHash }) };
}

function normalizeServiceMetadata(value: MacOsServiceMetadata, component: MacOsServiceMetadata["component"]): MacOsServiceMetadata {
  if (value === null || typeof value !== "object" || value.component !== component ||
      !/^[0-9a-f]{7,64}$/u.test(value.sourceRevision) ||
      !/^v?\d+\.\d+(?:\.\d+)?(?:[-+].*)?$/u.test(value.contractVersion) ||
      !/^(?:policy-[1-9][0-9]*|\d+\.\d+(?:\.\d+)?(?:[-+].*)?)$/u.test(value.policyVersion)) {
    fail("INVALID_METADATA", `${component === "mac-operator-broker" ? "Broker" : "Edge"} service metadata is invalid`);
  }
  return { ...value };
}

function normalizeEdgeListener(input: MacOsServiceInstallPlanInput): { bindHost: string; bindPort: number } {
  const candidate = input as MacOsEdgeInstallPlanInput;
  if (typeof candidate.bindHost !== "string" || candidate.bindHost.length < 1 || candidate.bindHost.length > 255 ||
      candidate.bindHost.includes("\0") || /[\r\n/\\]/u.test(candidate.bindHost) ||
      !Number.isSafeInteger(candidate.bindPort) || candidate.bindPort < 1 || candidate.bindPort > 65_535) {
    fail("INVALID_METADATA", "Edge listener binding is invalid");
  }
  return { bindHost: candidate.bindHost, bindPort: candidate.bindPort };
}

function normalizeCapabilities(value: readonly string[]): readonly string[] {
  if (!Array.isArray(value) || value.length > MAX_CAPABILITIES || value.some((item) => typeof item !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(item))) {
    fail("INVALID_METADATA", "enabled capabilities are invalid");
  }
  const unique = [...new Set(value)].sort();
  return unique;
}

function normalizePreviousRevision(value: string | undefined, operation: MacOsInstallOperation): string | undefined {
  if (operation === "install") {
    if (value !== undefined) fail("INVALID_METADATA", "install must not provide a previous source revision");
    return undefined;
  }
  if (typeof value !== "string" || !/^[0-9a-f]{7,64}$/u.test(value)) {
    fail("INVALID_METADATA", "upgrade, rollback, and uninstall require an exact previous source revision");
  }
  return value;
}

function renderedPlistSha256(plan: MacOsServiceInstallPlanBase): string {
  return createHash("sha256").update(plan.renderedPlist, "utf8").digest("hex");
}

function expectedPlistReadbackPath(plan: MacOsServiceInstallPlanBase): string {
  try {
    return realpathSync(plan.plistPath);
  } catch {
    return plan.plistPath;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return isPlainDataRecord(value);
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function sameLaunchdIdentity(left: LaunchdJobReadback, right: LaunchdJobReadback): boolean {
  return left.serviceId === right.serviceId && left.domain === right.domain && left.label === right.label &&
    left.state === right.state && left.pid === right.pid && left.program === right.program &&
    sameNullableStrings(left.arguments, right.arguments) && left.plistPath === right.plistPath &&
    left.type === right.type && left.lastExitCode === right.lastExitCode && left.truncated === right.truncated;
}

async function readStableProcessIdentity(pid: number): Promise<PeerProcessIdentity> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      return capturePeerProcessIdentity(pid);
    } catch (error) {
      lastError = error;
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 50));
    }
  }
  throw lastError instanceof Error ? lastError : new Error("Process identity could not be read");
}

function sameNullableStrings(left: readonly string[] | null, right: readonly string[] | null): boolean {
  if (left === null || right === null) return left === right;
  return sameStrings(left, right);
}

function sameProcessIdentity(left: PeerProcessIdentity, right: PeerProcessIdentity): boolean {
  return left.pid === right.pid && left.startTimeMicros === right.startTimeMicros;
}

function samePlistIdentity(left: MacOsPlistReadback, right: MacOsPlistReadback): boolean {
  return left.path === right.path && left.bytes === right.bytes && left.sha256 === right.sha256 &&
    left.device === right.device && left.inode === right.inode;
}

function readCodeSignatureField(output: string, fieldName: string, pattern: RegExp): string | null {
  const matches = [...output.matchAll(new RegExp(`^${fieldName}=([^\\r\\n]+)$`, "gmu"))];
  if (matches.length === 0) return null;
  if (matches.length !== 1) fail("SIGNATURE_MISMATCH", `code signature returned duplicate ${fieldName}`);
  const value = matches[0]?.[1]?.trim();
  if (value === "not set" && fieldName === "TeamIdentifier") return null;
  if (value === undefined || !pattern.test(value)) fail("SIGNATURE_MISMATCH", `code signature returned malformed ${fieldName}`);
  return value;
}

function fail(code: MacOsInstallPlanErrorCode, message: string): never {
  throw new MacOsInstallPlanError(code, message);
}
