import { lstat } from "node:fs/promises";
import { createHash, randomBytes } from "node:crypto";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import type { CodeSignatureCommandSpec, CodeSignatureExpectation, CodeSignatureReadback, LaunchdCommandSpec, MacOsPlistReadback } from "./macos-install-plan.js";
import { validateCodeSignatureReadback } from "./macos-install-plan.js";
import { FilesystemInspector, type FilesystemIdentityPrecondition, type FilesystemPathPlan } from "./filesystem-inspector.js";
import { readLaunchdJobReadback, type LaunchdJobReadback, type LaunchdReadbackExecutor } from "./launchd-readback.js";
import { capturePeerProcessIdentity, type PeerProcessIdentity } from "./peer-credentials.js";
import { ProcessSupervisor, type ProcessExecutionRequest, type ProcessExecutionResult } from "./process-supervisor.js";
import { readPrivilegedHelperStatus, type PrivilegedHelperAdapter, type PrivilegedHelperStatusClientOptions } from "./privileged-helper.js";
import { isPlainDataRecord } from "./plain-record.js";

const HELPER_LABEL = "com.mac-operator.privileged-helper" as const;
const HELPER_PLIST_PATH = "/Library/LaunchDaemons/com.mac-operator.privileged-helper.plist" as const;
const LAUNCHCTL_PATH = "/bin/launchctl" as const;
const CODESIGN_PATH = "/usr/bin/codesign" as const;
const COMMAND_TIMEOUT_MS = 5_000 as const;
const COMMAND_OUTPUT_CAP_BYTES = 131_072 as const;
const MAX_ARGUMENT_BYTES = 4_096;
const MAX_ARGUMENT_TOTAL_BYTES = 64 * 1_024;
const MAX_PLIST_BYTES = 512 * 1_024;
const REVISION_PATTERN = /^[a-f0-9]{40}$/u;
const VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,120}$/u;
const CAPABILITY_PATTERN = /^mac_priv_[a-z][a-z0-9_]{0,63}$/u;
const CAPABILITY_EVIDENCE_PATTERN = /^[A-Za-z0-9._:/-]{1,256}$/u;
const IMPLEMENTED_HELPER_CAPABILITIES = new Set(["mac_priv_service_control"]);
const INTERPRETER_NAMES = new Set([
  "bash",
  "csh",
  "env",
  "node",
  "osascript",
  "perl",
  "python",
  "python3",
  "ruby",
  "sh",
  "zsh"
]);
type PrivilegedHelperExpectedFilesystemKind = "file" | "directory" | "file-or-directory";

export type PrivilegedHelperPackageOperation = "install" | "upgrade" | "rollback" | "uninstall";

export type PrivilegedHelperPackageErrorCode =
  | "INVALID_ARGUMENT"
  | "INVALID_ROOT_DOMAIN"
  | "INVALID_PACKAGE_PATH"
  | "INVALID_SOCKET_BOUNDARY"
  | "INVALID_PEER_IDENTITY"
  | "INVALID_REVISION"
  | "INVALID_SIGNATURE"
  | "INVALID_CAPABILITY_RELEASE"
  | "SERVICE_MISMATCH"
  | "SIGNATURE_MISMATCH"
  | "INVALID_READBACK"
  | "CONFIRMATION_REQUIRED"
  | "FILESYSTEM_MISMATCH"
  | "RECOVERY_FAILED"
  | "COMMAND_FAILED"
  | "READBACK_FAILED";

export class PrivilegedHelperPackageError extends Error {
  readonly code: PrivilegedHelperPackageErrorCode;

  constructor(code: PrivilegedHelperPackageErrorCode, message: string) {
    super(message);
    this.name = "PrivilegedHelperPackageError";
    this.code = code;
  }
}

export interface PrivilegedHelperLaunchdConfig {
  label: typeof HELPER_LABEL;
  program: string;
  programArguments: readonly string[];
  workingDirectory: string;
  stdoutPath: string;
  stderrPath: string;
  runAtLoad?: boolean;
  keepAlive?: boolean;
  throttleIntervalSeconds?: number;
}

export interface PrivilegedHelperBrokerPeerExpectation {
  uid: number;
  gid?: number;
}

export interface PrivilegedHelperPackagePlanInput {
  operation?: PrivilegedHelperPackageOperation;
  helperRoot: string;
  plistPath?: string;
  service: PrivilegedHelperLaunchdConfig;
  signedArtifactPath: string;
  signature: CodeSignatureExpectation;
  helperKeyConfigPath: string;
  helperSocketPath: string;
  brokerSocketPath: string;
  /** Broker-owned authority socket used by the root helper for live polling. */
  helperAuthoritySocketPath: string;
  brokerPeer: PrivilegedHelperBrokerPeerExpectation;
  sourceRevision: string;
  contractVersion: string;
  policyVersion: string;
  expectedPreviousSourceRevision?: string;
  /** Host-owned release evidence for implemented helper capabilities. */
  capabilityRelease?: PrivilegedHelperCapabilityRelease;
}

/**
 * Explicit host release metadata for the root helper capability projection.
 * This is not supplied by MCP callers and is never inferred from tool
 * arguments. The package readback must still match the projection exactly.
 */
export interface PrivilegedHelperCapabilityRelease {
  source: "host-verified";
  adapterAvailable: boolean;
  enabledCapabilities: readonly string[];
  evidenceRef: string;
}

/**
 * Derive a package release from the host-owned helper adapter projection.
 * Callers cannot use this to add capabilities: normalization rejects any
 * operation that has no implemented adapter contract.
 */
export function createPrivilegedHelperCapabilityRelease(
  adapter: Pick<PrivilegedHelperAdapter, "available" | "enabledCapabilities">,
  evidenceRef: string
): PrivilegedHelperCapabilityRelease {
  if (adapter === null || typeof adapter !== "object") {
    fail("INVALID_CAPABILITY_RELEASE", "privileged helper adapter projection is unavailable");
  }
  return normalizeCapabilityRelease({
    source: "host-verified",
    adapterAvailable: adapter.available,
    enabledCapabilities: adapter.enabledCapabilities,
    evidenceRef
  })!;
}

export interface PrivilegedHelperLaunchdReadback {
  label: typeof HELPER_LABEL;
  program: string;
  programArguments: readonly string[];
  workingDirectory: string;
  stdoutPath: string;
  stderrPath: string;
  domain: "system";
  type: "LaunchDaemon";
  runsAsRoot: true;
  usesEnvironmentVariables: false;
  usesShell: false;
  runAtLoad: boolean;
  keepAlive: boolean;
  throttleIntervalSeconds: number;
}

export interface PrivilegedHelperRuntimeReadback {
  component: "mac-operator-privileged-helper";
  state: "running";
  runtimeState: "running";
  nativeTransportRequired: true;
  adapterAvailable: boolean;
  helperSocketPath: string;
  brokerSocketPath: string;
  helperAuthoritySocketPath: string;
  brokerPeerUid: number;
  brokerPeerGid: number | null;
  sourceRevision: string;
  contractVersion: string;
  policyVersion: string;
  enabledCapabilities: readonly string[];
}

export interface PrivilegedHelperPackageReadback {
  domain: "system";
  label: typeof HELPER_LABEL;
  plistPath: typeof HELPER_PLIST_PATH;
  pid: number;
  processIdentity: PeerProcessIdentity;
  plist: MacOsPlistReadback;
  launchd: PrivilegedHelperLaunchdReadback;
  authoritySocket: PrivilegedHelperAuthoritySocketReadback;
  helper: PrivilegedHelperRuntimeReadback;
  signature: CodeSignatureReadback;
}

export interface PrivilegedHelperAuthoritySocketReadback {
  path: string;
  ownerUid: number;
  ownerGid: number;
  mode: number;
  device: number;
  inode: number;
}

export interface PrivilegedHelperPackageReadbackSources {
  launchd: LaunchdJobReadback;
  processIdentity: PeerProcessIdentity;
  plist: MacOsPlistReadback;
  helper: PrivilegedHelperRuntimeReadback;
  authoritySocket: PrivilegedHelperAuthoritySocketReadback;
  signature: CodeSignatureReadback;
}

export interface PrivilegedHelperPackageReadbackObserver {
  readLaunchd(serviceId: string): Promise<LaunchdJobReadback>;
  readProcessIdentity(pid: number): Promise<PeerProcessIdentity> | PeerProcessIdentity;
  readPlist(plan: PrivilegedHelperPackagePlan): Promise<MacOsPlistReadback>;
  readRuntime(): Promise<PrivilegedHelperRuntimeReadback>;
  readAuthoritySocket(plan: PrivilegedHelperPackagePlan): Promise<PrivilegedHelperAuthoritySocketReadback>;
  readSignature(): Promise<CodeSignatureReadback>;
}

export interface PrivilegedHelperPackageHostObserverOptions {
  /** Test-only or host-adapter injection; production callers should use helperStatusClient. */
  readRuntime?: () => Promise<PrivilegedHelperRuntimeReadback>;
  /** Authenticated helper-owned runtime source for production readback. */
  helperStatusClient?: PrivilegedHelperStatusClientOptions;
  launchdExecutor?: LaunchdReadbackExecutor;
  processIdentityReader?: (pid: number) => PeerProcessIdentity;
  readPlist?: (plan: PrivilegedHelperPackagePlan) => Promise<MacOsPlistReadback>;
  readAuthoritySocket?: (plan: PrivilegedHelperPackagePlan) => Promise<PrivilegedHelperAuthoritySocketReadback>;
  readSignature?: (plan: PrivilegedHelperPackagePlan) => Promise<CodeSignatureReadback>;
}

export interface PrivilegedHelperPackagePlan {
  operation: PrivilegedHelperPackageOperation;
  domain: "system";
  label: typeof HELPER_LABEL;
  helperRoot: string;
  plistPath: typeof HELPER_PLIST_PATH;
  signedArtifactPath: string;
  signature: CodeSignatureExpectation;
  helperKeyConfigPath: string;
  helperSocketPath: string;
  brokerSocketPath: string;
  helperAuthoritySocketPath: string;
  brokerPeer: PrivilegedHelperBrokerPeerExpectation;
  sourceRevision: string;
  contractVersion: string;
  policyVersion: string;
  expectedPreviousSourceRevision?: string;
  capabilityRelease?: PrivilegedHelperCapabilityRelease;
  launchd: PrivilegedHelperLaunchdReadback;
  renderedPlist: string;
  signatureVerify: CodeSignatureCommandSpec;
  preflight: readonly string[];
  install: {
    file: PrivilegedHelperFileAction;
    bootstrap: LaunchdCommandSpec;
  };
  rollback: {
    bootout: LaunchdCommandSpec;
    file: PrivilegedHelperFileAction;
    bootstrap: LaunchdCommandSpec;
  };
  uninstall: {
    bootout: LaunchdCommandSpec;
    file: PrivilegedHelperFileAction;
  };
  enabledCapabilities: readonly string[];
  adapterAvailable: boolean;
}

export interface PrivilegedHelperFilesystemEntryReadback {
  path: string;
  kind: "file" | "directory";
  ownerUid: number;
  mode: number;
  device: number;
  inode: number;
}

export interface PrivilegedHelperFilesystemReadback {
  ownerUid: 0;
  entries: readonly PrivilegedHelperFilesystemEntryReadback[];
}

export interface PrivilegedHelperPlistApplyOptions {
  /** Host-only confirmation; this function is not exposed through MCP. */
  confirmOperation: PrivilegedHelperPackageOperation;
  /** Root ownership is mandatory; non-root callers fail before filesystem access. */
  ownerUid: number;
}

export interface PrivilegedHelperPlistApplyResult {
  operation: PrivilegedHelperPackageOperation;
  path: typeof HELPER_PLIST_PATH;
  bytesWritten: number;
  sha256: string | null;
  created: boolean;
  backupPath: string | null;
  backupSha256: string | null;
  device: string;
  inode: string;
}

export interface PrivilegedHelperFileAction {
  kind: "write-plist" | "restore-plist" | "remove-plist";
  path: typeof HELPER_PLIST_PATH;
  ownerUid: 0;
  mode: 0o600;
  backupPath?: string;
  content?: string;
}

export interface PrivilegedHelperExistingServiceReadback {
  present: boolean;
  sourceRevision: string | null;
}

export type PrivilegedHelperPackageExecutionStep =
  | { kind: "verify-signature"; command: CodeSignatureCommandSpec }
  | { kind: "bootout"; command: LaunchdCommandSpec }
  | { kind: "apply-plist"; action: PrivilegedHelperFileAction }
  | { kind: "bootstrap"; command: LaunchdCommandSpec }
  | { kind: "readback"; operation: PrivilegedHelperPackageOperation };

export interface PrivilegedHelperPackageExecutionPlan {
  operation: PrivilegedHelperPackageOperation;
  existingService: PrivilegedHelperExistingServiceReadback;
  steps: readonly PrivilegedHelperPackageExecutionStep[];
  recoverySteps: readonly PrivilegedHelperPackageExecutionStep[];
}

export interface PrivilegedHelperPackageCommandExecutor {
  run(command: LaunchdCommandSpec | CodeSignatureCommandSpec): Promise<ProcessExecutionResult>;
}

export interface PrivilegedHelperPackageExecutionOptions {
  /** Host-only confirmation; this function is not exposed through MCP. */
  confirmOperation: PrivilegedHelperPackageOperation;
  /** Must be the root UID and is checked against the actual current process. */
  ownerUid: number;
  existingService: PrivilegedHelperExistingServiceReadback;
  /** Returns only independently observed sources; execution composes and validates them. */
  readback: () => Promise<PrivilegedHelperPackageReadbackSources | null>;
  /** Injectable only for host tests; production defaults to ProcessSupervisor. */
  commandExecutor?: PrivilegedHelperPackageCommandExecutor;
}

export interface PrivilegedHelperPackageExecutionResult {
  operation: PrivilegedHelperPackageOperation;
  readback: PrivilegedHelperPackageReadback | null;
  plist: PrivilegedHelperPlistApplyResult;
}

/**
 * Builds a reviewable root LaunchDaemon plan without executing launchctl,
 * writing files, or enabling a helper adapter. The helper is native-only and
 * can receive requests only from the Broker identity encoded in the plan.
 */
export function buildPrivilegedHelperPackagePlan(input: PrivilegedHelperPackagePlanInput): PrivilegedHelperPackagePlan {
  if (input === null || typeof input !== "object") fail("INVALID_ARGUMENT", "privileged helper package input is malformed");
  const operation = input.operation ?? "install";
  if (!["install", "upgrade", "rollback", "uninstall"].includes(operation)) {
    fail("INVALID_ARGUMENT", "privileged helper package operation is invalid");
  }
  const helperRoot = canonicalPath(input.helperRoot, "helper root");
  if (helperRoot === "/" || helperRoot === "/Users" || helperRoot.startsWith("/Users/")) {
    fail("INVALID_PACKAGE_PATH", "privileged helper root must not be user-writable");
  }
  const plistPath = input.plistPath ?? HELPER_PLIST_PATH;
  if (plistPath !== HELPER_PLIST_PATH) fail("INVALID_ROOT_DOMAIN", "privileged helper must use the exact system LaunchDaemon plist path");
  const service = normalizeService(input.service, helperRoot);
  const signedArtifactPath = canonicalPath(input.signedArtifactPath, "signed helper artifact");
  const helperKeyConfigPath = canonicalPath(input.helperKeyConfigPath, "helper key config");
  const helperSocketPath = canonicalPath(input.helperSocketPath, "helper socket");
  const brokerSocketPath = canonicalPath(input.brokerSocketPath, "Broker socket");
  const helperAuthoritySocketPath = canonicalPath(input.helperAuthoritySocketPath, "helper authority socket");
  for (const [path, label] of [
    [signedArtifactPath, "signed helper artifact"],
    [helperKeyConfigPath, "helper key config"],
    [helperSocketPath, "helper socket"],
    [service.workingDirectory, "helper working directory"],
    [service.stdoutPath, "helper stdout path"],
    [service.stderrPath, "helper stderr path"]
  ] as const) {
    if (!isDescendant(helperRoot, path, label === "helper working directory")) {
      fail("INVALID_PACKAGE_PATH", `${label} must remain inside the helper root`);
    }
  }
  if (helperSocketPath === brokerSocketPath || helperSocketPath === helperAuthoritySocketPath || brokerSocketPath === helperAuthoritySocketPath) {
    fail("INVALID_SOCKET_BOUNDARY", "helper, Broker, and authority sockets must be distinct");
  }
  if (isDescendant(helperRoot, helperAuthoritySocketPath, false)) {
    fail("INVALID_SOCKET_BOUNDARY", "helper authority socket must remain outside the root-owned helper package");
  }
  validatePeerExpectation(input.brokerPeer);
  validateRevision(input.sourceRevision, "source revision");
  validateVersion(input.contractVersion, "contract version");
  validateVersion(input.policyVersion, "policy version");
  const expectedPreviousSourceRevision = normalizePreviousRevision(input.expectedPreviousSourceRevision, operation);
  const capabilityRelease = normalizeCapabilityRelease(input.capabilityRelease);
  const signature = normalizeSignature(input.signature);
  if (signature.identifier !== HELPER_LABEL) fail("INVALID_SIGNATURE", "helper signature identifier is invalid");
  const renderedPlist = renderPrivilegedHelperLaunchdPlist(service);
  const backupPath = `${plistPath}.previous`;
  const launchd = {
    label: HELPER_LABEL,
    program: service.program,
    programArguments: [...service.programArguments],
    workingDirectory: service.workingDirectory,
    stdoutPath: service.stdoutPath,
    stderrPath: service.stderrPath,
    domain: "system",
    type: "LaunchDaemon" as const,
    runsAsRoot: true,
    usesEnvironmentVariables: false,
    usesShell: false,
    runAtLoad: service.runAtLoad,
    keepAlive: service.keepAlive,
    throttleIntervalSeconds: service.throttleIntervalSeconds
  } satisfies PrivilegedHelperLaunchdReadback;
  const file: PrivilegedHelperFileAction = { kind: "write-plist", path: HELPER_PLIST_PATH, ownerUid: 0, mode: 0o600, content: renderedPlist };
  const restore: PrivilegedHelperFileAction = { kind: "restore-plist", path: HELPER_PLIST_PATH, ownerUid: 0, mode: 0o600, backupPath };
  const remove: PrivilegedHelperFileAction = { kind: "remove-plist", path: HELPER_PLIST_PATH, ownerUid: 0, mode: 0o600 };
  const plan: PrivilegedHelperPackagePlan = {
    operation,
    domain: "system",
    label: HELPER_LABEL,
    helperRoot,
    plistPath: HELPER_PLIST_PATH,
    signedArtifactPath,
    signature,
    helperKeyConfigPath,
    helperSocketPath,
    brokerSocketPath,
    helperAuthoritySocketPath,
    brokerPeer: { uid: input.brokerPeer.uid, ...(input.brokerPeer.gid === undefined ? {} : { gid: input.brokerPeer.gid }) },
    sourceRevision: input.sourceRevision,
    contractVersion: input.contractVersion,
    policyVersion: input.policyVersion,
    ...(expectedPreviousSourceRevision === undefined ? {} : { expectedPreviousSourceRevision }),
    ...(capabilityRelease === undefined ? {} : { capabilityRelease }),
    launchd,
    renderedPlist,
    signatureVerify: {
      executable: CODESIGN_PATH,
      args: ["--verify", "--strict", "--deep", signedArtifactPath],
      cwd: "/",
      environment: {},
      timeoutMs: COMMAND_TIMEOUT_MS,
      outputCapBytes: COMMAND_OUTPUT_CAP_BYTES
    },
    preflight: [
      "verify the helper artifact is Developer ID signed with the exact helper identifier before any root-domain write",
      "verify helper root, key config, socket parent, executable, and logs are root-owned regular paths with no symlinks or group/other writes",
      "verify the Broker peer UID/GID and native PID/start-time identity are captured by helper startup before accepting a request",
      "verify the Broker-owned authority socket is distinct from the root helper socket and is authenticated before enabled dispatch",
      operation === "install" ? "verify the exact system LaunchDaemon is absent before installation" :
        operation === "uninstall" ? "verify the exact system LaunchDaemon identity before uninstall" :
          `verify the existing helper source revision matches ${expectedPreviousSourceRevision}`,
      "never expose this helper as an MCP tool or enable a privileged adapter without a separate capability release"
    ],
    install: {
      file,
      bootstrap: launchctlCommand(["bootstrap", "system", HELPER_PLIST_PATH])
    },
    rollback: {
      bootout: launchctlCommand(["bootout", `system/${HELPER_LABEL}`]),
      file: restore,
      bootstrap: launchctlCommand(["bootstrap", "system", HELPER_PLIST_PATH])
    },
    uninstall: {
      bootout: launchctlCommand(["bootout", `system/${HELPER_LABEL}`]),
      file: remove
    },
    enabledCapabilities: capabilityRelease?.enabledCapabilities ?? [],
    adapterAvailable: capabilityRelease?.adapterAvailable ?? false
  };
  return plan;
}

/**
 * Builds the host-only lifecycle sequence for a privileged-helper package.
 * This is a dry-run contract: it validates the exact existing revision and
 * returns fixed command/file steps, but it never invokes launchctl or mutates
 * the filesystem. A future root-owned executor must consume this sequence and
 * perform the listed readback/recovery steps without accepting new arguments.
 */
export function buildPrivilegedHelperPackageExecutionPlan(
  plan: PrivilegedHelperPackagePlan,
  existingService: PrivilegedHelperExistingServiceReadback
): PrivilegedHelperPackageExecutionPlan {
  validatePrivilegedHelperExistingService(plan, existingService);
  const steps: PrivilegedHelperPackageExecutionStep[] = [];
  if (plan.operation !== "uninstall") steps.push({ kind: "verify-signature", command: plan.signatureVerify });
  if (plan.operation !== "install") steps.push({ kind: "bootout", command: plan.rollback.bootout });
  const action = plan.operation === "install" ? plan.install.file : plan.operation === "uninstall" ? plan.uninstall.file : plan.rollback.file;
  steps.push({ kind: "apply-plist", action });
  if (plan.operation !== "uninstall") steps.push({ kind: "bootstrap", command: plan.install.bootstrap });
  steps.push({ kind: "readback", operation: plan.operation });

  const recoverySteps: PrivilegedHelperPackageExecutionStep[] = [];
  if (plan.operation === "install") {
    recoverySteps.push({ kind: "bootout", command: plan.rollback.bootout });
    recoverySteps.push({ kind: "apply-plist", action: plan.uninstall.file });
    recoverySteps.push({ kind: "readback", operation: "uninstall" });
  } else if (plan.operation === "upgrade" || plan.operation === "rollback") {
    recoverySteps.push({ kind: "bootout", command: plan.rollback.bootout });
    recoverySteps.push({ kind: "apply-plist", action: plan.rollback.file });
    recoverySteps.push({ kind: "bootstrap", command: plan.rollback.bootstrap });
    recoverySteps.push({ kind: "readback", operation: "rollback" });
  } else {
    recoverySteps.push({ kind: "readback", operation: "uninstall" });
  }
  return { operation: plan.operation, existingService, steps, recoverySteps };
}

/**
 * Executes the host-only helper package lifecycle after an explicit root
 * confirmation. This wrapper is not an MCP tool: it accepts only the fixed
 * plan, uses bounded Broker-owned command specs, and requires final launchd/
 * helper readback before reporting success. Non-root callers fail before any
 * filesystem or child-process access.
 */
export async function executePrivilegedHelperPackagePlan(
  plan: PrivilegedHelperPackagePlan,
  options: PrivilegedHelperPackageExecutionOptions
): Promise<PrivilegedHelperPackageExecutionResult> {
  if (options.confirmOperation !== plan.operation) {
    fail("CONFIRMATION_REQUIRED", "privileged helper execution requires an explicit matching operation");
  }
  assertPrivilegedHelperRootOwner(options.ownerUid);
  buildPrivilegedHelperPackageExecutionPlan(plan, options.existingService);
  const executor = options.commandExecutor ?? new ProcessSupervisor({ allowedEnvironmentKeys: [] });
  let bootoutSucceeded = false;
  let plistApplied = false;
  let bootstrapAttempted = false;
  let plist: PrivilegedHelperPlistApplyResult | undefined;
  try {
    if (plan.operation !== "uninstall") await runPrivilegedHelperCommand(executor, plan.signatureVerify, "helper signature verification failed");
    if (plan.operation !== "install") {
      await runPrivilegedHelperCommand(executor, plan.rollback.bootout, "existing helper service could not be stopped");
      bootoutSucceeded = true;
    }
    plist = await applyPrivilegedHelperPlistPlan(plan, { confirmOperation: plan.operation, ownerUid: 0 });
    plistApplied = true;
    if (plan.operation !== "uninstall") {
      bootstrapAttempted = true;
      await runPrivilegedHelperCommand(executor, plan.install.bootstrap, "helper service could not be bootstrapped");
    }
  } catch (error) {
    await recoverPrivilegedHelperPackage(plan, executor, { bootoutSucceeded, plistApplied, bootstrapAttempted }).catch(() => {
      fail("RECOVERY_FAILED", "privileged helper execution failed and recovery was not verified");
    });
    throw normalizePrivilegedHelperExecutionError(error, "privileged helper execution failed");
  }

  try {
    const sources = await options.readback();
    let readback: PrivilegedHelperPackageReadback | null;
    if (plan.operation === "uninstall") {
      if (sources !== null) fail("READBACK_FAILED", "helper uninstall readback still reports an installed service");
      readback = null;
    } else {
      if (sources === null) fail("READBACK_FAILED", "helper readback is absent after bootstrap");
      readback = composePrivilegedHelperPackageReadback(plan, sources);
    }
    return { operation: plan.operation, readback, plist: plist! };
  } catch (error) {
    await recoverPrivilegedHelperPackage(plan, executor, { bootoutSucceeded, plistApplied, bootstrapAttempted }).catch(() => {
      fail("RECOVERY_FAILED", "privileged helper readback failed and recovery was not verified");
    });
    throw normalizePrivilegedHelperExecutionError(error, "privileged helper readback failed");
  }
}

/**
 * Performs a read-only root-owned preflight for helper package paths. Every
 * path is lstat'ed twice; the caller must still use descriptor-relative,
 * identity-bound writes for any later installation.
 */
export async function inspectPrivilegedHelperPackageFilesystem(
  plan: PrivilegedHelperPackagePlan,
  options: { requirePlist?: boolean } = {}
): Promise<PrivilegedHelperFilesystemReadback> {
  const paths = requiredPrivilegedHelperFilesystemPaths(plan, options.requirePlist ?? plan.operation !== "install");
  const entries: PrivilegedHelperFilesystemEntryReadback[] = [];
  for (const [path, expectedKind] of paths) {
    const first = await readPrivilegedHelperFilesystemEntry(path, expectedKind);
    const second = await readPrivilegedHelperFilesystemEntry(path, expectedKind);
    if (first.device !== second.device || first.inode !== second.inode) {
      fail("INVALID_PACKAGE_PATH", "privileged helper filesystem identity changed during preflight");
    }
    entries.push(first);
  }
  const readback = { ownerUid: 0 as const, entries };
  validatePrivilegedHelperFilesystemReadback(plan, readback, options.requirePlist ?? plan.operation !== "install");
  return readback;
}

export function validatePrivilegedHelperFilesystemReadback(
  plan: PrivilegedHelperPackagePlan,
  readback: PrivilegedHelperFilesystemReadback,
  requirePlist = plan.operation !== "install"
): void {
  if (readback === null || typeof readback !== "object" || readback.ownerUid !== 0 || !Array.isArray(readback.entries)) {
    fail("INVALID_READBACK", "privileged helper filesystem readback is malformed");
  }
  const expected = requiredPrivilegedHelperFilesystemPaths(plan, requirePlist);
  const expectedMap = new Map(expected);
  if (readback.entries.length !== expected.length) fail("INVALID_READBACK", "privileged helper filesystem readback entry count is invalid");
  const seen = new Set<string>();
  for (const entry of readback.entries) {
    if (entry === null || typeof entry !== "object" || typeof entry.path !== "string" || seen.has(entry.path)) {
      fail("INVALID_READBACK", "privileged helper filesystem readback contains a duplicate or malformed entry");
    }
    const expectedKind = expectedMap.get(entry.path);
    if (expectedKind === undefined || entry.ownerUid !== 0 ||
        !Number.isSafeInteger(entry.mode) || (entry.mode & 0o022) !== 0 ||
        !Number.isSafeInteger(entry.device) || !Number.isSafeInteger(entry.inode) || entry.device < 0 || entry.inode < 0 ||
        (expectedKind === "file" && entry.kind !== "file") ||
        (expectedKind === "directory" && entry.kind !== "directory") ||
        (expectedKind === "file-or-directory" && entry.kind !== "file" && entry.kind !== "directory")) {
      fail("INVALID_PACKAGE_PATH", "privileged helper filesystem ownership, mode, type, or identity is unsafe");
    }
    if ((entry.path === plan.helperKeyConfigPath || entry.path === plan.plistPath) && (entry.mode & 0o777) !== 0o600) {
      fail("INVALID_PACKAGE_PATH", "privileged helper secret/plist files must be owner-only");
    }
    if (entry.path === plan.launchd.program && (entry.mode & 0o100) === 0) {
      fail("INVALID_PACKAGE_PATH", "privileged helper executable is not owner-executable");
    }
    seen.add(entry.path);
  }
}

/**
 * Reads the Broker-owned authority socket as a separate ownership domain.
 * The socket is intentionally not included in the root-owned helper file
 * preflight; only its exact endpoint identity and restricted mode are checked.
 */
export async function readPrivilegedHelperAuthoritySocketReadback(
  plan: PrivilegedHelperPackagePlan
): Promise<PrivilegedHelperAuthoritySocketReadback> {
  let first;
  let second;
  try {
    first = await lstat(plan.helperAuthoritySocketPath);
    second = await lstat(plan.helperAuthoritySocketPath);
  } catch {
    fail("READBACK_FAILED", "privileged helper authority socket is unavailable");
  }
  if (!first.isSocket() || first.isSymbolicLink() || !second.isSocket() || second.isSymbolicLink() ||
      first.uid !== second.uid || first.gid !== second.gid || first.mode !== second.mode ||
      first.dev !== second.dev || first.ino !== second.ino) {
    fail("SERVICE_MISMATCH", "privileged helper authority socket identity changed during readback");
  }
  return {
    path: plan.helperAuthoritySocketPath,
    ownerUid: first.uid,
    ownerGid: first.gid,
    mode: first.mode & 0o777,
    device: first.dev,
    inode: first.ino
  };
}

export function requiredPrivilegedHelperFilesystemPaths(
  plan: PrivilegedHelperPackagePlan,
  requirePlist = plan.operation !== "install"
): readonly (readonly [string, PrivilegedHelperExpectedFilesystemKind])[] {
  const paths = new Map<string, PrivilegedHelperExpectedFilesystemKind>();
  paths.set(plan.helperRoot, "directory");
  paths.set(plan.launchd.program, "file");
  paths.set(plan.signedArtifactPath, "file-or-directory");
  paths.set(plan.helperKeyConfigPath, "file");
  paths.set(dirname(plan.helperSocketPath), "directory");
  paths.set(dirname(plan.launchd.stdoutPath), "directory");
  paths.set(dirname(plan.plistPath), "directory");
  if (requirePlist) paths.set(plan.plistPath, "file");
  for (const target of [
    plan.helperRoot,
    dirname(plan.launchd.program),
    dirname(plan.signedArtifactPath),
    dirname(plan.helperKeyConfigPath),
    dirname(plan.helperSocketPath),
    dirname(plan.launchd.stdoutPath),
    dirname(plan.plistPath)
  ]) {
    for (const ancestor of ancestorsToRoot(target)) paths.set(ancestor, "directory");
  }
  return [...paths.entries()].map(([path, kind]) => [path, kind] as const).sort(([left], [right]) => left.localeCompare(right));
}

/**
 * Applies only the helper plist file action through the descriptor-relative
 * native writer. It never invokes launchctl; callers must separately execute
 * and verify the fixed bootstrap/bootout commands from the plan.
 */
export async function applyPrivilegedHelperPlistPlan(
  plan: PrivilegedHelperPackagePlan,
  options: PrivilegedHelperPlistApplyOptions
): Promise<PrivilegedHelperPlistApplyResult> {
  if (options.confirmOperation !== plan.operation) {
    fail("CONFIRMATION_REQUIRED", "privileged helper plist apply requires an explicit matching operation");
  }
  assertPrivilegedHelperRootOwner(options.ownerUid);
  await inspectPrivilegedHelperPackageFilesystem(plan, { requirePlist: plan.operation !== "install" });
  const inspector = createPrivilegedHelperInspector();
  const targetPlan = inspector.planPath(plan.plistPath, "write");
  const current = optionalPrivilegedHelperStat(inspector, targetPlan);
  if (plan.operation === "install") {
    if (current !== undefined) fail("FILESYSTEM_MISMATCH", "helper plist install requires an absent target");
    const result = inspector.writePlanned(
      targetPlan,
      Buffer.from(plan.renderedPlist, "utf8"),
      undefined,
      true,
      temporaryHelperPlistName("install"),
      identity(false)
    );
    return toPrivilegedHelperApplyResult(plan.operation, result, null, null);
  }
  if (current === undefined) fail("FILESYSTEM_MISMATCH", "helper plist operation requires an existing target");
  const currentIdentity = identityFromPrivilegedHelperMetadata(current);
  if (plan.operation === "uninstall") {
    const original = readExistingPrivilegedHelperPlist(inspector, plan.plistPath);
    const backupPlan = inspector.planPath(`${plan.plistPath}.previous`, "write");
    const backupCurrent = optionalPrivilegedHelperStat(inspector, backupPlan);
    let backupRemoved = false;
    try {
      const removed = inspector.unlinkPlanned(targetPlan, currentIdentity);
      if (backupCurrent !== undefined) {
        inspector.unlinkPlanned(backupPlan, identityFromPrivilegedHelperMetadata(backupCurrent));
        backupRemoved = true;
      }
      if (optionalPrivilegedHelperStat(inspector, targetPlan) !== undefined) {
        fail("FILESYSTEM_MISMATCH", "helper plist uninstall postcondition did not remove the target");
      }
      return {
        operation: "uninstall",
        path: HELPER_PLIST_PATH,
        bytesWritten: 0,
        sha256: null,
        created: false,
        backupPath: backupRemoved ? `${plan.plistPath}.previous` : null,
        backupSha256: null,
        device: removed.device,
        inode: removed.inode
      };
    } catch (error) {
      if (optionalPrivilegedHelperStat(inspector, targetPlan) === undefined) {
        try {
          inspector.writePlanned(targetPlan, original.content, undefined, true, temporaryHelperPlistName("uninstall-restore"), identity(false));
        } catch (restoreError) {
          throw new AggregateError([error, restoreError], "helper plist uninstall failed and restoration also failed");
        }
      }
      throw error;
    }
  }
  const backupPath = `${plan.plistPath}.previous`;
  if (plan.operation === "upgrade") {
    const original = readExistingPrivilegedHelperPlist(inspector, plan.plistPath);
    const backupPlan = inspector.planPath(backupPath, "write");
    const backupCurrent = optionalPrivilegedHelperStat(inspector, backupPlan);
    const backupResult = inspector.writePlanned(
      backupPlan,
      original.content,
      undefined,
      false,
      temporaryHelperPlistName("backup"),
      backupCurrent === undefined ? identity(false) : identityFromPrivilegedHelperMetadata(backupCurrent)
    );
    try {
      const result = inspector.writePlanned(
        targetPlan,
        Buffer.from(plan.renderedPlist, "utf8"),
        undefined,
        false,
        temporaryHelperPlistName("upgrade"),
        currentIdentity
      );
      return toPrivilegedHelperApplyResult(plan.operation, result, backupPath, backupResult.sha256);
    } catch (error) {
      try {
        inspector.writePlanned(targetPlan, original.content, undefined, false, temporaryHelperPlistName("upgrade-restore"), currentIdentity);
      } catch (restoreError) {
        throw new AggregateError([error, restoreError], "helper plist upgrade failed and restoration also failed");
      }
      throw error;
    }
  }
  const backup = readExistingPrivilegedHelperPlist(inspector, backupPath);
  const result = inspector.writePlanned(
    targetPlan,
    backup.content,
    undefined,
    false,
    temporaryHelperPlistName("rollback"),
    currentIdentity
  );
  return toPrivilegedHelperApplyResult(plan.operation, result, backupPath, null);
}

async function readPrivilegedHelperFilesystemEntry(
  path: string,
  expectedKind: PrivilegedHelperExpectedFilesystemKind
): Promise<PrivilegedHelperFilesystemEntryReadback> {
  let stats;
  try {
    stats = await lstat(path);
  } catch {
    fail("INVALID_PACKAGE_PATH", "required privileged helper package path is unavailable");
  }
  if (stats.isSymbolicLink() || stats.uid !== 0 || (stats.mode & 0o022) !== 0 ||
      (expectedKind === "file" && !stats.isFile()) ||
      (expectedKind === "directory" && !stats.isDirectory()) ||
      (expectedKind === "file-or-directory" && !stats.isFile() && !stats.isDirectory())) {
    fail("INVALID_PACKAGE_PATH", "privileged helper package path ownership, mode, symlink, or type is unsafe");
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

function ancestorsToRoot(target: string): readonly string[] {
  const result: string[] = [];
  let current = target;
  while (true) {
    result.push(current);
    if (current === "/") break;
    const parent = dirname(current);
    if (parent === current) fail("INVALID_PACKAGE_PATH", "privileged helper path cannot reach the filesystem root");
    current = parent;
  }
  return result;
}

function createPrivilegedHelperInspector(): FilesystemInspector {
  return new FilesystemInspector([{
    rootId: "mac-operator-privileged-helper-system-root",
    path: "/",
    metadata: true,
    contentRead: true,
    write: true,
    denyRelativePaths: []
  }]);
}

function optionalPrivilegedHelperStat(inspector: FilesystemInspector, plan: FilesystemPathPlan) {
  try {
    return inspector.statPlanned(plan, false);
  } catch {
    return undefined;
  }
}

function readExistingPrivilegedHelperPlist(inspector: FilesystemInspector, path: string): { content: Buffer; device: string; inode: string } {
  const plan = inspector.planPath(path, "content_read");
  const read = inspector.readPlanned(plan, 0, 1_048_576);
  if (read.truncated) fail("FILESYSTEM_MISMATCH", "helper plist content exceeds the bounded rollback budget");
  return { content: read.content, device: read.device, inode: read.inode };
}

function identity(present: boolean, device = "0", inode = "0"): FilesystemIdentityPrecondition {
  return { present, device, inode };
}

function identityFromPrivilegedHelperMetadata(metadata: { device: string; inode: string }): FilesystemIdentityPrecondition {
  return identity(true, metadata.device, metadata.inode);
}

function temporaryHelperPlistName(kind: string): string {
  return `.mac-operator-write-helper-${kind}-${randomBytes(12).toString("hex")}`;
}

function toPrivilegedHelperApplyResult(
  operation: PrivilegedHelperPackageOperation,
  result: { path: string; bytesWritten: number; sha256: string; created: boolean; device: string; inode: string },
  backupPath: string | null,
  backupSha256: string | null
): PrivilegedHelperPlistApplyResult {
  return {
    operation,
    path: HELPER_PLIST_PATH,
    bytesWritten: result.bytesWritten,
    sha256: result.sha256,
    created: result.created,
    backupPath,
    backupSha256,
    device: result.device,
    inode: result.inode
  };
}

export function renderPrivilegedHelperLaunchdPlist(config: PrivilegedHelperLaunchdConfig): string {
  const normalized = normalizeService(config, dirname(config.program), false);
  const argumentsXml = normalized.programArguments.map((argument) => `      <string>${escapeXml(argument)}</string>`).join("\n");
  return [
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">",
    "<plist version=\"1.0\">",
    "  <dict>",
    `    <key>Label</key><string>${escapeXml(HELPER_LABEL)}</string>`,
    "    <key>ProgramArguments</key>",
    "    <array>",
    argumentsXml,
    "    </array>",
    `    <key>WorkingDirectory</key><string>${escapeXml(normalized.workingDirectory)}</string>`,
    `    <key>StandardOutPath</key><string>${escapeXml(normalized.stdoutPath)}</string>`,
    `    <key>StandardErrorPath</key><string>${escapeXml(normalized.stderrPath)}</string>`,
    "    <key>UserName</key><string>root</string>",
    `    <key>RunAtLoad</key><${normalized.runAtLoad ? "true" : "false"}/>`,
    `    <key>KeepAlive</key><${normalized.keepAlive ? "true" : "false"}/>`,
    `    <key>ThrottleInterval</key><integer>${normalized.throttleIntervalSeconds}</integer>`,
    "    <key>ProcessType</key><string>Background</string>",
    "    <key>AbandonProcessGroup</key><false/>",
    "  </dict>",
    "</plist>",
    ""
  ].join("\n");
}

export function validatePrivilegedHelperPackageReadback(
  plan: PrivilegedHelperPackagePlan,
  readback: PrivilegedHelperPackageReadback
): void {
  if (readback === null || typeof readback !== "object" || readback.domain !== "system" ||
      readback.label !== HELPER_LABEL || readback.plistPath !== HELPER_PLIST_PATH ||
      !Number.isSafeInteger(readback.pid) || readback.pid < 1 ||
      readback.processIdentity === null || typeof readback.processIdentity !== "object" ||
      !Number.isSafeInteger(readback.processIdentity.pid) || readback.processIdentity.pid < 1 ||
      !Number.isSafeInteger(readback.processIdentity.startTimeMicros) || readback.processIdentity.startTimeMicros < 1 ||
      readback.processIdentity.pid !== readback.pid ||
      !isPrivilegedHelperPlistReadback(readback.plist, plan)) {
    fail("INVALID_READBACK", "privileged helper readback identity is malformed");
  }
  const authoritySocket = readback.authoritySocket;
  if (authoritySocket === null || typeof authoritySocket !== "object" ||
      authoritySocket.path !== plan.helperAuthoritySocketPath ||
      !Number.isSafeInteger(authoritySocket.ownerUid) || authoritySocket.ownerUid !== plan.brokerPeer.uid ||
      !Number.isSafeInteger(authoritySocket.ownerGid) || authoritySocket.ownerGid < 0 || authoritySocket.ownerGid > 2_147_483_647 ||
      (plan.brokerPeer.gid !== undefined && authoritySocket.ownerGid !== plan.brokerPeer.gid) ||
      !Number.isSafeInteger(authoritySocket.mode) || (authoritySocket.mode & 0o077) !== 0 ||
      !Number.isSafeInteger(authoritySocket.device) || authoritySocket.device < 0 ||
      !Number.isSafeInteger(authoritySocket.inode) || authoritySocket.inode < 0) {
    fail("SERVICE_MISMATCH", "privileged helper authority socket ownership or identity does not match the plan");
  }
  if (readback.launchd === null || typeof readback.launchd !== "object" ||
      readback.launchd.label !== plan.launchd.label || readback.launchd.program !== plan.launchd.program ||
      !sameStrings(readback.launchd.programArguments, plan.launchd.programArguments) ||
      readback.launchd.workingDirectory !== plan.launchd.workingDirectory ||
      readback.launchd.stdoutPath !== plan.launchd.stdoutPath || readback.launchd.stderrPath !== plan.launchd.stderrPath ||
      readback.launchd.domain !== "system" || readback.launchd.type !== "LaunchDaemon" || readback.launchd.runsAsRoot !== true ||
      readback.launchd.usesEnvironmentVariables !== false || readback.launchd.usesShell !== false ||
      readback.launchd.runAtLoad !== plan.launchd.runAtLoad || readback.launchd.keepAlive !== plan.launchd.keepAlive ||
      readback.launchd.throttleIntervalSeconds !== plan.launchd.throttleIntervalSeconds) {
    fail("SERVICE_MISMATCH", "privileged helper launchd readback does not match the plan");
  }
  if (readback.helper === null || typeof readback.helper !== "object" ||
      readback.helper.component !== "mac-operator-privileged-helper" || readback.helper.state !== "running" ||
      readback.helper.runtimeState !== "running" || readback.helper.nativeTransportRequired !== true ||
      readback.helper.adapterAvailable !== plan.adapterAvailable || readback.helper.helperSocketPath !== plan.helperSocketPath ||
      readback.helper.brokerSocketPath !== plan.brokerSocketPath ||
      readback.helper.helperAuthoritySocketPath !== plan.helperAuthoritySocketPath ||
      readback.helper.brokerPeerUid !== plan.brokerPeer.uid ||
      readback.helper.brokerPeerGid !== (plan.brokerPeer.gid ?? null) ||
      readback.helper.sourceRevision !== plan.sourceRevision || readback.helper.contractVersion !== plan.contractVersion ||
      readback.helper.policyVersion !== plan.policyVersion || !sameStrings(readback.helper.enabledCapabilities, plan.enabledCapabilities)) {
    fail("SERVICE_MISMATCH", "privileged helper runtime readback does not match the plan");
  }
  try {
    validateCodeSignatureReadback(plan.signature, readback.signature, plan.signedArtifactPath);
  } catch {
    fail("SIGNATURE_MISMATCH", "privileged helper code signature readback does not match the plan");
  }
}

/**
 * Composes helper readiness only from independently observed launchd,
 * process, plist, runtime, and signature sources. The launchd parser remains
 * authoritative for service identity, state, PID, argv, plist path, and
 * LaunchDaemon type; planned fields are copied only after those observations
 * match the exact root-domain helper plan.
 */
export function composePrivilegedHelperPackageReadback(
  plan: PrivilegedHelperPackagePlan,
  sources: PrivilegedHelperPackageReadbackSources
): PrivilegedHelperPackageReadback {
  if (sources === null || typeof sources !== "object" ||
      sources.launchd === null || typeof sources.launchd !== "object" ||
      sources.processIdentity === null || typeof sources.processIdentity !== "object" ||
      sources.plist === null || typeof sources.plist !== "object" ||
      sources.helper === null || typeof sources.helper !== "object" ||
      sources.authoritySocket === null || typeof sources.authoritySocket !== "object" ||
      sources.signature === null || typeof sources.signature !== "object") {
    fail("INVALID_READBACK", "privileged helper readback sources are malformed");
  }
  const expectedServiceId = `${plan.domain}/${plan.label}`;
  const launchd = sources.launchd;
  if (launchd.serviceId !== expectedServiceId || launchd.domain !== "system" ||
      launchd.label !== plan.label || launchd.state !== "running" ||
      launchd.type !== "LaunchDaemon" || launchd.pid === null ||
      launchd.program !== plan.launchd.program ||
      !sameStrings(launchd.arguments, plan.launchd.programArguments) ||
      launchd.plistPath !== plan.plistPath || launchd.truncated !== false ||
      launchd.pid !== sources.processIdentity.pid) {
    fail("SERVICE_MISMATCH", "launchd readback sources do not match the planned privileged helper");
  }
  const readback: PrivilegedHelperPackageReadback = {
    domain: plan.domain,
    label: plan.label,
    plistPath: plan.plistPath,
    pid: launchd.pid,
    processIdentity: sources.processIdentity,
    plist: sources.plist,
    launchd: plan.launchd,
    authoritySocket: sources.authoritySocket,
    helper: sources.helper,
    signature: sources.signature
  };
  validatePrivilegedHelperPackageReadback(plan, readback);
  return readback;
}

/**
 * Reads the host-owned helper boundary without trusting a single mutable
 * snapshot. Launchd, PID/start-time, and plist identities are observed twice;
 * any target or process replacement during collection fails closed before the
 * sources are composed into a final package readback.
 */
export async function observePrivilegedHelperPackageReadback(
  plan: PrivilegedHelperPackagePlan,
  observer: PrivilegedHelperPackageReadbackObserver
): Promise<PrivilegedHelperPackageReadback> {
  try {
    if (observer === null || typeof observer !== "object") {
      fail("INVALID_READBACK", "privileged helper readback observer is malformed");
    }
    const serviceId = `${plan.domain}/${plan.label}`;
    const launchdBefore = await observer.readLaunchd(serviceId);
    if (launchdBefore.pid === null) fail("SERVICE_MISMATCH", "privileged helper launchd readback has no running PID");
    const processBefore = await observer.readProcessIdentity(launchdBefore.pid);
    const plistBefore = await observer.readPlist(plan);
    const helper = await observer.readRuntime();
    const authoritySocket = await observer.readAuthoritySocket(plan);
    const signature = await observer.readSignature();
    const launchdAfter = await observer.readLaunchd(serviceId);
    if (!sameLaunchdIdentity(launchdBefore, launchdAfter) || launchdAfter.pid === null) {
      fail("SERVICE_MISMATCH", "privileged helper launchd identity changed during readback");
    }
    const processAfter = await observer.readProcessIdentity(launchdAfter.pid);
    if (!sameProcessIdentity(processBefore, processAfter)) {
      fail("SERVICE_MISMATCH", "privileged helper process identity changed during readback");
    }
    const plistAfter = await observer.readPlist(plan);
    if (!samePlistIdentity(plistBefore, plistAfter)) {
      fail("FILESYSTEM_MISMATCH", "privileged helper plist identity changed during readback");
    }
    return composePrivilegedHelperPackageReadback(plan, {
      launchd: launchdAfter,
      processIdentity: processAfter,
      plist: plistAfter,
      helper,
      authoritySocket,
      signature
    });
  } catch (error) {
    if (error instanceof PrivilegedHelperPackageError) throw error;
    fail("READBACK_FAILED", "privileged helper host readback failed");
  }
}

/**
 * Creates the production-shaped observer. Launchd and codesign use the
 * bounded, empty-environment ProcessSupervisor; PID identity uses the native
 * observer; plist content uses the internal descriptor-backed reader. Runtime
 * metadata remains an explicit helper-owned source because it is not inferred
 * from launchd or caller arguments.
 */
export function createPrivilegedHelperPackageHostObserver(
  plan: PrivilegedHelperPackagePlan,
  options: PrivilegedHelperPackageHostObserverOptions
): PrivilegedHelperPackageReadbackObserver {
  if (options === null || typeof options !== "object" ||
      (typeof options.readRuntime !== "function" && options.helperStatusClient === undefined)) {
    fail("INVALID_ARGUMENT", "privileged helper host observer requires an authenticated runtime source");
  }
  const readRuntime = options.readRuntime ?? (() => readPrivilegedHelperStatus(options.helperStatusClient!));
  return {
    readLaunchd: async (serviceId) => readLaunchdJobReadback(serviceId, options.launchdExecutor === undefined ? {} : { executor: options.launchdExecutor }),
    readProcessIdentity: (pid) => options.processIdentityReader?.(pid) ?? capturePeerProcessIdentity(pid),
    readPlist: options.readPlist ?? (async (candidate) => readPrivilegedHelperPlistReadback(candidate)),
    readRuntime,
    readAuthoritySocket: options.readAuthoritySocket ?? (async (candidate) => readPrivilegedHelperAuthoritySocketReadback(candidate)),
    readSignature: options.readSignature === undefined
      ? async () => readPrivilegedHelperCodeSignature(plan, options.launchdExecutor === undefined ? {} : { executor: options.launchdExecutor })
      : async () => options.readSignature!(plan)
  };
}

/**
 * Performs a bounded strict verification and details readback for the exact
 * helper artifact. The parser accepts only the small codesign detail fields
 * needed by the package contract and never returns raw command output.
 */
export async function readPrivilegedHelperCodeSignature(
  plan: PrivilegedHelperPackagePlan,
  options: { executor?: LaunchdReadbackExecutor } = {}
): Promise<CodeSignatureReadback> {
  const executor = options.executor ?? new ProcessSupervisor({ allowedEnvironmentKeys: [] });
  let verification: ProcessExecutionResult;
  let details: ProcessExecutionResult;
  try {
    verification = await executor.run(plan.signatureVerify);
    if (verification.resultClass !== "SUCCEEDED" || verification.truncated) {
      fail("SIGNATURE_MISMATCH", "privileged helper code signature verification failed");
    }
    details = await executor.run({
      executable: CODESIGN_PATH,
      args: ["-dv", "--verbose=4", plan.signedArtifactPath],
      cwd: "/",
      environment: {},
      timeoutMs: COMMAND_TIMEOUT_MS,
      outputCapBytes: COMMAND_OUTPUT_CAP_BYTES
    });
  } catch (error) {
    if (error instanceof PrivilegedHelperPackageError) throw error;
    fail("SIGNATURE_MISMATCH", "privileged helper code signature readback failed");
  }
  if (details.resultClass !== "SUCCEEDED" || details.truncated) {
    fail("SIGNATURE_MISMATCH", "privileged helper code signature details failed");
  }
  const output = `${details.stdout}\n${details.stderr}`;
  const identifier = readCodeSignatureField(output, "Identifier", /^[A-Za-z0-9._:-]{1,128}$/u);
  const teamIdentifier = readCodeSignatureField(output, "TeamIdentifier", /^[A-Z0-9]{5,32}$/u);
  const cdHash = readCodeSignatureField(output, "CDHash", /^[a-f0-9]{20,64}$/u);
  const readback: CodeSignatureReadback = {
    artifactPath: plan.signedArtifactPath,
    valid: true,
    identifier,
    teamIdentifier,
    cdHash
  };
  try {
    validateCodeSignatureReadback(plan.signature, readback, plan.signedArtifactPath);
  } catch {
    fail("SIGNATURE_MISMATCH", "privileged helper code signature readback does not match the plan");
  }
  return readback;
}

/**
 * Reads the exact root-domain plist through the descriptor-backed filesystem
 * boundary. The caller must already be the host/root executor; no caller-
 * supplied inspector or path is accepted.
 */
export function readPrivilegedHelperPlistReadback(plan: PrivilegedHelperPackagePlan): MacOsPlistReadback {
  const inspector = createPrivilegedHelperInspector();
  let read: ReturnType<FilesystemInspector["readPlanned"]>;
  try {
    const targetPlan = inspector.planPath(plan.plistPath, "content_read");
    read = inspector.readPlanned(targetPlan, 0, MAX_PLIST_BYTES);
  } catch {
    fail("FILESYSTEM_MISMATCH", "privileged helper plist could not be read through the protected filesystem boundary");
  }
  const expectedBytes = Buffer.from(plan.renderedPlist, "utf8");
  const sha256 = createHash("sha256").update(read.content).digest("hex");
  if (read.truncated || read.path !== plan.plistPath || !read.content.equals(expectedBytes) || sha256 !== createHash("sha256").update(expectedBytes).digest("hex")) {
    fail("FILESYSTEM_MISMATCH", "privileged helper plist readback does not match the rendered plan");
  }
  return { path: read.path, bytes: read.content.byteLength, sha256, device: read.device, inode: read.inode };
}

function normalizeService(config: PrivilegedHelperLaunchdConfig, helperRoot: string, enforceRoot = true): Required<PrivilegedHelperLaunchdConfig> {
  if (config === null || typeof config !== "object" || config.label !== HELPER_LABEL) {
    fail("INVALID_ARGUMENT", "privileged helper launchd label is invalid");
  }
  const program = canonicalPath(config.program, "privileged helper program");
  if (enforceRoot && !isDescendant(helperRoot, program, false)) fail("INVALID_PACKAGE_PATH", "privileged helper program must remain inside the helper root");
  if (INTERPRETER_NAMES.has(basename(program).toLowerCase()) || /\.(?:c|m)?js|\.sh|\.command$/iu.test(program)) {
    fail("INVALID_PACKAGE_PATH", "privileged helper program must be a signed native executable");
  }
  if (!Array.isArray(config.programArguments) || config.programArguments.length !== 1 || config.programArguments[0] !== program) {
    fail("INVALID_PACKAGE_PATH", "privileged helper launchd argv must contain only the native helper executable");
  }
  let totalBytes = 0;
  for (const argument of config.programArguments) {
    if (typeof argument !== "string" || argument.length === 0 || argument.includes("\0") || Buffer.byteLength(argument, "utf8") > MAX_ARGUMENT_BYTES) {
      fail("INVALID_ARGUMENT", "privileged helper launchd argv contains an invalid value");
    }
    totalBytes += Buffer.byteLength(argument, "utf8");
  }
  if (totalBytes > MAX_ARGUMENT_TOTAL_BYTES) fail("INVALID_ARGUMENT", "privileged helper launchd argv is too large");
  const workingDirectory = canonicalPath(config.workingDirectory, "privileged helper working directory");
  const stdoutPath = canonicalPath(config.stdoutPath, "privileged helper stdout path");
  const stderrPath = canonicalPath(config.stderrPath, "privileged helper stderr path");
  if (enforceRoot && (!isDescendant(helperRoot, workingDirectory, true) || !isDescendant(helperRoot, stdoutPath, false) || !isDescendant(helperRoot, stderrPath, false))) {
    fail("INVALID_PACKAGE_PATH", "privileged helper working directory and logs must remain inside the helper root");
  }
  if (stdoutPath === stderrPath) fail("INVALID_PACKAGE_PATH", "privileged helper stdout and stderr paths must differ");
  const runAtLoad = config.runAtLoad ?? true;
  const keepAlive = config.keepAlive ?? true;
  const throttleIntervalSeconds = config.throttleIntervalSeconds ?? 5;
  if (runAtLoad !== true || keepAlive !== true || !Number.isSafeInteger(throttleIntervalSeconds) || throttleIntervalSeconds < 1 || throttleIntervalSeconds > 3_600) {
    fail("INVALID_ARGUMENT", "privileged helper launchd lifecycle must be enabled and bounded");
  }
  return { ...config, program, programArguments: [program], workingDirectory, stdoutPath, stderrPath, runAtLoad, keepAlive, throttleIntervalSeconds };
}

function validatePeerExpectation(value: PrivilegedHelperBrokerPeerExpectation): void {
  if (value === null || typeof value !== "object" || !Number.isSafeInteger(value.uid) || value.uid < 1 || value.uid > 2_147_483_647 ||
      (value.gid !== undefined && (!Number.isSafeInteger(value.gid) || value.gid < 0 || value.gid > 2_147_483_647))) {
    fail("INVALID_PEER_IDENTITY", "privileged helper Broker peer identity is invalid");
  }
}

function normalizeSignature(value: CodeSignatureExpectation): CodeSignatureExpectation {
  if (value === null || typeof value !== "object" || typeof value.identifier !== "string" ||
      value.identifier !== HELPER_LABEL || typeof value.teamIdentifier !== "string" ||
      !/^[A-Z0-9]{10}$/u.test(value.teamIdentifier) || typeof value.cdHash !== "string" ||
      !/^[a-f0-9]{20,64}$/u.test(value.cdHash)) {
    fail("INVALID_SIGNATURE", "privileged helper requires a Developer ID team identifier and CDHash");
  }
  return { identifier: value.identifier, teamIdentifier: value.teamIdentifier, cdHash: value.cdHash };
}

function normalizePreviousRevision(value: string | undefined, operation: PrivilegedHelperPackageOperation): string | undefined {
  if (operation === "install") {
    if (value !== undefined) fail("INVALID_REVISION", "install cannot provide a previous source revision");
    return undefined;
  }
  if (value === undefined || !REVISION_PATTERN.test(value)) fail("INVALID_REVISION", "upgrade, rollback, and uninstall require an exact previous source revision");
  return value;
}

function normalizeCapabilityRelease(value: PrivilegedHelperCapabilityRelease | undefined): PrivilegedHelperCapabilityRelease | undefined {
  if (value === undefined) return undefined;
  if (!isPlainDataRecord(value) || Object.keys(value).sort().join(",") !== "adapterAvailable,enabledCapabilities,evidenceRef,source" ||
      value.source !== "host-verified" ||
      typeof value.adapterAvailable !== "boolean" || !Array.isArray(value.enabledCapabilities) ||
      typeof value.evidenceRef !== "string" || !CAPABILITY_EVIDENCE_PATTERN.test(value.evidenceRef)) {
    fail("INVALID_CAPABILITY_RELEASE", "privileged helper capability release is malformed");
  }
  const capabilities = [...value.enabledCapabilities];
  if (capabilities.length > 8 || capabilities.some((capability) => typeof capability !== "string" ||
      !CAPABILITY_PATTERN.test(capability) || !IMPLEMENTED_HELPER_CAPABILITIES.has(capability)) ||
      capabilities.some((capability, index) => index > 0 && capabilities[index - 1]! >= capability) ||
      value.adapterAvailable !== (capabilities.length > 0)) {
    fail("INVALID_CAPABILITY_RELEASE", "privileged helper capability release is not an implemented canonical projection");
  }
  return Object.freeze({
    source: "host-verified" as const,
    adapterAvailable: value.adapterAvailable,
    enabledCapabilities: Object.freeze(capabilities),
    evidenceRef: value.evidenceRef
  });
}

function validateRevision(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !REVISION_PATTERN.test(value)) fail("INVALID_REVISION", `${label} is invalid`);
}

function validateVersion(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !VERSION_PATTERN.test(value)) fail("INVALID_ARGUMENT", `${label} is invalid`);
}

function launchctlCommand(args: readonly string[]): LaunchdCommandSpec {
  return { executable: LAUNCHCTL_PATH, args: [...args], cwd: "/", environment: {}, timeoutMs: COMMAND_TIMEOUT_MS, outputCapBytes: COMMAND_OUTPUT_CAP_BYTES };
}

function sameStrings(left: unknown, right: readonly string[]): boolean {
  return Array.isArray(left) && left.length === right.length && left.every((value, index) => value === right[index]);
}

function sameLaunchdIdentity(left: LaunchdJobReadback, right: LaunchdJobReadback): boolean {
  return left.serviceId === right.serviceId && left.domain === right.domain && left.label === right.label &&
    left.state === right.state && left.pid === right.pid && left.program === right.program &&
    sameStrings(left.arguments, right.arguments ?? []) && left.plistPath === right.plistPath && left.type === right.type;
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
  if (matches.length !== 1) fail("SIGNATURE_MISMATCH", `privileged helper code signature returned duplicate ${fieldName}`);
  const value = matches[0]?.[1]?.trim();
  if (value === undefined || !pattern.test(value)) fail("SIGNATURE_MISMATCH", `privileged helper code signature returned malformed ${fieldName}`);
  return value;
}

function isPrivilegedHelperPlistReadback(value: unknown, plan: PrivilegedHelperPackagePlan): value is MacOsPlistReadback {
  if (value === null || typeof value !== "object") return false;
  const readback = value as Partial<MacOsPlistReadback>;
  return readback.path === plan.plistPath &&
    Number.isSafeInteger(readback.bytes) && readback.bytes === Buffer.byteLength(plan.renderedPlist, "utf8") &&
    typeof readback.sha256 === "string" && readback.sha256 === createHash("sha256").update(plan.renderedPlist, "utf8").digest("hex") &&
    typeof readback.device === "string" && /^\d+$/u.test(readback.device) &&
    typeof readback.inode === "string" && /^\d+$/u.test(readback.inode);
}

function canonicalPath(value: unknown, label: string): string {
  if (typeof value !== "string" || !isAbsolute(value) || value.includes("\0") || resolve(value) !== value) fail("INVALID_ARGUMENT", `${label} must be a canonical absolute path`);
  return value;
}

function isDescendant(root: string, target: string, allowEqual: boolean): boolean {
  const relativePath = relative(root, target);
  return (allowEqual || relativePath.length > 0) && relativePath !== ".." && !relativePath.startsWith("../") && !relativePath.startsWith("/");
}

function escapeXml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll("\"", "&quot;").replaceAll("'", "&apos;");
}

function assertPrivilegedHelperRootOwner(ownerUid: number): void {
  const currentUid = process.getuid?.();
  if (ownerUid !== 0 || currentUid !== 0) {
    fail("INVALID_PEER_IDENTITY", "privileged helper execution requires root ownership");
  }
}

async function runPrivilegedHelperCommand(
  executor: PrivilegedHelperPackageCommandExecutor,
  command: LaunchdCommandSpec | CodeSignatureCommandSpec,
  message: string
): Promise<void> {
  let result: ProcessExecutionResult;
  try {
    result = await executor.run(command);
  } catch {
    fail("COMMAND_FAILED", message);
  }
  if (result.resultClass !== "SUCCEEDED") fail("COMMAND_FAILED", message);
}

async function recoverPrivilegedHelperPackage(
  plan: PrivilegedHelperPackagePlan,
  executor: PrivilegedHelperPackageCommandExecutor,
  state: { bootoutSucceeded: boolean; plistApplied: boolean; bootstrapAttempted: boolean }
): Promise<void> {
  if (!state.bootoutSucceeded && !state.plistApplied && !state.bootstrapAttempted) return;
  if (state.bootstrapAttempted) {
    await runPrivilegedHelperCommand(executor, plan.rollback.bootout, "helper recovery could not stop the mismatched service");
  }
  if (!state.plistApplied) {
    if (state.bootoutSucceeded && plan.operation !== "install") {
      await runPrivilegedHelperCommand(executor, plan.install.bootstrap, "helper recovery could not restore the previous service");
    }
    return;
  }
  if (plan.operation === "uninstall") return;
  const recoveryOperation = plan.operation === "install" ? "uninstall" : "rollback";
  const recoveryPlan = {
    ...plan,
    operation: recoveryOperation,
    expectedPreviousSourceRevision: plan.sourceRevision
  } as PrivilegedHelperPackagePlan;
  await applyPrivilegedHelperPlistPlan(recoveryPlan, { confirmOperation: recoveryOperation, ownerUid: 0 });
  if (recoveryOperation === "rollback") {
    await runPrivilegedHelperCommand(executor, plan.rollback.bootstrap, "helper recovery could not bootstrap the previous service");
  }
}

function normalizePrivilegedHelperExecutionError(error: unknown, message: string): PrivilegedHelperPackageError {
  if (error instanceof PrivilegedHelperPackageError) return error;
  return new PrivilegedHelperPackageError("READBACK_FAILED", message);
}

function validatePrivilegedHelperExistingService(
  plan: PrivilegedHelperPackagePlan,
  existingService: PrivilegedHelperExistingServiceReadback
): void {
  if (existingService === null || typeof existingService !== "object" || typeof existingService.present !== "boolean" ||
      (existingService.sourceRevision !== null && !REVISION_PATTERN.test(existingService.sourceRevision))) {
    fail("SERVICE_MISMATCH", "privileged helper existing-service readback is malformed");
  }
  if (plan.operation === "install") {
    if (existingService.present || existingService.sourceRevision !== null) {
      fail("SERVICE_MISMATCH", "privileged helper install requires an absent existing service");
    }
    return;
  }
  if (!existingService.present || existingService.sourceRevision !== plan.expectedPreviousSourceRevision) {
    fail("SERVICE_MISMATCH", "privileged helper operation requires the exact previous source revision");
  }
}

function fail(code: PrivilegedHelperPackageErrorCode, message: string): never {
  throw new PrivilegedHelperPackageError(code, message);
}
