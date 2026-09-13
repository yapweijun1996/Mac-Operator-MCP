import { lstat } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import type { CodeSignatureCommandSpec, CodeSignatureExpectation, CodeSignatureReadback, LaunchdCommandSpec } from "./macos-install-plan.js";
import { validateCodeSignatureReadback } from "./macos-install-plan.js";
import { FilesystemInspector, type FilesystemIdentityPrecondition, type FilesystemPathPlan } from "./filesystem-inspector.js";

const HELPER_LABEL = "com.mac-operator.privileged-helper" as const;
const HELPER_PLIST_PATH = "/Library/LaunchDaemons/com.mac-operator.privileged-helper.plist" as const;
const LAUNCHCTL_PATH = "/bin/launchctl" as const;
const CODESIGN_PATH = "/usr/bin/codesign" as const;
const COMMAND_TIMEOUT_MS = 5_000 as const;
const COMMAND_OUTPUT_CAP_BYTES = 131_072 as const;
const MAX_ARGUMENT_BYTES = 4_096;
const MAX_ARGUMENT_TOTAL_BYTES = 64 * 1_024;
const REVISION_PATTERN = /^[a-f0-9]{40}$/u;
const VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,120}$/u;
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
  | "SERVICE_MISMATCH"
  | "SIGNATURE_MISMATCH"
  | "INVALID_READBACK"
  | "CONFIRMATION_REQUIRED"
  | "FILESYSTEM_MISMATCH"
  | "RECOVERY_FAILED";

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
  brokerPeer: PrivilegedHelperBrokerPeerExpectation;
  sourceRevision: string;
  contractVersion: string;
  policyVersion: string;
  expectedPreviousSourceRevision?: string;
}

export interface PrivilegedHelperLaunchdReadback {
  label: typeof HELPER_LABEL;
  program: string;
  workingDirectory: string;
  stdoutPath: string;
  stderrPath: string;
  domain: "system";
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
  adapterAvailable: false;
  helperSocketPath: string;
  brokerSocketPath: string;
  brokerPeerUid: number;
  brokerPeerGid: number | null;
  sourceRevision: string;
  contractVersion: string;
  policyVersion: string;
  enabledCapabilities: readonly [];
}

export interface PrivilegedHelperPackageReadback {
  domain: "system";
  label: typeof HELPER_LABEL;
  plistPath: typeof HELPER_PLIST_PATH;
  pid: number | null;
  launchd: PrivilegedHelperLaunchdReadback;
  helper: PrivilegedHelperRuntimeReadback;
  signature: CodeSignatureReadback;
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
  brokerPeer: PrivilegedHelperBrokerPeerExpectation;
  sourceRevision: string;
  contractVersion: string;
  policyVersion: string;
  expectedPreviousSourceRevision?: string;
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
  enabledCapabilities: readonly [];
  adapterAvailable: false;
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
  if (helperSocketPath === brokerSocketPath) fail("INVALID_SOCKET_BOUNDARY", "helper and Broker sockets must be distinct");
  validatePeerExpectation(input.brokerPeer);
  validateRevision(input.sourceRevision, "source revision");
  validateVersion(input.contractVersion, "contract version");
  validateVersion(input.policyVersion, "policy version");
  const expectedPreviousSourceRevision = normalizePreviousRevision(input.expectedPreviousSourceRevision, operation);
  const signature = normalizeSignature(input.signature);
  if (signature.identifier !== HELPER_LABEL) fail("INVALID_SIGNATURE", "helper signature identifier is invalid");
  const renderedPlist = renderPrivilegedHelperLaunchdPlist(service);
  const backupPath = `${plistPath}.previous`;
  const launchd = {
    label: HELPER_LABEL,
    program: service.program,
    workingDirectory: service.workingDirectory,
    stdoutPath: service.stdoutPath,
    stderrPath: service.stderrPath,
    domain: "system",
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
    brokerPeer: { uid: input.brokerPeer.uid, ...(input.brokerPeer.gid === undefined ? {} : { gid: input.brokerPeer.gid }) },
    sourceRevision: input.sourceRevision,
    contractVersion: input.contractVersion,
    policyVersion: input.policyVersion,
    ...(expectedPreviousSourceRevision === undefined ? {} : { expectedPreviousSourceRevision }),
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
    enabledCapabilities: [],
    adapterAvailable: false
  };
  return plan;
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
  const currentUid = process.getuid?.();
  if (options.ownerUid !== 0 || currentUid !== 0) {
    fail("INVALID_PEER_IDENTITY", "privileged helper plist apply requires root ownership");
  }
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
      (readback.pid !== null && (!Number.isSafeInteger(readback.pid) || readback.pid < 1))) {
    fail("INVALID_READBACK", "privileged helper readback identity is malformed");
  }
  if (readback.launchd === null || typeof readback.launchd !== "object" ||
      readback.launchd.label !== plan.launchd.label || readback.launchd.program !== plan.launchd.program ||
      readback.launchd.workingDirectory !== plan.launchd.workingDirectory ||
      readback.launchd.stdoutPath !== plan.launchd.stdoutPath || readback.launchd.stderrPath !== plan.launchd.stderrPath ||
      readback.launchd.domain !== "system" || readback.launchd.runsAsRoot !== true ||
      readback.launchd.usesEnvironmentVariables !== false || readback.launchd.usesShell !== false ||
      readback.launchd.runAtLoad !== plan.launchd.runAtLoad || readback.launchd.keepAlive !== plan.launchd.keepAlive ||
      readback.launchd.throttleIntervalSeconds !== plan.launchd.throttleIntervalSeconds) {
    fail("SERVICE_MISMATCH", "privileged helper launchd readback does not match the plan");
  }
  if (readback.helper === null || typeof readback.helper !== "object" ||
      readback.helper.component !== "mac-operator-privileged-helper" || readback.helper.state !== "running" ||
      readback.helper.runtimeState !== "running" || readback.helper.nativeTransportRequired !== true ||
      readback.helper.adapterAvailable !== false || readback.helper.helperSocketPath !== plan.helperSocketPath ||
      readback.helper.brokerSocketPath !== plan.brokerSocketPath || readback.helper.brokerPeerUid !== plan.brokerPeer.uid ||
      readback.helper.brokerPeerGid !== (plan.brokerPeer.gid ?? null) ||
      readback.helper.sourceRevision !== plan.sourceRevision || readback.helper.contractVersion !== plan.contractVersion ||
      readback.helper.policyVersion !== plan.policyVersion || !Array.isArray(readback.helper.enabledCapabilities) ||
      readback.helper.enabledCapabilities.length !== 0) {
    fail("SERVICE_MISMATCH", "privileged helper runtime readback does not match the plan");
  }
  try {
    validateCodeSignatureReadback(plan.signature, readback.signature, plan.signedArtifactPath);
  } catch {
    fail("SIGNATURE_MISMATCH", "privileged helper code signature readback does not match the plan");
  }
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
      value.identifier !== HELPER_LABEL || (value.teamIdentifier !== undefined && !/^[A-Z0-9]{5,32}$/u.test(value.teamIdentifier)) ||
      (value.cdHash !== undefined && !/^[a-f0-9]{20,64}$/u.test(value.cdHash))) {
    fail("INVALID_SIGNATURE", "privileged helper code signature expectation is invalid");
  }
  return { identifier: value.identifier, ...(value.teamIdentifier === undefined ? {} : { teamIdentifier: value.teamIdentifier }), ...(value.cdHash === undefined ? {} : { cdHash: value.cdHash }) };
}

function normalizePreviousRevision(value: string | undefined, operation: PrivilegedHelperPackageOperation): string | undefined {
  if (operation === "install") {
    if (value !== undefined) fail("INVALID_REVISION", "install cannot provide a previous source revision");
    return undefined;
  }
  if (value === undefined || !REVISION_PATTERN.test(value)) fail("INVALID_REVISION", "upgrade, rollback, and uninstall require an exact previous source revision");
  return value;
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

function fail(code: PrivilegedHelperPackageErrorCode, message: string): never {
  throw new PrivilegedHelperPackageError(code, message);
}
