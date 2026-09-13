import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import type { CodeSignatureCommandSpec, CodeSignatureExpectation, CodeSignatureReadback, LaunchdCommandSpec } from "./macos-install-plan.js";
import { validateCodeSignatureReadback } from "./macos-install-plan.js";

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
  | "INVALID_READBACK";

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
