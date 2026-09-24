import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import {
  buildMacOsNotarizationAssessmentCommand,
  type MacOsNotarizationAssessmentCommand
} from "./macos-notarization.js";
import type {
  CodeSignatureCommandSpec,
  CodeSignatureExpectation,
  LaunchdCommandSpec
} from "./macos-install-plan.js";
import {
  validateRootHelperSnapshotReleaseEvidence,
  type RootHelperSnapshotReleaseEvidence
} from "./root-helper-snapshot-release.js";

const ROOT_HELPER_LABEL = "com.mac-operator.root-helper-snapshot" as const;
const ROOT_HELPER_PLIST_PATH = "/Library/LaunchDaemons/com.mac-operator.root-helper-snapshot.plist" as const;
const LAUNCHCTL_PATH = "/bin/launchctl" as const;
const CODESIGN_PATH = "/usr/bin/codesign" as const;
const COMMAND_TIMEOUT_MS = 5_000 as const;
const COMMAND_OUTPUT_CAP_BYTES = 131_072 as const;
const MAX_ARGUMENT_BYTES = 4_096 as const;
const MAX_ARGUMENT_TOTAL_BYTES = 64 * 1_024;
const REVISION_PATTERN = /^[a-f0-9]{40}$/u;
const VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,120}$/u;
const EVIDENCE_REFERENCE_PATTERN = /^[A-Za-z0-9._:/-]{1,256}$/u;
const INTERPRETER_NAMES = new Set([
  "bash", "csh", "env", "node", "osascript", "perl", "python", "python3", "ruby", "sh", "zsh"
]);

export type RootHelperSnapshotPackageOperation = "install" | "upgrade" | "rollback" | "uninstall";

export type RootHelperSnapshotPackageErrorCode =
  | "INVALID_ARGUMENT"
  | "INVALID_ROOT_DOMAIN"
  | "INVALID_PACKAGE_PATH"
  | "INVALID_SOCKET_BOUNDARY"
  | "INVALID_PEER_IDENTITY"
  | "INVALID_REVISION"
  | "INVALID_SIGNATURE"
  | "INVALID_READBACK"
  | "SIGNATURE_MISMATCH"
  | "FILESYSTEM_MISMATCH"
  | "SERVICE_MISMATCH"
  | "CONFIRMATION_REQUIRED"
  | "AUTHORITY_FAILED"
  | "COMMAND_FAILED"
  | "READBACK_FAILED"
  | "RECOVERY_FAILED";

export class RootHelperSnapshotPackageError extends Error {
  readonly code: RootHelperSnapshotPackageErrorCode;

  constructor(code: RootHelperSnapshotPackageErrorCode, message: string) {
    super(message);
    this.name = "RootHelperSnapshotPackageError";
    this.code = code;
  }
}

export interface RootHelperSnapshotLaunchdConfig {
  label: typeof ROOT_HELPER_LABEL;
  program: string;
  programArguments: readonly string[];
  workingDirectory: string;
  stdoutPath: string;
  stderrPath: string;
  runAtLoad?: boolean;
  keepAlive?: boolean;
  throttleIntervalSeconds?: number;
}

export interface RootHelperSnapshotPackagePeerExpectation {
  uid: number;
  gid?: number;
}

export interface RootHelperSnapshotPackagePlanInput {
  operation?: RootHelperSnapshotPackageOperation;
  helperRoot: string;
  plistPath?: string;
  service: RootHelperSnapshotLaunchdConfig;
  signedArtifactPath: string;
  signature: CodeSignatureExpectation;
  /** Release evidence must describe the exact native executable launched by launchd. */
  releaseEvidence: RootHelperSnapshotReleaseEvidence;
  helperKeyConfigPath: string;
  attestationPublicKeyConfigPath: string;
  snapshotRoot: string;
  socketPath: string;
  /** Separate authenticated read-only status endpoint for source-revision readback. */
  statusSocketPath?: string;
  brokerSocketPath: string;
  authoritySocketPath: string;
  reservedSocketPaths?: readonly string[];
  brokerPeer: RootHelperSnapshotPackagePeerExpectation;
  sourceRevision: string;
  contractVersion: string;
  policyVersion: string;
  evidenceRef: string;
  expectedPreviousSourceRevision?: string;
}

export interface RootHelperSnapshotLaunchdReadback {
  label: typeof ROOT_HELPER_LABEL;
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
  runAtLoad: true;
  keepAlive: true;
  throttleIntervalSeconds: number;
}

export interface RootHelperSnapshotFileAction {
  kind: "write-plist" | "restore-plist" | "remove-plist";
  path: typeof ROOT_HELPER_PLIST_PATH;
  ownerUid: 0;
  mode: 0o600;
  backupPath?: string;
  content?: string;
}

export interface RootHelperSnapshotPackagePlan {
  operation: RootHelperSnapshotPackageOperation;
  domain: "system";
  label: typeof ROOT_HELPER_LABEL;
  helperRoot: string;
  plistPath: typeof ROOT_HELPER_PLIST_PATH;
  signedArtifactPath: string;
  signature: CodeSignatureExpectation;
  releaseEvidence: RootHelperSnapshotReleaseEvidence;
  helperKeyConfigPath: string;
  attestationPublicKeyConfigPath: string;
  snapshotRoot: string;
  socketPath: string;
  statusSocketPath: string;
  brokerSocketPath: string;
  authoritySocketPath: string;
  reservedSocketPaths: readonly string[];
  brokerPeer: RootHelperSnapshotPackagePeerExpectation;
  sourceRevision: string;
  contractVersion: string;
  policyVersion: string;
  evidenceRef: string;
  expectedPreviousSourceRevision?: string;
  launchd: RootHelperSnapshotLaunchdReadback;
  renderedPlist: string;
  signatureVerify: CodeSignatureCommandSpec;
  notarizationAssess: MacOsNotarizationAssessmentCommand;
  preflight: readonly string[];
  install: { file: RootHelperSnapshotFileAction; bootstrap: LaunchdCommandSpec };
  rollback: { bootout: LaunchdCommandSpec; file: RootHelperSnapshotFileAction; bootstrap: LaunchdCommandSpec };
  uninstall: { bootout: LaunchdCommandSpec; file: RootHelperSnapshotFileAction };
}

/**
 * Builds a reviewable root-domain LaunchDaemon plan for the snapshot helper.
 * The plan is intentionally non-executing: no plist is written, no launchctl
 * command runs, and no root capability is enabled by this module.
 */
export function buildRootHelperSnapshotPackagePlan(
  input: RootHelperSnapshotPackagePlanInput
): RootHelperSnapshotPackagePlan {
  if (input === null || typeof input !== "object") fail("INVALID_ARGUMENT", "root-helper snapshot package input is malformed");
  const operation = input.operation ?? "install";
  if (!["install", "upgrade", "rollback", "uninstall"].includes(operation)) {
    fail("INVALID_ARGUMENT", "root-helper snapshot package operation is invalid");
  }
  const helperRoot = canonicalPath(input.helperRoot, "root-helper snapshot package root");
  if (helperRoot === "/" || helperRoot === "/Users" || helperRoot.startsWith("/Users/")) {
    fail("INVALID_PACKAGE_PATH", "root-helper snapshot package root must not be user-writable");
  }
  const plistPath = input.plistPath ?? ROOT_HELPER_PLIST_PATH;
  if (plistPath !== ROOT_HELPER_PLIST_PATH) fail("INVALID_ROOT_DOMAIN", "root-helper snapshot must use the exact system LaunchDaemon plist path");
  const service = normalizeService(input.service, helperRoot);
  const signedArtifactPath = canonicalPath(input.signedArtifactPath, "root-helper snapshot signed artifact");
  if (service.program !== signedArtifactPath) {
    fail("INVALID_PACKAGE_PATH", "root-helper snapshot program must equal the signed release artifact");
  }
  const helperKeyConfigPath = canonicalPath(input.helperKeyConfigPath, "root-helper snapshot key config");
  const attestationPublicKeyConfigPath = canonicalPath(input.attestationPublicKeyConfigPath, "root-helper snapshot attestation public-key config");
  const snapshotRoot = canonicalPath(input.snapshotRoot, "root-helper snapshot root");
  const socketPath = canonicalPath(input.socketPath, "root-helper snapshot socket");
  const statusSocketPath = canonicalPath(
    input.statusSocketPath ?? join(dirname(socketPath), `${basename(socketPath)}.status`),
    "root-helper snapshot status socket"
  );
  const brokerSocketPath = canonicalPath(input.brokerSocketPath, "Broker socket");
  const authoritySocketPath = canonicalPath(input.authoritySocketPath, "Broker authority socket");
  const reservedSocketPaths = [...(input.reservedSocketPaths ?? [])].map((path) => canonicalPath(path, "reserved socket"));
  const socketPaths = [socketPath, statusSocketPath, brokerSocketPath, authoritySocketPath, ...reservedSocketPaths];
  if (new Set(socketPaths).size !== socketPaths.length) fail("INVALID_SOCKET_BOUNDARY", "root-helper snapshot sockets must be distinct");
  for (const [path, label] of [
    [signedArtifactPath, "signed artifact"],
    [helperKeyConfigPath, "key config"],
    [attestationPublicKeyConfigPath, "attestation public-key config"],
    [snapshotRoot, "snapshot root"],
    [service.workingDirectory, "working directory"],
    [service.stdoutPath, "stdout path"],
    [service.stderrPath, "stderr path"]
  ] as const) {
    if (!isDescendant(helperRoot, path, label === "working directory")) {
      fail("INVALID_PACKAGE_PATH", `root-helper snapshot ${label} must remain inside the protected package root`);
    }
  }
  validatePeerExpectation(input.brokerPeer);
  validateRevision(input.sourceRevision, "source revision");
  validateVersion(input.contractVersion, "contract version");
  validateVersion(input.policyVersion, "policy version");
  if (typeof input.evidenceRef !== "string" || !EVIDENCE_REFERENCE_PATTERN.test(input.evidenceRef)) {
    fail("INVALID_ARGUMENT", "root-helper snapshot evidence reference is invalid");
  }
  const expectedPreviousSourceRevision = normalizePreviousRevision(input.expectedPreviousSourceRevision, operation);
  const signature = normalizeSignature(input.signature);
  const releaseEvidence = cloneReleaseEvidence(input.releaseEvidence);
  try {
    validateRootHelperSnapshotReleaseEvidence(releaseEvidence, {
      artifactPath: signedArtifactPath,
      helperPath: signedArtifactPath,
      signature
    });
  } catch {
    fail("INVALID_SIGNATURE", "root-helper snapshot requires matching Developer ID notarization evidence");
  }
  const renderedPlist = renderRootHelperSnapshotLaunchdPlist(service);
  const backupPath = `${plistPath}.previous`;
  const launchd = {
    label: ROOT_HELPER_LABEL,
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
    runAtLoad: true,
    keepAlive: true,
    throttleIntervalSeconds: service.throttleIntervalSeconds
  } satisfies RootHelperSnapshotLaunchdReadback;
  const file: RootHelperSnapshotFileAction = { kind: "write-plist", path: ROOT_HELPER_PLIST_PATH, ownerUid: 0, mode: 0o600, content: renderedPlist };
  const restore: RootHelperSnapshotFileAction = { kind: "restore-plist", path: ROOT_HELPER_PLIST_PATH, ownerUid: 0, mode: 0o600, backupPath };
  const remove: RootHelperSnapshotFileAction = { kind: "remove-plist", path: ROOT_HELPER_PLIST_PATH, ownerUid: 0, mode: 0o600 };
  return {
    operation,
    domain: "system",
    label: ROOT_HELPER_LABEL,
    helperRoot,
    plistPath: ROOT_HELPER_PLIST_PATH,
    signedArtifactPath,
    signature,
    releaseEvidence,
    helperKeyConfigPath,
    attestationPublicKeyConfigPath,
    snapshotRoot,
    socketPath,
    statusSocketPath,
    brokerSocketPath,
    authoritySocketPath,
    reservedSocketPaths: Object.freeze(reservedSocketPaths),
    brokerPeer: { uid: input.brokerPeer.uid, ...(input.brokerPeer.gid === undefined ? {} : { gid: input.brokerPeer.gid }) },
    sourceRevision: input.sourceRevision,
    contractVersion: input.contractVersion,
    policyVersion: input.policyVersion,
    evidenceRef: input.evidenceRef,
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
    notarizationAssess: buildMacOsNotarizationAssessmentCommand(signedArtifactPath),
    preflight: [
      "verify the native helper artifact is Developer ID signed with the exact root-helper identifier before any root-domain write",
      "verify Gatekeeper accepts the native helper artifact as notarized Developer ID code before any root-domain write",
      "verify package root, key config, snapshot root, socket parents, executable, and logs are root-owned regular paths with no symlinks or group/other writes",
      "verify the attestation public-key config is protected, revisioned, digest-bound, and contains only the trusted Ed25519 public key set",
      "verify the Broker peer UID/GID and native PID/start-time identity are captured before accepting a snapshot request",
      "verify the root-helper snapshot, root-helper status, Broker, and Broker authority sockets are distinct from every reserved socket",
      "verify host evidence is independently accepted for root-owned private snapshots, immutable selection, close-on-exec, and native peer/HMAC authentication",
      "verify a supported production sandbox mechanism and native Ed25519 attestation verification are independently evidenced before advertising capability",
      operation === "install" ? "verify the exact root-helper snapshot LaunchDaemon is absent before installation" :
        operation === "uninstall" ? "verify the exact root-helper snapshot LaunchDaemon identity before uninstall" :
          `verify the existing root-helper snapshot source revision matches ${expectedPreviousSourceRevision}`,
      "never expose the root-helper snapshot service as an MCP tool or enable public task scope from package installation alone"
    ],
    install: { file, bootstrap: launchctlCommand(["bootstrap", "system", ROOT_HELPER_PLIST_PATH]) },
    rollback: {
      bootout: launchctlCommand(["bootout", `system/${ROOT_HELPER_LABEL}`]),
      file: restore,
      bootstrap: launchctlCommand(["bootstrap", "system", ROOT_HELPER_PLIST_PATH])
    },
    uninstall: { bootout: launchctlCommand(["bootout", `system/${ROOT_HELPER_LABEL}`]), file: remove }
  };
}

export function renderRootHelperSnapshotLaunchdPlist(config: RootHelperSnapshotLaunchdConfig): string {
  const normalized = normalizeService(config, dirname(config.program), false);
  const argumentsXml = normalized.programArguments.map((argument) => `      <string>${escapeXml(argument)}</string>`).join("\n");
  return [
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">",
    "<plist version=\"1.0\">",
    "  <dict>",
    `    <key>Label</key><string>${escapeXml(ROOT_HELPER_LABEL)}</string>`,
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

function normalizeService(config: RootHelperSnapshotLaunchdConfig, helperRoot: string, enforceRoot = true): Required<RootHelperSnapshotLaunchdConfig> {
  if (config === null || typeof config !== "object" || config.label !== ROOT_HELPER_LABEL) {
    fail("INVALID_ARGUMENT", "root-helper snapshot LaunchDaemon label is invalid");
  }
  const program = canonicalPath(config.program, "root-helper snapshot program");
  if (enforceRoot && !isDescendant(helperRoot, program, false)) fail("INVALID_PACKAGE_PATH", "root-helper snapshot program must remain inside the package root");
  if (INTERPRETER_NAMES.has(basename(program).toLowerCase()) || /\.(?:c|m)?js|\.sh|\.command$/iu.test(program)) {
    fail("INVALID_PACKAGE_PATH", "root-helper snapshot program must be a signed native executable");
  }
  if (!Array.isArray(config.programArguments) || config.programArguments.length < 1 || config.programArguments[0] !== program) {
    fail("INVALID_PACKAGE_PATH", "root-helper snapshot ProgramArguments must begin with the native helper executable");
  }
  let totalBytes = 0;
  for (const argument of config.programArguments) {
    if (typeof argument !== "string" || argument.length === 0 || argument.includes("\0") || argument.includes("\n") || Buffer.byteLength(argument, "utf8") > MAX_ARGUMENT_BYTES) {
      fail("INVALID_ARGUMENT", "root-helper snapshot ProgramArguments contains an invalid value");
    }
    totalBytes += Buffer.byteLength(argument, "utf8");
  }
  if (totalBytes > MAX_ARGUMENT_TOTAL_BYTES) fail("INVALID_ARGUMENT", "root-helper snapshot ProgramArguments is too large");
  const workingDirectory = canonicalPath(config.workingDirectory, "root-helper snapshot working directory");
  const stdoutPath = canonicalPath(config.stdoutPath, "root-helper snapshot stdout path");
  const stderrPath = canonicalPath(config.stderrPath, "root-helper snapshot stderr path");
  if (enforceRoot && (!isDescendant(helperRoot, workingDirectory, true) || !isDescendant(helperRoot, stdoutPath, false) || !isDescendant(helperRoot, stderrPath, false))) {
    fail("INVALID_PACKAGE_PATH", "root-helper snapshot working directory and logs must remain inside the package root");
  }
  if (stdoutPath === stderrPath) fail("INVALID_PACKAGE_PATH", "root-helper snapshot stdout and stderr paths must differ");
  const runAtLoad = config.runAtLoad ?? true;
  const keepAlive = config.keepAlive ?? true;
  const throttleIntervalSeconds = config.throttleIntervalSeconds ?? 5;
  if (runAtLoad !== true || keepAlive !== true || !Number.isSafeInteger(throttleIntervalSeconds) || throttleIntervalSeconds < 1 || throttleIntervalSeconds > 3_600) {
    fail("INVALID_ARGUMENT", "root-helper snapshot LaunchDaemon lifecycle must be enabled and bounded");
  }
  return { ...config, program, programArguments: [...config.programArguments], workingDirectory, stdoutPath, stderrPath, runAtLoad, keepAlive, throttleIntervalSeconds };
}

function validatePeerExpectation(value: RootHelperSnapshotPackagePeerExpectation): void {
  if (value === null || typeof value !== "object" || !Number.isSafeInteger(value.uid) || value.uid < 1 || value.uid > 2_147_483_647 ||
      (value.gid !== undefined && (!Number.isSafeInteger(value.gid) || value.gid < 0 || value.gid > 2_147_483_647))) {
    fail("INVALID_PEER_IDENTITY", "root-helper snapshot Broker peer identity is invalid");
  }
}

function normalizeSignature(value: CodeSignatureExpectation): CodeSignatureExpectation {
  if (value === null || typeof value !== "object" || typeof value.identifier !== "string" || value.identifier !== ROOT_HELPER_LABEL ||
      typeof value.teamIdentifier !== "string" || !/^[A-Z0-9]{10}$/u.test(value.teamIdentifier) || typeof value.cdHash !== "string" ||
      !/^[a-f0-9]{20,64}$/u.test(value.cdHash)) {
    fail("INVALID_SIGNATURE", "root-helper snapshot requires a Developer ID team identifier and CDHash");
  }
  return { identifier: value.identifier, teamIdentifier: value.teamIdentifier, cdHash: value.cdHash };
}

function cloneReleaseEvidence(value: RootHelperSnapshotReleaseEvidence): RootHelperSnapshotReleaseEvidence {
  const clone: RootHelperSnapshotReleaseEvidence = {
    artifact: { ...value.artifact },
    signature: { ...value.signature },
    notarization: { ...value.notarization },
    policy: value.policy
  };
  Object.freeze(clone.artifact);
  Object.freeze(clone.signature);
  Object.freeze(clone.notarization);
  return Object.freeze(clone);
}

function normalizePreviousRevision(value: string | undefined, operation: RootHelperSnapshotPackageOperation): string | undefined {
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

function fail(code: RootHelperSnapshotPackageErrorCode, message: string): never {
  throw new RootHelperSnapshotPackageError(code, message);
}
