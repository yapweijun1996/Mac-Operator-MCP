import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import type { BrokerServiceMetadata, BrokerServiceReadback } from "./service-entrypoint.js";
import { normalizeLaunchdServiceConfig, renderLaunchdPlist, type LaunchdServiceConfig, type LaunchdServiceReadback } from "./launchd.js";

const LAUNCHCTL_PATH = "/bin/launchctl";
const SERVICE_TIMEOUT_MS = 5_000;
const SERVICE_OUTPUT_CAP_BYTES = 131_072 as const;
const MAX_PLAN_BYTES = 512 * 1024;
const MAX_CAPABILITIES = 128;

export type MacOsInstallOperation = "install" | "upgrade" | "rollback" | "uninstall";

export type MacOsInstallPlanErrorCode =
  | "INVALID_ARGUMENT"
  | "INVALID_USER_DOMAIN"
  | "INVALID_INSTALL_ROOT"
  | "INVALID_PLIST_PATH"
  | "INVALID_PACKAGE_PATH"
  | "INVALID_SIGNATURE_EXPECTATION"
  | "INVALID_METADATA"
  | "INVALID_READBACK"
  | "SIGNATURE_MISMATCH"
  | "SERVICE_MISMATCH";

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
  signedArtifactPath: string;
  enabledCapabilities?: readonly string[];
  expectedPreviousSourceRevision?: string;
}

export interface MacOsInstallPlan {
  operation: MacOsInstallOperation;
  domain: string;
  label: string;
  userHome: string;
  installRoot: string;
  plistPath: string;
  backupPath: string;
  metadata: BrokerServiceMetadata;
  signature: CodeSignatureExpectation;
  signedArtifactPath: string;
  enabledCapabilities: readonly string[];
  expectedPreviousSourceRevision?: string;
  launchd: LaunchdServiceReadback;
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

export interface MacOsInstallReadback {
  domain: string;
  label: string;
  plistPath: string;
  pid: number | null;
  launchd: LaunchdServiceReadback;
  broker: BrokerServiceReadback;
  signature: CodeSignatureReadback;
}

export interface ExistingServiceReadback {
  present: boolean;
  sourceRevision: string | null;
}

/**
 * Builds a reviewable, non-executing LaunchAgent installation plan.
 *
 * The plan contains only fixed argv and explicit file actions. It never calls
 * launchctl, writes a plist, signs code, or changes launchd state.
 */
export function buildMacOsInstallPlan(input: MacOsInstallPlanInput): MacOsInstallPlan {
  if (input === null || typeof input !== "object") fail("INVALID_ARGUMENT", "macOS install plan input is malformed");
  const operation = input.operation ?? "install";
  if (!["install", "upgrade", "rollback", "uninstall"].includes(operation)) {
    fail("INVALID_ARGUMENT", "macOS install operation is invalid");
  }
  if (!Number.isSafeInteger(input.uid) || input.uid < 1 || input.uid > 2_147_483_647) {
    fail("INVALID_USER_DOMAIN", "a positive non-root launchd uid is required");
  }
  const service = normalizeLaunchdServiceConfig(input.service);
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
  const metadata = normalizeMetadata(input.metadata);
  const signature = normalizeSignatureExpectation(input.signature);
  const expectedPreviousSourceRevision = normalizePreviousRevision(input.expectedPreviousSourceRevision, operation);
  const renderedPlist = renderLaunchdPlist(service);
  if (Buffer.byteLength(renderedPlist, "utf8") > MAX_PLAN_BYTES) {
    fail("INVALID_ARGUMENT", "rendered launchd plist exceeds the plan budget");
  }
  const domain = `gui/${String(input.uid)}`;
  const backupPath = `${plistPath}.previous`;
  const signatureVerify = codesignVerifyCommand(signedArtifactPath);
  const bootstrap = launchctlCommand(["bootstrap", domain, plistPath]);
  const bootout = launchctlCommand(["bootout", `${domain}/${service.label}`]);
  const file = { kind: "write-plist", path: plistPath, mode: 0o600, content: renderedPlist } as const;
  const restore = { kind: "restore-plist", path: plistPath, mode: 0o600, backupPath } as const;
  const remove = { kind: "remove-plist", path: plistPath, mode: 0o600 } as const;
  const launchd = {
    label: service.label,
    program: service.program,
    workingDirectory: service.workingDirectory,
    stdoutPath: service.stdoutPath,
    stderrPath: service.stderrPath,
    runsAsUnprivilegedUser: true,
    usesEnvironmentVariables: false,
    usesShell: false,
    runAtLoad: service.runAtLoad,
    keepAlive: service.keepAlive,
    throttleIntervalSeconds: service.throttleIntervalSeconds
  } satisfies LaunchdServiceReadback;
  return {
    operation,
    domain,
    label: service.label,
    userHome,
    installRoot,
    plistPath,
    backupPath,
    metadata,
    signature,
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
      "write the plist atomically, bootstrap the exact per-user domain, then verify launchd and Broker readback",
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
  const normalizedExpected = normalizeSignatureExpectation(expected);
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
  if (!isRecord(readback) || !isRecord(readback.launchd) || !isRecord(readback.broker) || !isRecord(readback.signature)) {
    fail("INVALID_READBACK", "service readback is malformed");
  }
  const expectedUid = plan.domain.slice("gui/".length);
  if (readback.domain !== plan.domain || readback.label !== plan.label || readback.plistPath !== plan.plistPath ||
      !/^\d+$/.test(expectedUid) || (readback.pid !== null && (!Number.isSafeInteger(readback.pid) || readback.pid < 1))) {
    fail("SERVICE_MISMATCH", "launchd readback does not match the planned per-user service");
  }
  if (readback.launchd.label !== plan.launchd.label || readback.launchd.program !== plan.launchd.program ||
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

export function validateExistingServicePrecondition(plan: MacOsInstallPlan, readback: ExistingServiceReadback): void {
  if (!isRecord(readback) || typeof readback.present !== "boolean" ||
      (readback.sourceRevision !== null && typeof readback.sourceRevision !== "string")) {
    fail("INVALID_READBACK", "existing service readback is malformed");
  }
  if (plan.operation === "install") {
    if (readback.present || readback.sourceRevision !== null) fail("SERVICE_MISMATCH", "install requires an absent existing service");
    return;
  }
  if (!readback.present || readback.sourceRevision !== plan.expectedPreviousSourceRevision) {
    fail("SERVICE_MISMATCH", "existing service does not match the approved operation precondition");
  }
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

function normalizeSignatureExpectation(value: CodeSignatureExpectation): CodeSignatureExpectation {
  if (value === null || typeof value !== "object" || typeof value.identifier !== "string" ||
      !/^[A-Za-z0-9.-]{1,128}$/u.test(value.identifier)) {
    fail("INVALID_SIGNATURE_EXPECTATION", "code signature identifier is invalid");
  }
  if (value.teamIdentifier !== undefined && !/^[A-Z0-9]{10}$/u.test(value.teamIdentifier)) {
    fail("INVALID_SIGNATURE_EXPECTATION", "code signature team identifier is invalid");
  }
  if (value.cdHash !== undefined && !/^[A-Fa-f0-9]{20,64}$/u.test(value.cdHash)) {
    fail("INVALID_SIGNATURE_EXPECTATION", "code signature cdhash is invalid");
  }
  return { identifier: value.identifier, ...(value.teamIdentifier === undefined ? {} : { teamIdentifier: value.teamIdentifier }), ...(value.cdHash === undefined ? {} : { cdHash: value.cdHash }) };
}

function normalizeMetadata(value: BrokerServiceMetadata): BrokerServiceMetadata {
  if (value === null || typeof value !== "object" || value.component !== "mac-operator-broker" ||
      !/^[0-9a-f]{7,64}$/u.test(value.sourceRevision) ||
      !/^v?\d+\.\d+(?:\.\d+)?(?:[-+].*)?$/u.test(value.contractVersion) ||
      !/^\d+\.\d+(?:\.\d+)?(?:[-+].*)?$/u.test(value.policyVersion)) {
    fail("INVALID_METADATA", "Broker service metadata is invalid");
  }
  return { ...value };
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function fail(code: MacOsInstallPlanErrorCode, message: string): never {
  throw new MacOsInstallPlanError(code, message);
}
