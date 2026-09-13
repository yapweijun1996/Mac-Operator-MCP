import { lstat } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { FilesystemInspector, type FilesystemIdentityPrecondition, type FilesystemPathPlan } from "./filesystem-inspector.js";
import type { BrokerServiceMetadata, BrokerServiceReadback } from "./service-entrypoint.js";
import type { PeerProcessIdentity } from "./peer-credentials.js";
import type { LaunchdJobReadback } from "./launchd-readback.js";
import { normalizeLaunchdServiceConfig, renderLaunchdPlist, type LaunchdServiceConfig, type LaunchdServiceReadback } from "./launchd.js";
import { ProcessSupervisor, type ProcessExecutionResult } from "./process-supervisor.js";

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
  entrypointPath: string;
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
  /** PID from launchd, bound to the native start-time identity readback. */
  pid: number;
  processIdentity: PeerProcessIdentity;
  launchd: LaunchdServiceReadback;
  broker: BrokerServiceReadback;
  signature: CodeSignatureReadback;
}

export interface MacOsInstallReadbackSources {
  launchd: LaunchdJobReadback;
  processIdentity: PeerProcessIdentity;
  broker: BrokerServiceReadback;
  signature: CodeSignatureReadback;
}

export interface ExistingServiceReadback {
  present: boolean;
  sourceRevision: string | null;
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

export interface MacOsInstallCommandExecutor {
  run(command: LaunchdCommandSpec | CodeSignatureCommandSpec): Promise<ProcessExecutionResult>;
}

export interface MacOsInstallExecutionOptions extends MacOsPlistApplyOptions {
  /** Host-only confirmation; it must exactly match the planned operation. */
  confirmOperation: MacOsInstallOperation;
  existingService: ExistingServiceReadback;
  commandExecutor?: MacOsInstallCommandExecutor;
  readback: () => Promise<MacOsInstallReadback | null>;
}

export interface MacOsInstallExecutionResult {
  operation: MacOsInstallOperation;
  readback: MacOsInstallReadback | null;
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
    entrypointPath: entrypoint,
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
  if (!isRecord(readback) || !isRecord(readback.launchd) || !isRecord(readback.broker) ||
      !isRecord(readback.signature) || !isRecord(readback.processIdentity)) {
    fail("INVALID_READBACK", "service readback is malformed");
  }
  const expectedUid = plan.domain.slice("gui/".length);
  if (readback.domain !== plan.domain || readback.label !== plan.label || readback.plistPath !== plan.plistPath ||
      !/^\d+$/.test(expectedUid) || !Number.isSafeInteger(readback.pid) || readback.pid < 1 ||
      !Number.isSafeInteger(readback.processIdentity.pid) || readback.processIdentity.pid < 1 ||
      !Number.isSafeInteger(readback.processIdentity.startTimeMicros) || readback.processIdentity.startTimeMicros < 1 ||
      readback.processIdentity.pid !== readback.pid) {
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
      !isRecord(sources.broker) || !isRecord(sources.signature)) {
    fail("INVALID_READBACK", "install readback sources are malformed");
  }
  const expectedServiceId = `${plan.domain}/${plan.label}`;
  const launchd = sources.launchd;
  if (launchd.serviceId !== expectedServiceId || launchd.domain !== plan.domain || launchd.label !== plan.label ||
      launchd.state !== "running" || launchd.type !== "LaunchAgent" || launchd.pid === null ||
      launchd.program !== plan.launchd.program || launchd.plistPath !== plan.plistPath ||
      launchd.pid !== sources.processIdentity.pid) {
    fail("SERVICE_MISMATCH", "launchd readback sources do not match the planned Broker service");
  }
  const readback: MacOsInstallReadback = {
    domain: plan.domain,
    label: plan.label,
    plistPath: plan.plistPath,
    pid: launchd.pid,
    processIdentity: sources.processIdentity,
    launchd: plan.launchd,
    broker: sources.broker,
    signature: sources.signature
  };
  validateMacOsInstallReadback(plan, readback);
  return readback;
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

/**
 * Performs the read-only filesystem portion of installer preflight. Every
 * checked path is lstat'ed twice and must retain its device/inode identity;
 * symlinks, foreign ownership, group/other write access, and unexpected types
 * fail closed. The caller must still use descriptor-relative atomic writes for
 * the actual installation step.
 */
export async function inspectMacOsInstallFilesystem(
  plan: MacOsInstallPlan,
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
  plan: MacOsInstallPlan,
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
 * launchctl command is never treated as success without the caller's final
 * readback. If readback fails after bootstrap, the exact service is booted out
 * and the plist is left for an explicit rollback plan; no uncertain repair can
 * overwrite a target that may have changed under an external actor.
 */
export async function executeMacOsInstallPlan(
  plan: MacOsInstallPlan,
  options: MacOsInstallExecutionOptions
): Promise<MacOsInstallExecutionResult> {
  if (options.confirmOperation !== plan.operation) {
    fail("CONFIRMATION_REQUIRED", "installation requires an explicit matching host operation confirmation");
  }
  validateExistingServicePrecondition(plan, options.existingService);
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
    readback = await options.readback();
    if (plan.operation === "uninstall") {
      if (readback !== null) fail("READBACK_FAILED", "uninstall readback still reports an installed service");
    } else {
      if (readback === null) fail("READBACK_FAILED", "service readback is absent after bootstrap");
      validateMacOsInstallReadback(plan, readback);
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

function createInstallInspector(plan: MacOsInstallPlan): FilesystemInspector {
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
