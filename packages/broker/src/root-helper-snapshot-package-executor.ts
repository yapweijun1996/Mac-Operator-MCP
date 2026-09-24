import { createHash, randomBytes } from "node:crypto";
import { lstat } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { FilesystemInspector, type FilesystemIdentityPrecondition } from "./filesystem-inspector.js";
import {
  RootHelperSnapshotPackageError,
  type RootHelperSnapshotPackagePlan,
  type RootHelperSnapshotPackageOperation
} from "./root-helper-snapshot-package.js";
import {
  assertRootHelperSnapshotReleaseArtifactStable,
  validateRootHelperSnapshotReleaseEvidence,
  type RootHelperSnapshotReleaseEvidence
} from "./root-helper-snapshot-release.js";
import type { MacOsInstallCommandExecutor } from "./macos-install-plan.js";
import { ProcessSupervisor, type ProcessExecutionResult } from "./process-supervisor.js";
import { LaunchdReadbackError, readLaunchdJobReadback, type LaunchdJobReadback, type LaunchdReadbackExecutor } from "./launchd-readback.js";
import {
  capturePeerProcessCredentials,
  capturePeerProcessIdentity,
  type PeerCredentials,
  type PeerProcessIdentity
} from "./peer-credentials.js";
import {
  readPrivilegedHelperSocketReadback,
  type PrivilegedHelperSocketReadback
} from "./privileged-helper-package.js";

const ROOT_UID = 0;
const ROOT_FILESYSTEM_ROOT = "/Library";
const ROOT_HELPER_SERVICE_ID = "system/com.mac-operator.root-helper-snapshot";
const PLIST_MAX_BYTES = 1_048_576;

export interface RootHelperSnapshotPackageExistingServiceReadback {
  present: boolean;
  sourceRevision: string | null;
}

export interface RootHelperSnapshotPackagePlistReadback {
  path: string;
  bytes: number;
  sha256: string;
  device: string;
  inode: string;
}

/** Independent non-socket sources required for a successful installed-service readback. */
export interface RootHelperSnapshotPackageReadbackSources {
  launchd: LaunchdJobReadback;
  processIdentity: PeerProcessIdentity;
  processUid: number;
  plist: RootHelperSnapshotPackagePlistReadback;
  releaseEvidence: RootHelperSnapshotReleaseEvidence;
}

export interface RootHelperSnapshotPackageSocketReadbacks {
  rootHelperSocket: PrivilegedHelperSocketReadback;
  statusSocket: PrivilegedHelperSocketReadback;
  brokerSocket: PrivilegedHelperSocketReadback;
  authoritySocket: PrivilegedHelperSocketReadback;
}

/** Final readback after the executor has independently sampled all four sockets. */
export interface RootHelperSnapshotPackageReadback extends RootHelperSnapshotPackageReadbackSources, RootHelperSnapshotPackageSocketReadbacks {}

export interface RootHelperSnapshotPackageObserver {
  readLaunchd(serviceId: string): Promise<LaunchdJobReadback>;
  readSourceRevision?: () => Promise<string> | string;
}

/** Independent host-owned sources used for final root-helper readback. */
export interface RootHelperSnapshotPackageReadbackObserver {
  readLaunchd(serviceId: string): Promise<LaunchdJobReadback>;
  readProcessIdentity(pid: number): Promise<PeerProcessIdentity> | PeerProcessIdentity;
  readProcessCredentials(pid: number): Promise<PeerCredentials> | PeerCredentials;
  readPlist(plan: RootHelperSnapshotPackagePlan): Promise<RootHelperSnapshotPackagePlistReadback>;
  readReleaseEvidence(): Promise<RootHelperSnapshotReleaseEvidence>;
}

export interface RootHelperSnapshotPackageHostObserverOptions {
  /** Release evidence must come from an owner-controlled release source. */
  readReleaseEvidence: () => Promise<RootHelperSnapshotReleaseEvidence>;
  launchdExecutor?: LaunchdReadbackExecutor;
  processIdentityReader?: (pid: number) => PeerProcessIdentity;
  processCredentialsReader?: (pid: number) => PeerCredentials;
  readPlist?: (plan: RootHelperSnapshotPackagePlan) => Promise<RootHelperSnapshotPackagePlistReadback>;
}

export interface RootHelperSnapshotPackageExecutionOptions {
  /** Host-only confirmation; it must exactly match the plan operation. */
  confirmOperation: RootHelperSnapshotPackageOperation;
  /** Optional caller hint retained only for a precondition consistency check. */
  existingService?: RootHelperSnapshotPackageExistingServiceReadback;
  /** Host-owned service source sampled twice immediately before mutation. */
  readExistingService: () => Promise<RootHelperSnapshotPackageExistingServiceReadback> | RootHelperSnapshotPackageExistingServiceReadback;
  /** Root-only filesystem authority. The default native inspector is used in production. */
  inspector?: FilesystemInspector;
  commandExecutor?: MacOsInstallCommandExecutor;
  /** Test-only or legacy absence source; production installs should use readbackObserver. */
  readback?: () => Promise<RootHelperSnapshotPackageReadbackSources | null>;
  /** Production-shaped observer for independently sampled non-socket and socket sources. */
  readbackObserver?: RootHelperSnapshotPackageReadbackObserver;
}

export interface RootHelperSnapshotPackagePlistApplyResult {
  operation: RootHelperSnapshotPackageOperation;
  path: string;
  bytesWritten: number;
  sha256: string | null;
  created: boolean;
  backupPath: string | null;
  backupSha256: string | null;
  device: string;
  inode: string;
}

export interface RootHelperSnapshotPackageExecutionResult {
  operation: RootHelperSnapshotPackageOperation;
  readback: RootHelperSnapshotPackageReadback | null;
  plist: RootHelperSnapshotPackagePlistApplyResult;
}

/**
 * Executes a reviewed root-domain package plan. This function is deliberately
 * host-only and root-gated; it is not an MCP handler and it never accepts a
 * caller-selected command, path, environment, or service label.
 */
export async function executeRootHelperSnapshotPackagePlan(
  plan: RootHelperSnapshotPackagePlan,
  options: RootHelperSnapshotPackageExecutionOptions
): Promise<RootHelperSnapshotPackageExecutionResult> {
  if (options === null || typeof options !== "object") {
    fail("INVALID_ARGUMENT", "root-helper package execution options are malformed");
  }
  if (options.confirmOperation !== plan.operation) {
    fail("CONFIRMATION_REQUIRED", "root-helper installation requires an explicit matching host operation confirmation");
  }
  if (typeof options.readback !== "function" && options.readbackObserver === undefined) {
    fail("INVALID_ARGUMENT", "root-helper installation requires an independent host readback observer");
  }
  if (plan.operation === "uninstall" && options.readbackObserver !== undefined) {
    fail("INVALID_ARGUMENT", "root-helper uninstall requires an absence readback source");
  }
  if (typeof process.getuid !== "function" || process.getuid() !== ROOT_UID) {
    fail("AUTHORITY_FAILED", "root-helper package mutation requires a root host process");
  }
  const existingService = await readStableExistingService(options.readExistingService);
  if (options.existingService !== undefined) {
    validateExistingService(options.existingService);
    if (!sameExistingService(options.existingService, existingService)) {
      fail("SERVICE_MISMATCH", "caller existing-service hint does not match the host precondition readback");
    }
  }
  validateExistingServicePrecondition(plan, existingService);
  const executor = options.commandExecutor ?? new ProcessSupervisor({ allowedEnvironmentKeys: [] });
  if (plan.operation !== "uninstall") {
    await runCommand(executor, plan.signatureVerify, "root-helper code signature verification failed");
    await runCommand(executor, plan.notarizationAssess, "root-helper notarization assessment failed");
  }

  let bootedOut = false;
  let plistApplied = false;
  let bootstrapped = false;
  let plist: RootHelperSnapshotPackagePlistApplyResult;
  try {
    if (plan.operation !== "install") {
      await runCommand(executor, plan.rollback.bootout, "existing root-helper service could not be stopped");
      bootedOut = true;
    }
    plist = await applyRootHelperSnapshotPlistPlan(plan, options.inspector === undefined ? {} : { inspector: options.inspector });
    plistApplied = true;
    if (plan.operation !== "uninstall") {
      await runCommand(executor, plan.install.bootstrap, "root-helper LaunchDaemon could not be bootstrapped");
      bootstrapped = true;
    }
  } catch (error) {
    if (bootedOut && !plistApplied) {
      try {
        await runCommand(executor, plan.install.bootstrap, "previous root-helper service could not be restored");
      } catch (restoreError) {
        throw new AggregateError([error, restoreError], "root-helper installation failed and service recovery also failed");
      }
    }
    throw error;
  }

  try {
    if (plan.operation !== "uninstall" && options.readbackObserver !== undefined) {
      const readback = await observeRootHelperSnapshotPackageReadback(plan, options.readbackObserver);
      return { operation: plan.operation, readback, plist };
    }
    const sources = await options.readback!();
    if (plan.operation === "uninstall") {
      if (sources !== null) fail("READBACK_FAILED", "root-helper uninstall readback still reports an installed service");
      return { operation: plan.operation, readback: null, plist };
    }
    if (sources === null) fail("READBACK_FAILED", "root-helper service readback is absent after bootstrap");
    const sockets = await readRootHelperSnapshotPackageSocketReadbacks(plan);
    const readback = composeRootHelperSnapshotPackageReadback(plan, sources, sockets);
    await validateRootHelperSnapshotPackageReadback(plan, readback);
    return { operation: plan.operation, readback, plist };
  } catch (error) {
    if (bootstrapped) {
      try {
        await runCommand(executor, plan.rollback.bootout, "mismatched root-helper service could not be stopped");
      } catch (stopError) {
        throw new AggregateError([error, stopError], "root-helper readback failed and service recovery also failed");
      }
    }
    if (error instanceof RootHelperSnapshotPackageError) throw error;
    fail("READBACK_FAILED", "root-helper service readback failed after installation");
  }
}

/** Applies only the exact root-helper plist file action; launchd is untouched. */
export async function applyRootHelperSnapshotPlistPlan(
  plan: RootHelperSnapshotPackagePlan,
  options: { inspector?: FilesystemInspector } = {}
): Promise<RootHelperSnapshotPackagePlistApplyResult> {
  const inspector = options.inspector ?? createRootHelperPackageInspector();
  await inspectRootHelperSnapshotPackageFilesystem(plan);
  const targetPlan = inspector.planPath(plan.plistPath, "write");
  const current = optionalStat(inspector, targetPlan);
  if (plan.operation === "install") {
    if (current !== undefined) fail("FILESYSTEM_MISMATCH", "root-helper install requires an absent plist");
    const result = inspector.writePlanned(
      targetPlan,
      Buffer.from(plan.renderedPlist, "utf8"),
      undefined,
      true,
      temporaryName("root-helper-plist"),
      identity(false)
    );
    return toApplyResult(plan.operation, result, null, null);
  }
  if (current === undefined) fail("FILESYSTEM_MISMATCH", "root-helper upgrade, rollback, or uninstall requires an existing plist");
  const currentIdentity = identityFromMetadata(current);
  if (plan.operation === "uninstall") {
    const removed = inspector.unlinkPlanned(targetPlan, currentIdentity);
    if (optionalStat(inspector, targetPlan) !== undefined) fail("FILESYSTEM_MISMATCH", "root-helper uninstall did not remove the plist");
    return {
      operation: plan.operation,
      path: removed.path,
      bytesWritten: 0,
      sha256: null,
      created: false,
      backupPath: null,
      backupSha256: null,
      device: removed.device,
      inode: removed.inode
    };
  }
  const backupPath = plan.rollback.file.backupPath;
  if (typeof backupPath !== "string") fail("FILESYSTEM_MISMATCH", "root-helper rollback backup path is missing");
  const backupPlan = inspector.planPath(backupPath, "write");
  if (plan.operation === "upgrade") {
    const original = readPlist(inspector, targetPlan);
    const previousBackup = optionalStat(inspector, backupPlan);
    const backup = inspector.writePlanned(
      backupPlan,
      original.content,
      undefined,
      false,
      temporaryName("root-helper-backup"),
      previousBackup === undefined ? identity(false) : identityFromMetadata(previousBackup)
    );
    try {
      const result = inspector.writePlanned(
        targetPlan,
        Buffer.from(plan.renderedPlist, "utf8"),
        undefined,
        false,
        temporaryName("root-helper-plist"),
        currentIdentity
      );
      return toApplyResult(plan.operation, result, backupPath, backup.sha256);
    } catch (error) {
      try {
        inspector.writePlanned(
          targetPlan,
          original.content,
          undefined,
          false,
          temporaryName("root-helper-restore"),
          currentIdentity
        );
      } catch (restoreError) {
        throw new AggregateError([error, restoreError], "root-helper upgrade failed and plist recovery also failed");
      }
      throw error;
    }
  }
  const backup = optionalStat(inspector, backupPlan);
  if (backup === undefined) fail("FILESYSTEM_MISMATCH", "root-helper rollback backup is unavailable");
  const backupContent = readPlist(inspector, backupPlan).content;
  const result = inspector.writePlanned(
    targetPlan,
    backupContent,
    undefined,
    false,
    temporaryName("root-helper-rollback"),
    currentIdentity
  );
  return toApplyResult(plan.operation, result, backupPath, null);
}

/** Read only the exact package plist and verify its path-safe identity. */
export function readRootHelperSnapshotPlist(
  plan: RootHelperSnapshotPackagePlan,
  inspector = createRootHelperPackageInspector()
): RootHelperSnapshotPackagePlistReadback {
  const targetPlan = inspector.planPath(plan.plistPath, "content_read");
  const metadata = inspector.statPlanned(targetPlan, false);
  if (metadata.type !== "file" || metadata.isSymlink) fail("FILESYSTEM_MISMATCH", "root-helper plist is not a regular file");
  const read = inspector.readPlanned(targetPlan, 0, PLIST_MAX_BYTES);
  if (read.truncated) fail("FILESYSTEM_MISMATCH", "root-helper plist exceeds its bounded size");
  return {
    path: read.path,
    bytes: read.sizeBytes,
    sha256: createHash("sha256").update(read.content).digest("hex"),
    device: read.device,
    inode: read.inode
  };
}

export async function validateRootHelperSnapshotPackageReadback(
  plan: RootHelperSnapshotPackagePlan,
  readback: RootHelperSnapshotPackageReadback
): Promise<void> {
  if (readback === null || typeof readback !== "object") fail("INVALID_READBACK", "root-helper package readback is malformed");
  const launchd = readback.launchd;
  const serviceId = ROOT_HELPER_SERVICE_ID;
  if (launchd.serviceId !== serviceId || launchd.domain !== "system" || launchd.label !== plan.label ||
      launchd.state !== "running" || launchd.type !== "LaunchDaemon" || launchd.pid === null ||
      launchd.program !== plan.launchd.program || !sameStrings(launchd.arguments, plan.launchd.programArguments) ||
      launchd.plistPath !== plan.plistPath || launchd.truncated !== false) {
    fail("SERVICE_MISMATCH", "root-helper LaunchDaemon readback does not match the package plan");
  }
  if (!Number.isSafeInteger(readback.processIdentity.pid) || readback.processIdentity.pid < 1 ||
      !Number.isSafeInteger(readback.processIdentity.startTimeMicros) || readback.processIdentity.startTimeMicros < 1 ||
      readback.processIdentity.pid !== launchd.pid || readback.processUid !== ROOT_UID) {
    fail("SERVICE_MISMATCH", "root-helper process identity readback is not root-owned and stable");
  }
  const expectedBytes = Buffer.byteLength(plan.renderedPlist, "utf8");
  const expectedSha256 = createHash("sha256").update(plan.renderedPlist, "utf8").digest("hex");
  if (readback.plist.path !== plan.plistPath || readback.plist.bytes !== expectedBytes ||
      readback.plist.sha256 !== expectedSha256 || !/^[0-9]+$/u.test(readback.plist.device) ||
      !/^[0-9]+$/u.test(readback.plist.inode)) {
    fail("FILESYSTEM_MISMATCH", "root-helper plist readback does not match the rendered plan");
  }
  validateRootHelperSocketReadback(readback.rootHelperSocket, plan.socketPath, 0, 0, "root-helper");
  validateRootHelperSocketReadback(readback.statusSocket, plan.statusSocketPath, 0, 0, "root-helper status");
  validateRootHelperSocketReadback(
    readback.brokerSocket,
    plan.brokerSocketPath,
    plan.brokerPeer.uid,
    plan.brokerPeer.gid,
    "Broker"
  );
  validateRootHelperSocketReadback(
    readback.authoritySocket,
    plan.authoritySocketPath,
    plan.brokerPeer.uid,
    plan.brokerPeer.gid,
    "root-helper authority"
  );
  try {
    validateRootHelperSnapshotReleaseEvidence(readback.releaseEvidence, {
      artifactPath: plan.signedArtifactPath,
      helperPath: plan.signedArtifactPath,
      signature: plan.signature
    });
    if (!sameReleaseArtifact(plan.releaseEvidence, readback.releaseEvidence)) {
      fail("SIGNATURE_MISMATCH", "root-helper release evidence changed after installation");
    }
    await assertRootHelperSnapshotReleaseArtifactStable(readback.releaseEvidence);
  } catch (error) {
    if (error instanceof RootHelperSnapshotPackageError) throw error;
    fail("SIGNATURE_MISMATCH", "root-helper release readback is not stable");
  }
}

/**
 * Composes root-helper readiness only from separately observed service,
 * process, plist, socket, and release sources. Socket metadata is never
 * copied from the package plan or inferred from launchd arguments.
 */
export function composeRootHelperSnapshotPackageReadback(
  plan: RootHelperSnapshotPackagePlan,
  sources: RootHelperSnapshotPackageReadbackSources,
  sockets: RootHelperSnapshotPackageSocketReadbacks
): RootHelperSnapshotPackageReadback {
  if (sources === null || typeof sources !== "object" ||
      sources.launchd === null || typeof sources.launchd !== "object" ||
      sources.processIdentity === null || typeof sources.processIdentity !== "object" ||
      sources.plist === null || typeof sources.plist !== "object" ||
      sources.releaseEvidence === null || typeof sources.releaseEvidence !== "object") {
    fail("INVALID_READBACK", "root-helper package readback sources are malformed");
  }
  if (sockets === null || typeof sockets !== "object" ||
      sockets.rootHelperSocket === null || typeof sockets.rootHelperSocket !== "object" ||
      sockets.statusSocket === null || typeof sockets.statusSocket !== "object" ||
      sockets.brokerSocket === null || typeof sockets.brokerSocket !== "object" ||
      sockets.authoritySocket === null || typeof sockets.authoritySocket !== "object") {
    fail("INVALID_READBACK", "root-helper package socket sources are malformed");
  }
  const expectedServiceId = ROOT_HELPER_SERVICE_ID;
  if (sources.launchd.serviceId !== expectedServiceId || sources.launchd.pid === null ||
      sources.launchd.pid !== sources.processIdentity.pid) {
    fail("SERVICE_MISMATCH", "root-helper readback sources do not identify the planned running service");
  }
  const readback: RootHelperSnapshotPackageReadback = {
    launchd: sources.launchd,
    processIdentity: sources.processIdentity,
    processUid: sources.processUid,
    plist: sources.plist,
    rootHelperSocket: sockets.rootHelperSocket,
    statusSocket: sockets.statusSocket,
    brokerSocket: sockets.brokerSocket,
    authoritySocket: sockets.authoritySocket,
    releaseEvidence: sources.releaseEvidence
  };
  return readback;
}

/**
 * Independently samples the four root-helper package endpoints. The executor
 * calls this after launchd bootstrap rather than accepting socket metadata
 * from the generic package readback callback.
 */
export async function readRootHelperSnapshotPackageSocketReadbacks(
  plan: RootHelperSnapshotPackagePlan,
  readSocket: RootHelperSnapshotSocketReader = readRootHelperSnapshotSocketReadback
): Promise<RootHelperSnapshotPackageSocketReadbacks> {
  try {
    const rootHelperSocket = await readSocket(plan.socketPath, 0, 0, "root-helper");
    const statusSocket = await readSocket(plan.statusSocketPath, 0, 0, "root-helper status");
    const brokerSocket = await readSocket(
      plan.brokerSocketPath,
      plan.brokerPeer.uid,
      plan.brokerPeer.gid,
      "Broker"
    );
    const authoritySocket = await readSocket(
      plan.authoritySocketPath,
      plan.brokerPeer.uid,
      plan.brokerPeer.gid,
      "root-helper authority"
    );
    return { rootHelperSocket, statusSocket, brokerSocket, authoritySocket };
  } catch (error) {
    if (error instanceof RootHelperSnapshotPackageError) throw error;
    fail("READBACK_FAILED", "root-helper package socket readback failed");
  }
}

/**
 * Collects non-socket host sources twice and rejects service, process, or
 * plist replacement while the final package readback is being assembled.
 */
export async function collectRootHelperSnapshotPackageReadbackSources(
  plan: RootHelperSnapshotPackagePlan,
  observer: RootHelperSnapshotPackageReadbackObserver
): Promise<RootHelperSnapshotPackageReadbackSources> {
  try {
    if (observer === null || typeof observer !== "object" ||
        typeof observer.readLaunchd !== "function" ||
        typeof observer.readProcessIdentity !== "function" ||
        typeof observer.readProcessCredentials !== "function" ||
        typeof observer.readPlist !== "function" ||
        typeof observer.readReleaseEvidence !== "function") {
      fail("INVALID_READBACK", "root-helper package readback observer is malformed");
    }
    const serviceId = ROOT_HELPER_SERVICE_ID;
    const launchdBefore = await observer.readLaunchd(serviceId);
    if (launchdBefore.pid === null) fail("SERVICE_MISMATCH", "root-helper launchd readback has no running PID");
    const processBefore = await observer.readProcessIdentity(launchdBefore.pid);
    const credentialsBefore = await observer.readProcessCredentials(launchdBefore.pid);
    const plistBefore = await observer.readPlist(plan);
    const releaseEvidence = await observer.readReleaseEvidence();
    const launchdAfter = await observer.readLaunchd(serviceId);
    if (launchdAfter.pid === null || !sameLaunchdIdentity(launchdBefore, launchdAfter)) {
      fail("SERVICE_MISMATCH", "root-helper launchd identity changed during readback");
    }
    const processAfter = await observer.readProcessIdentity(launchdAfter.pid);
    if (!sameProcessIdentity(processBefore, processAfter)) {
      fail("SERVICE_MISMATCH", "root-helper process identity changed during readback");
    }
    const credentialsAfter = await observer.readProcessCredentials(launchdAfter.pid);
    if (credentialsBefore.uid !== credentialsAfter.uid || credentialsBefore.gid !== credentialsAfter.gid ||
        credentialsBefore.pid !== credentialsAfter.pid) {
      fail("SERVICE_MISMATCH", "root-helper process credentials changed during readback");
    }
    const plistAfter = await observer.readPlist(plan);
    if (!samePlistIdentity(plistBefore, plistAfter)) {
      fail("FILESYSTEM_MISMATCH", "root-helper plist identity changed during readback");
    }
    return {
      launchd: launchdAfter,
      processIdentity: processAfter,
      processUid: credentialsAfter.uid,
      plist: plistAfter,
      releaseEvidence
    };
  } catch (error) {
    if (error instanceof RootHelperSnapshotPackageError) throw error;
    fail("READBACK_FAILED", "root-helper package host readback failed");
  }
}

/**
 * Performs the complete production-shaped root-helper readback. All service,
 * process, plist, release, and socket identities come from independent host
 * sources; no package-plan socket metadata is copied into the result.
 */
export async function observeRootHelperSnapshotPackageReadback(
  plan: RootHelperSnapshotPackagePlan,
  observer: RootHelperSnapshotPackageReadbackObserver
): Promise<RootHelperSnapshotPackageReadback> {
  const sources = await collectRootHelperSnapshotPackageReadbackSources(plan, observer);
  const sockets = await readRootHelperSnapshotPackageSocketReadbacks(plan);
  const readback = composeRootHelperSnapshotPackageReadback(plan, sources, sockets);
  await validateRootHelperSnapshotPackageReadback(plan, readback);
  return readback;
}

/** Creates the bounded host observer used by production root-helper apply code. */
export function createRootHelperSnapshotPackageHostObserver(
  plan: RootHelperSnapshotPackagePlan,
  options: RootHelperSnapshotPackageHostObserverOptions
): RootHelperSnapshotPackageReadbackObserver {
  if (options === null || typeof options !== "object" || typeof options.readReleaseEvidence !== "function") {
    fail("INVALID_ARGUMENT", "root-helper host observer requires owner-controlled release evidence");
  }
  return {
    readLaunchd: async (serviceId) => readLaunchdJobReadback(
      serviceId,
      options.launchdExecutor === undefined ? {} : { executor: options.launchdExecutor }
    ),
    readProcessIdentity: (pid) => options.processIdentityReader?.(pid) ?? capturePeerProcessIdentity(pid),
    readProcessCredentials: (pid) => options.processCredentialsReader?.(pid) ?? capturePeerProcessCredentials(pid),
    readPlist: options.readPlist ?? (async (candidate) => readRootHelperSnapshotPlist(candidate)),
    readReleaseEvidence: options.readReleaseEvidence
  };
}

export type RootHelperSnapshotSocketReader = (
  path: string,
  expectedOwnerUid: number,
  expectedOwnerGid: number | undefined,
  label: string
) => Promise<PrivilegedHelperSocketReadback>;

/** Reads one root-helper package socket through the shared stable-socket boundary. */
export async function readRootHelperSnapshotSocketReadback(
  path: string,
  expectedOwnerUid: number,
  expectedOwnerGid: number | undefined,
  label: string
): Promise<PrivilegedHelperSocketReadback> {
  try {
    return await readPrivilegedHelperSocketReadback(path, expectedOwnerUid, expectedOwnerGid, label);
  } catch (error) {
    if (error instanceof RootHelperSnapshotPackageError) throw error;
    fail("READBACK_FAILED", `${label} socket readback failed`);
  }
}

function validateRootHelperSocketReadback(
  readback: PrivilegedHelperSocketReadback,
  expectedPath: string,
  expectedOwnerUid: number,
  expectedOwnerGid: number | undefined,
  label: string
): void {
  if (readback === null || typeof readback !== "object" || readback.path !== expectedPath ||
      !Number.isSafeInteger(readback.ownerUid) || readback.ownerUid !== expectedOwnerUid ||
      !Number.isSafeInteger(readback.ownerGid) || readback.ownerGid < 0 || readback.ownerGid > 2_147_483_647 ||
      (expectedOwnerGid !== undefined && readback.ownerGid !== expectedOwnerGid) ||
      !Number.isSafeInteger(readback.mode) || readback.mode < 0 || readback.mode > 0o777 ||
      (readback.mode & 0o077) !== 0 ||
      !Number.isSafeInteger(readback.device) || readback.device < 0 ||
      !Number.isSafeInteger(readback.inode) || readback.inode < 0) {
    fail("SERVICE_MISMATCH", `${label} socket ownership or identity does not match the plan`);
  }
}

export function createRootHelperSnapshotPackageObserver(
  options: {
    launchdExecutor?: LaunchdReadbackExecutor;
    readSourceRevision?: () => Promise<string> | string;
  } = {}
): RootHelperSnapshotPackageObserver {
  return {
    readLaunchd: (serviceId) => readLaunchdJobReadback(serviceId, options.launchdExecutor === undefined ? {} : { executor: options.launchdExecutor }),
    ...(options.readSourceRevision === undefined ? {} : { readSourceRevision: options.readSourceRevision })
  };
}

export function createRootHelperSnapshotPackageExistingServiceReader(
  plan: RootHelperSnapshotPackagePlan,
  observer: RootHelperSnapshotPackageObserver
): () => Promise<RootHelperSnapshotPackageExistingServiceReadback> {
  if (observer === null || typeof observer !== "object" || typeof observer.readLaunchd !== "function") {
    fail("INVALID_ARGUMENT", "root-helper existing-service observer is malformed");
  }
  if (plan.operation !== "install" && typeof observer.readSourceRevision !== "function") {
    fail("INVALID_ARGUMENT", "root-helper non-install observer requires a source revision reader");
  }
  return async () => {
    let launchd: LaunchdJobReadback;
    try {
      launchd = await observer.readLaunchd(ROOT_HELPER_SERVICE_ID);
    } catch (error) {
      if (error instanceof LaunchdReadbackError && error.code === "UNAVAILABLE") {
        return { present: false, sourceRevision: null };
      }
      fail("READBACK_FAILED", "existing root-helper LaunchDaemon readback failed");
    }
    if (launchd.serviceId !== ROOT_HELPER_SERVICE_ID || launchd.domain !== "system" || launchd.label !== plan.label ||
        launchd.type !== "LaunchDaemon" || launchd.program !== plan.launchd.program ||
        !sameStrings(launchd.arguments ?? [], plan.launchd.programArguments) || launchd.plistPath !== plan.plistPath) {
      fail("SERVICE_MISMATCH", "existing root-helper LaunchDaemon identity does not match the plan");
    }
    if (plan.operation === "install") return { present: true, sourceRevision: null };
    let sourceRevision: string;
    try {
      sourceRevision = await observer.readSourceRevision!();
    } catch {
      fail("READBACK_FAILED", "existing root-helper source revision readback failed");
    }
    if (!/^[0-9a-f]{7,64}$/u.test(sourceRevision)) fail("SERVICE_MISMATCH", "existing root-helper source revision is malformed");
    return { present: true, sourceRevision };
  };
}

async function readStableExistingService(
  reader: () => Promise<RootHelperSnapshotPackageExistingServiceReadback> | RootHelperSnapshotPackageExistingServiceReadback
): Promise<RootHelperSnapshotPackageExistingServiceReadback> {
  if (typeof reader !== "function") fail("INVALID_ARGUMENT", "root-helper existing-service reader is required");
  let first: RootHelperSnapshotPackageExistingServiceReadback;
  let second: RootHelperSnapshotPackageExistingServiceReadback;
  try {
    first = await reader();
    second = await reader();
  } catch {
    fail("READBACK_FAILED", "root-helper existing-service readback failed");
  }
  validateExistingService(first);
  validateExistingService(second);
  if (!sameExistingService(first, second)) fail("SERVICE_MISMATCH", "root-helper existing-service identity changed during preflight");
  return first;
}

function validateExistingService(value: RootHelperSnapshotPackageExistingServiceReadback): void {
  if (value === null || typeof value !== "object" || typeof value.present !== "boolean" ||
      (value.sourceRevision !== null && !/^[0-9a-f]{7,64}$/u.test(value.sourceRevision))) {
    fail("INVALID_READBACK", "root-helper existing-service readback is malformed");
  }
  if (!value.present && value.sourceRevision !== null) fail("INVALID_READBACK", "absent root-helper service has a source revision");
}

function validateExistingServicePrecondition(
  plan: RootHelperSnapshotPackagePlan,
  existing: RootHelperSnapshotPackageExistingServiceReadback
): void {
  if (plan.operation === "install") {
    if (existing.present || existing.sourceRevision !== null) fail("SERVICE_MISMATCH", "root-helper install requires an absent service");
    return;
  }
  if (!existing.present || existing.sourceRevision !== plan.expectedPreviousSourceRevision) {
    fail("SERVICE_MISMATCH", "root-helper existing service does not match the planned previous revision");
  }
}

async function runCommand(
  executor: MacOsInstallCommandExecutor,
  command: Parameters<MacOsInstallCommandExecutor["run"]>[0],
  message: string
): Promise<void> {
  let result: ProcessExecutionResult;
  try {
    result = await executor.run(command);
  } catch {
    fail("COMMAND_FAILED", message);
  }
  if (result.resultClass !== "SUCCEEDED" || result.truncated) fail("COMMAND_FAILED", message);
}

async function inspectRootHelperSnapshotPackageFilesystem(
  plan: RootHelperSnapshotPackagePlan
): Promise<void> {
  const directories = new Set<string>([
    plan.helperRoot,
    plan.snapshotRoot,
    plan.launchd.workingDirectory,
    dirname(plan.launchd.stdoutPath),
    dirname(plan.launchd.stderrPath),
    dirname(plan.plistPath),
    dirname(plan.socketPath),
    dirname(plan.statusSocketPath),
    dirname(plan.brokerSocketPath),
    dirname(plan.authoritySocketPath)
  ]);
  const files = new Set<string>([
    plan.signedArtifactPath,
    plan.helperKeyConfigPath,
    plan.attestationPublicKeyConfigPath
  ]);
  if (plan.operation !== "install") files.add(plan.plistPath);
  for (const path of [...directories, ...files]) {
    for (const ancestor of ancestorsThrough(ROOT_FILESYSTEM_ROOT, dirname(path))) directories.add(ancestor);
  }
  for (const path of [...directories].sort()) await assertPackageEntry(path, "directory");
  for (const path of [...files].sort()) await assertPackageEntry(path, "file");
}

async function assertPackageEntry(path: string, expected: "file" | "directory"): Promise<void> {
  let first;
  let second;
  try {
    first = await lstat(path);
    second = await lstat(path);
  } catch {
    fail("FILESYSTEM_MISMATCH", "root-helper package path is unavailable");
  }
  if (first.dev !== second.dev || first.ino !== second.ino || first.uid !== second.uid || first.mode !== second.mode ||
      (expected === "file" && !first.isFile()) || (expected === "directory" && !first.isDirectory()) ||
      first.isSymbolicLink() || first.uid !== ROOT_UID || (first.mode & 0o022) !== 0) {
    fail("FILESYSTEM_MISMATCH", "root-helper package path ownership, mode, or type is unsafe");
  }
}

function createRootHelperPackageInspector(): FilesystemInspector {
  return new FilesystemInspector([{
    rootId: "root-helper-package",
    path: ROOT_FILESYSTEM_ROOT,
    metadata: true,
    contentRead: true,
    write: true,
    denyRelativePaths: []
  }]);
}

function readPlist(inspector: FilesystemInspector, plan: ReturnType<FilesystemInspector["planPath"]>): { content: Buffer; device: string; inode: string } {
  const read = inspector.readPlanned(plan, 0, PLIST_MAX_BYTES);
  if (read.truncated) fail("FILESYSTEM_MISMATCH", "root-helper plist exceeds its bounded rollback budget");
  return { content: read.content, device: read.device, inode: read.inode };
}

function optionalStat(inspector: FilesystemInspector, plan: ReturnType<FilesystemInspector["planPath"]>) {
  try {
    return inspector.statPlanned(plan, false);
  } catch {
    return undefined;
  }
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
  operation: RootHelperSnapshotPackageOperation,
  result: { path: string; bytesWritten: number; sha256: string; created: boolean; device: string; inode: string },
  backupPath: string | null,
  backupSha256: string | null
): RootHelperSnapshotPackagePlistApplyResult {
  return { operation, path: result.path, bytesWritten: result.bytesWritten, sha256: result.sha256, created: result.created,
    backupPath, backupSha256, device: result.device, inode: result.inode };
}

function ancestorsThrough(root: string, target: string): readonly string[] {
  const result: string[] = [];
  let current = resolve(target);
  while (true) {
    if (!isWithin(root, current, true)) fail("FILESYSTEM_MISMATCH", "root-helper package path escapes the protected root");
    result.push(current);
    if (current === root) return result;
    const parent = dirname(current);
    if (parent === current) fail("FILESYSTEM_MISMATCH", "root-helper package path has no protected ancestor");
    current = parent;
  }
}

function isWithin(root: string, target: string, allowEqual: boolean): boolean {
  const child = relative(root, target);
  return (allowEqual || child.length > 0) && child !== ".." && !child.startsWith("../") && !child.startsWith("/");
}

function sameStrings(left: readonly string[] | null, right: readonly string[]): boolean {
  return left !== null && left.length === right.length && left.every((value, index) => value === right[index]);
}

function sameLaunchdIdentity(left: LaunchdJobReadback, right: LaunchdJobReadback): boolean {
  return left.serviceId === right.serviceId && left.domain === right.domain && left.label === right.label &&
    left.state === right.state && left.pid === right.pid && left.program === right.program &&
    sameNullableStrings(left.arguments, right.arguments) && left.plistPath === right.plistPath &&
    left.type === right.type && left.lastExitCode === right.lastExitCode && left.truncated === right.truncated;
}

function sameNullableStrings(left: readonly string[] | null, right: readonly string[] | null): boolean {
  return left === null || right === null
    ? left === right
    : left.length === right.length && left.every((value, index) => value === right[index]);
}

function sameProcessIdentity(left: PeerProcessIdentity, right: PeerProcessIdentity): boolean {
  return left.pid === right.pid && left.startTimeMicros === right.startTimeMicros;
}

function samePlistIdentity(left: RootHelperSnapshotPackagePlistReadback, right: RootHelperSnapshotPackagePlistReadback): boolean {
  return left.path === right.path && left.bytes === right.bytes && left.sha256 === right.sha256 &&
    left.device === right.device && left.inode === right.inode;
}

function sameExistingService(left: RootHelperSnapshotPackageExistingServiceReadback, right: RootHelperSnapshotPackageExistingServiceReadback): boolean {
  return left.present === right.present && left.sourceRevision === right.sourceRevision;
}

function sameReleaseArtifact(left: RootHelperSnapshotReleaseEvidence, right: RootHelperSnapshotReleaseEvidence): boolean {
  return left.artifact.artifactPath === right.artifact.artifactPath && left.artifact.sha256 === right.artifact.sha256 &&
    left.artifact.bytes === right.artifact.bytes && left.artifact.files === right.artifact.files &&
    left.artifact.directories === right.artifact.directories && left.artifact.device === right.artifact.device &&
    left.artifact.inode === right.artifact.inode && left.artifact.mode === right.artifact.mode &&
    left.signature.identifier === right.signature.identifier && left.signature.teamIdentifier === right.signature.teamIdentifier &&
    left.signature.cdHash === right.signature.cdHash && left.notarization.origin === right.notarization.origin;
}

function fail(code: ConstructorParameters<typeof RootHelperSnapshotPackageError>[0], message: string): never {
  throw new RootHelperSnapshotPackageError(code, message);
}
