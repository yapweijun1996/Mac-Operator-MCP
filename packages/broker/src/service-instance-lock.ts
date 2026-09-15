import { constants } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { lstat, open, readdir, realpath, rename, unlink } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { parseJsonUtf8Strict } from "@mac-operator/contracts";
import { capturePeerProcessIdentity, type PeerProcessIdentity } from "./peer-credentials.js";

const LOCK_SCHEMA_VERSION = "0.1";
const MAX_LOCK_BYTES = 1_024;

export type ServiceInstanceLockErrorCode =
  | "INVALID_PATH"
  | "LOCK_INVALID"
  | "LOCK_UNAVAILABLE"
  | "ALREADY_ACTIVE"
  | "OWNER_UNVERIFIED"
  | "LOCK_CHANGED";

export class ServiceInstanceLockError extends Error {
  readonly code: ServiceInstanceLockErrorCode;

  constructor(code: ServiceInstanceLockErrorCode, message: string) {
    super(message);
    this.name = "ServiceInstanceLockError";
    this.code = code;
  }
}

export type ServiceInstanceProbeResult = "active" | "stale" | "unknown";

export interface ServiceInstanceLockOptions {
  identity?: PeerProcessIdentity;
  probe?: (identity: PeerProcessIdentity) => ServiceInstanceProbeResult | Promise<ServiceInstanceProbeResult>;
}

interface LockDocument {
  schemaVersion: typeof LOCK_SCHEMA_VERSION;
  pid: number;
  startTimeMicros: number;
}

interface LockFileRecord {
  fileDevice: number;
  fileInode: number;
  document: LockDocument;
}

export interface ServiceInstanceLockRecoveryResult {
  status: "recovered" | "absent" | "not_stale" | "ambiguous";
  path: string;
  quarantinePath: string | null;
  identity: FileIdentity;
}

export interface FileIdentity {
  device: number;
  inode: number;
}

const MIN_LOCK_RECOVERY_AGE_MS = 1_000;
const MAX_LOCK_RECOVERY_AGE_MS = 604_800_000;
const LOCK_QUARANTINE_PREFIX = ".mac-operator-lock-removing-";

/**
 * Holds an owner-only, exclusive startup lock for one packaged Broker.
 * Stale files are reclaimed only when the recorded PID is proven dead or has
 * a different native start-time identity; observer uncertainty fails closed.
 */
export class BrokerServiceInstanceLock {
  private closed = false;

  private constructor(
    readonly path: string,
    private readonly handle: FileHandle,
    private readonly fileDevice: number,
    private readonly fileInode: number
  ) {}

  static async acquire(path: string, options: ServiceInstanceLockOptions = {}): Promise<BrokerServiceInstanceLock> {
    validateLockPath(path);
    const identity = options.identity ?? capturePeerProcessIdentity(process.pid);
    validateProcessIdentity(identity);
    const probe = options.probe ?? probeNativeProcessIdentity;
    const ownerUid = process.getuid?.();
    if (ownerUid === undefined) throw new ServiceInstanceLockError("LOCK_UNAVAILABLE", "Broker service lock requires a POSIX owner identity");

    for (let attempt = 0; attempt < 4; attempt += 1) {
      try {
        const handle = await open(
          path,
          constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
          0o600
        );
        let createdDevice: number | undefined;
        let createdInode: number | undefined;
        try {
          const document: LockDocument = {
            schemaVersion: LOCK_SCHEMA_VERSION,
            pid: identity.pid,
            startTimeMicros: identity.startTimeMicros
          };
          const bytes = Buffer.from(`${JSON.stringify(document)}\n`, "utf8");
          if (bytes.byteLength > MAX_LOCK_BYTES) throw new ServiceInstanceLockError("LOCK_INVALID", "Broker service lock document is oversized");
          await handle.writeFile(bytes);
          await handle.sync();
          const fileStat = await handle.stat();
          createdDevice = fileStat.dev;
          createdInode = fileStat.ino;
          if (!fileStat.isFile() || fileStat.uid !== ownerUid || (fileStat.mode & 0o077) !== 0 || fileStat.size !== bytes.byteLength) {
            throw new ServiceInstanceLockError("LOCK_INVALID", "Broker service lock permissions or identity are invalid");
          }
          return new BrokerServiceInstanceLock(path, handle, fileStat.dev, fileStat.ino);
        } catch (error) {
          await handle.close().catch(() => undefined);
          if (createdDevice !== undefined && createdInode !== undefined) {
            await unlinkExactLock(path, createdDevice, createdInode).catch(() => undefined);
          }
          throw error;
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
          if (error instanceof ServiceInstanceLockError) throw error;
          throw new ServiceInstanceLockError("LOCK_UNAVAILABLE", "Broker service instance lock could not be acquired");
        }
        const existing = await readLockFile(path, ownerUid);
        const state = await probe(existing.document);
        if (state === "active") {
          throw new ServiceInstanceLockError("ALREADY_ACTIVE", "Broker service instance is already active");
        }
        if (state === "unknown") {
          throw new ServiceInstanceLockError("OWNER_UNVERIFIED", "Broker service lock owner could not be verified");
        }
        await unlinkExactLock(path, existing.fileDevice, existing.fileInode);
      }
    }
    throw new ServiceInstanceLockError("LOCK_UNAVAILABLE", "Broker service instance lock remained contested");
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    let firstError: unknown;
    try {
      await unlinkExactLock(this.path, this.fileDevice, this.fileInode);
    } catch (error) {
      firstError = error;
    }
    try {
      await this.handle.close();
    } catch (error) {
      firstError ??= error;
    }
    if (firstError !== undefined) throw firstError;
  }
}

async function readLockFile(path: string, ownerUid: number): Promise<LockFileRecord> {
  let pathStat: Awaited<ReturnType<typeof lstat>>;
  try {
    pathStat = await lstat(path);
  } catch {
    throw new ServiceInstanceLockError("LOCK_UNAVAILABLE", "Broker service lock disappeared while reading");
  }
  if (!pathStat.isFile() || pathStat.isSymbolicLink() || pathStat.uid !== ownerUid || (pathStat.mode & 0o077) !== 0 || pathStat.size < 2 || pathStat.size > MAX_LOCK_BYTES) {
    throw new ServiceInstanceLockError("LOCK_INVALID", "Broker service lock is not a protected regular file");
  }
  try {
    if (await realpath(path) !== path) throw new ServiceInstanceLockError("LOCK_INVALID", "Broker service lock is not canonical");
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const opened = await handle.stat();
      if (!opened.isFile() || opened.uid !== ownerUid || (opened.mode & 0o077) !== 0 ||
          opened.dev !== pathStat.dev || opened.ino !== pathStat.ino || opened.size !== pathStat.size) {
        throw new ServiceInstanceLockError("LOCK_CHANGED", "Broker service lock changed while reading");
      }
      const bytes = await handle.readFile();
      let value: unknown;
      try { value = parseJsonUtf8Strict(bytes); }
      catch { throw new ServiceInstanceLockError("LOCK_INVALID", "Broker service lock is not valid JSON"); }
      const document = parseLockDocument(value);
      return { fileDevice: opened.dev, fileInode: opened.ino, document };
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (error instanceof ServiceInstanceLockError) throw error;
    throw new ServiceInstanceLockError("LOCK_UNAVAILABLE", "Broker service lock could not be read");
  }
}

async function unlinkExactLock(path: string, device: number, inode: number): Promise<void> {
  let current: Awaited<ReturnType<typeof lstat>>;
  try { current = await lstat(path); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw new ServiceInstanceLockError("LOCK_UNAVAILABLE", "Broker service lock could not be inspected");
  }
  if (!current.isFile() || current.isSymbolicLink() || current.dev !== device || current.ino !== inode) {
    throw new ServiceInstanceLockError("LOCK_CHANGED", "Broker service lock ownership changed");
  }
  const quarantine = join(dirname(path), `${LOCK_QUARANTINE_PREFIX}${Date.now()}-${randomUUID()}-${lockPathBasenameHash(path)}`);
  try {
    await rename(path, quarantine);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw new ServiceInstanceLockError("LOCK_UNAVAILABLE", "Broker service lock could not be released");
  }
  let quarantined: Awaited<ReturnType<typeof lstat>>;
  try {
    quarantined = await lstat(quarantine);
  } catch {
    throw new ServiceInstanceLockError("LOCK_UNAVAILABLE", "Broker service lock quarantine could not be verified");
  }
  if (!quarantined.isFile() || quarantined.isSymbolicLink() || quarantined.dev !== device || quarantined.ino !== inode) {
    throw new ServiceInstanceLockError("LOCK_CHANGED", "Broker service lock changed during release");
  }
  try {
    await unlink(quarantine);
  } catch {
    throw new ServiceInstanceLockError("LOCK_UNAVAILABLE", "Broker service lock quarantine could not be removed");
  }
}

/**
 * Explicitly completes one stale service-lock quarantine after a crash. The
 * original lock document must still prove a stale PID/start-time identity;
 * active, unknown, malformed, recent, or ambiguous artifacts are preserved.
 */
export async function recoverOrphanedServiceInstanceLock(
  path: string,
  expected: FileIdentity,
  options: { minAgeMs?: number; probe?: ServiceInstanceLockOptions["probe"] } = {}
): Promise<ServiceInstanceLockRecoveryResult> {
  validateLockPath(path);
  const minAgeMs = options.minAgeMs ?? 60_000;
  if (!validFileIdentity(expected) || !Number.isSafeInteger(minAgeMs) ||
      minAgeMs < MIN_LOCK_RECOVERY_AGE_MS || minAgeMs > MAX_LOCK_RECOVERY_AGE_MS) {
    throw new ServiceInstanceLockError("LOCK_INVALID", "Broker service lock recovery precondition is malformed");
  }
  const ownerUid = process.getuid?.();
  if (ownerUid === undefined) throw new ServiceInstanceLockError("LOCK_UNAVAILABLE", "Broker service lock requires a POSIX owner identity");
  const parentPath = dirname(path);
  await validateLockRecoveryParent(parentPath, ownerUid);
  const parentBefore = await readDirectoryIdentity(parentPath);
  const basenameHash = lockPathBasenameHash(path);
  const names = await readdir(parentPath);
  const stale: string[] = [];
  const recent: string[] = [];
  let ambiguous = 0;
  const now = Date.now();
  const probe = options.probe ?? probeNativeProcessIdentity;
  for (const name of names) {
    const createdAt = parseLockQuarantineTimestamp(name, basenameHash);
    if (createdAt === undefined) continue;
    const candidatePath = join(parentPath, name);
    let candidate: Awaited<ReturnType<typeof lstat>>;
    try { candidate = await lstat(candidatePath); }
    catch { ambiguous += 1; continue; }
    if (!candidate.isFile() || candidate.isSymbolicLink() || candidate.nlink !== 1 || candidate.uid !== ownerUid ||
        (candidate.mode & 0o077) !== 0 || candidate.dev !== expected.device || candidate.ino !== expected.inode) continue;
    let record: LockFileRecord;
    try { record = await readLockFile(candidatePath, ownerUid); }
    catch { ambiguous += 1; continue; }
    let state: ServiceInstanceProbeResult;
    try { state = await probe(record.document); }
    catch { state = "unknown"; }
    if (state !== "stale") {
      ambiguous += 1;
      continue;
    }
    if (now >= createdAt && now - createdAt >= minAgeMs) stale.push(name);
    else recent.push(name);
  }
  const parentAfter = await readDirectoryIdentity(parentPath);
  if (parentBefore.device !== parentAfter.device || parentBefore.inode !== parentAfter.inode) {
    throw new ServiceInstanceLockError("LOCK_CHANGED", "Broker service lock recovery parent changed during scan");
  }
  const target = await lstat(path).catch((error: unknown) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw new ServiceInstanceLockError("LOCK_UNAVAILABLE", "Broker service lock target could not be inspected");
  });
  const targetOccupied = target !== undefined && (target.dev !== expected.device || target.ino !== expected.inode);
  const makeResult = (status: ServiceInstanceLockRecoveryResult["status"], quarantinePath: string | null): ServiceInstanceLockRecoveryResult => ({
    status,
    path,
    quarantinePath,
    identity: expected
  });
  if (targetOccupied || ambiguous > 0 || stale.length > 1 || recent.length > 1 || (stale.length > 0 && recent.length > 0)) {
    return makeResult("ambiguous", null);
  }
  if (stale.length === 0) {
    return makeResult(recent.length === 1 ? "not_stale" : "absent", recent.length === 1 ? join(parentPath, recent[0]!) : null);
  }
  const candidatePath = join(parentPath, stale[0]!);
  const parentFinal = await readDirectoryIdentity(parentPath);
  if (parentBefore.device !== parentFinal.device || parentBefore.inode !== parentFinal.inode) {
    throw new ServiceInstanceLockError("LOCK_CHANGED", "Broker service lock recovery parent changed before removal");
  }
  const current = await lstat(candidatePath).catch((error: unknown) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw new ServiceInstanceLockError("LOCK_UNAVAILABLE", "Broker service lock recovery artifact could not be inspected");
  });
  if (current === undefined) return makeResult("absent", null);
  if (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1 || current.uid !== ownerUid || (current.mode & 0o077) !== 0 ||
      current.dev !== expected.device || current.ino !== expected.inode) {
    throw new ServiceInstanceLockError("LOCK_CHANGED", "Broker service lock recovery artifact changed");
  }
  await unlink(candidatePath);
  await syncLockDirectory(parentPath);
  if (await lstat(candidatePath).catch((error: unknown) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  })) {
    throw new ServiceInstanceLockError("LOCK_CHANGED", "Broker service lock recovery postcondition failed");
  }
  return makeResult("recovered", candidatePath);
}

async function validateLockRecoveryParent(path: string, ownerUid: number): Promise<void> {
  const parent = await lstat(path);
  if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== ownerUid || (parent.mode & 0o077) !== 0 || await realpath(path) !== path) {
    throw new ServiceInstanceLockError("LOCK_INVALID", "Broker service lock recovery parent is not protected");
  }
}

async function readDirectoryIdentity(path: string): Promise<FileIdentity> {
  const value = await lstat(path);
  if (!value.isDirectory() || value.isSymbolicLink()) throw new ServiceInstanceLockError("LOCK_INVALID", "Broker service lock recovery parent is not a directory");
  return { device: value.dev, inode: value.ino };
}

function validFileIdentity(identity: FileIdentity): boolean {
  return Number.isSafeInteger(identity.device) && identity.device >= 0 && Number.isSafeInteger(identity.inode) && identity.inode > 0;
}

function lockPathBasenameHash(path: string): string {
  return createHash("sha256").update(path.slice(path.lastIndexOf("/") + 1), "utf8").digest("hex");
}

function parseLockQuarantineTimestamp(name: string, basenameHash: string): number | undefined {
  const prefix = LOCK_QUARANTINE_PREFIX.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const match = new RegExp(`^${prefix}(\\d{1,13})-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-${basenameHash}$`, "u").exec(name);
  if (!match) return undefined;
  const timestamp = Number(match[1]);
  return Number.isSafeInteger(timestamp) ? timestamp : undefined;
}

async function syncLockDirectory(path: string): Promise<void> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { await handle.sync(); } finally { await handle.close(); }
}

function parseLockDocument(value: unknown): LockDocument {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ServiceInstanceLockError("LOCK_INVALID", "Broker service lock document is malformed");
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !new Set(["schemaVersion", "pid", "startTimeMicros"]).has(key)) ||
      record.schemaVersion !== LOCK_SCHEMA_VERSION ||
      !Number.isSafeInteger(record.pid) || (record.pid as number) < 1 || (record.pid as number) > 99_999_999 ||
      !Number.isSafeInteger(record.startTimeMicros) || (record.startTimeMicros as number) < 1) {
    throw new ServiceInstanceLockError("LOCK_INVALID", "Broker service lock document is invalid");
  }
  return { schemaVersion: LOCK_SCHEMA_VERSION, pid: record.pid as number, startTimeMicros: record.startTimeMicros as number };
}

function validateLockPath(path: string): void {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path || path.includes("\0") || path.includes("\n") || path.includes("\r") || dirname(path) === path) {
    throw new ServiceInstanceLockError("INVALID_PATH", "Broker service lock path is invalid");
  }
}

function validateProcessIdentity(identity: PeerProcessIdentity): void {
  if (!Number.isSafeInteger(identity.pid) || identity.pid < 1 || identity.pid > 99_999_999 ||
      !Number.isSafeInteger(identity.startTimeMicros) || identity.startTimeMicros < 1) {
    throw new ServiceInstanceLockError("INVALID_PATH", "Broker service process identity is invalid");
  }
}

function probeNativeProcessIdentity(identity: PeerProcessIdentity): ServiceInstanceProbeResult {
  try {
    process.kill(identity.pid, 0);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return "stale";
    return "unknown";
  }
  try {
    const observed = capturePeerProcessIdentity(identity.pid);
    return observed.pid === identity.pid && observed.startTimeMicros === identity.startTimeMicros ? "active" : "stale";
  } catch {
    return "unknown";
  }
}
