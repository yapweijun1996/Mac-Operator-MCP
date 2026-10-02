import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { constants, chmodSync, closeSync, fsyncSync, lstatSync, openSync, readFileSync, readdirSync, realpathSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { canonicalJson, parseJsonUtf8Strict } from "@mac-operator/contracts";
import { loadNativePeerAdapter } from "./peer-credentials.js";
import { isPlainDataRecord } from "./plain-record.js";

const ANCHOR_FORMAT = "MOPS-AUDIT-ANCHOR-1" as const;
const ANCHOR_KEY_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const MAX_ANCHOR_BYTES = 8 * 1024;
const HMAC_DOMAIN = "mac-operator.audit-anchor.v1\0";

export interface AuditAnchorKeySource {
  /** Stable non-secret identity; key bytes must never be persisted or logged. */
  keyId: string;
  loadKey: () => Uint8Array;
}

export interface AuditAnchorRecord {
  format: typeof ANCHOR_FORMAT;
  keyId: string;
  sequence: number;
  eventHash: string;
  mac: string;
}

export interface AuditAnchorOptions {
  /** Absolute owner-only path outside the SQLite database directory when possible. */
  path: string;
  keySource: AuditAnchorKeySource;
}

export interface AuditAnchorLockRecoveryOptions {
  /** Canonical audit-anchor path whose sibling lock is being recovered. */
  path: string;
  /** Exact lock identity captured by a stopped-service operator readback. */
  expectedLockDevice: number;
  expectedLockInode: number;
  /**
   * Host-only stopped-service gate. The caller must hold its stop/recovery
   * guard while this synchronous operation runs; no PID or age heuristic is
   * accepted as proof that the lock is stale.
   */
  assertServiceStopped: () => void;
}

export interface AuditAnchorLockRecoveryResult {
  path: string;
  lockPath: string;
  removed: true;
  device: number;
  inode: number;
}

export interface AuditAnchorLockOrphanRecoveryResult {
  status: "recovered" | "absent" | "not_stale" | "ambiguous";
  path: string;
  lockPath: string;
  quarantinePath: string | null;
  device: number;
  inode: number;
}

const MIN_ANCHOR_LOCK_RECOVERY_AGE_MS = 1_000;
const MAX_ANCHOR_LOCK_RECOVERY_AGE_MS = 604_800_000;

/**
 * Keyed, Broker-owned audit tail anchor. The key is supplied by startup code
 * from a protected source (normally Keychain) and is retained only in memory.
 * The sidecar is deliberately fail-closed: a missing, stale, or invalid
 * anchor cannot be treated as evidence that the database is trustworthy.
 */
export class AuditAnchorManager {
  private readonly key: Buffer;
  private readonly options: AuditAnchorOptions;

  constructor(options: AuditAnchorOptions) {
    validateAnchorPath(options.path);
    this.options = { ...options, path: canonicalAnchorPath(options.path) };
    validateKeyId(options.keySource.keyId);
    const loaded = Buffer.from(options.keySource.loadKey());
    if (loaded.byteLength < 32 || loaded.byteLength > 128) {
      loaded.fill(0);
      throw new Error("Audit anchor key has an invalid length");
    }
    this.key = loaded;
    validateAnchorDirectory(this.options.path);
  }

  close(): void {
    this.key.fill(0);
  }

  verify(tail: { sequence: number; eventHash: string } | undefined): void {
    withAnchorLock(this.options.path, () => {
      const current = readAnchorIfPresent(this.options.path);
      if (tail === undefined) {
        if (current !== undefined) throw new Error("Audit anchor exists for an empty audit database");
        return;
      }
      if (current === undefined) throw new Error("Audit anchor is missing for a non-empty audit database");
      if (current.keyId !== this.options.keySource.keyId ||
          current.sequence !== tail.sequence || current.eventHash !== tail.eventHash ||
          !macEquals(current.mac, anchorMac(this.key, current.keyId, current.sequence, current.eventHash))) {
        throw new Error("Audit anchor does not match the persisted audit tail");
      }
    });
  }

  publish(sequence: number, eventHash: string): void {
    if (!Number.isSafeInteger(sequence) || sequence < 1 || !HASH_PATTERN.test(eventHash)) {
      throw new Error("Audit anchor tail is malformed");
    }
    withAnchorLock(this.options.path, () => {
      const existing = readAnchorIfPresent(this.options.path);
      if (existing !== undefined) {
        if (existing.keyId !== this.options.keySource.keyId) throw new Error("Audit anchor key identity changed");
        if (existing.sequence > sequence) return;
        if (existing.sequence === sequence && existing.eventHash === eventHash) return;
        if (existing.sequence === sequence) throw new Error("Audit anchor sequence was reused");
      }
      const record: AuditAnchorRecord = {
        format: ANCHOR_FORMAT,
        keyId: this.options.keySource.keyId,
        sequence,
        eventHash,
        mac: anchorMac(this.key, this.options.keySource.keyId, sequence, eventHash)
      };
      writeAnchor(this.options.path, record);
    });
  }
}

/**
 * Removes one exact audit-anchor lock after an authenticated host stop
 * readback. This is deliberately not used by startup or normal publication:
 * stale locks are never reclaimed automatically. The native unlink boundary
 * opens the canonical parent and uses unlinkat plus fsync, so a replacement
 * pathname cannot be deleted after the expected device/inode check.
 */
export function recoverAuditAnchorLock(
  options: AuditAnchorLockRecoveryOptions
): AuditAnchorLockRecoveryResult {
  validateAnchorPath(options.path);
  validateLockIdentity(options.expectedLockDevice, options.expectedLockInode);
  const anchorPath = canonicalAnchorPath(options.path);
  validateAnchorDirectory(anchorPath);
  options.assertServiceStopped();

  const lockPath = `${anchorPath}.lock`;
  const lock = lstatSync(lockPath);
  const uid = process.getuid?.();
  if (!lock.isFile() || lock.isSymbolicLink() || uid === undefined || lock.uid !== uid || (lock.mode & 0o077) !== 0 ||
      lock.dev !== options.expectedLockDevice || lock.ino !== options.expectedLockInode) {
    throw new Error("Audit anchor lock identity precondition failed");
  }

  const native = loadNativePeerAdapter();
  const result = native.unlinkFileWithinRoot(
    dirname(anchorPath),
    lockPath,
    true,
    String(options.expectedLockDevice),
    String(options.expectedLockInode)
  ) as unknown;
  if (!isNativeLockRecoveryResult(result) || !result.removed || result.rootPath !== dirname(anchorPath) ||
      result.path !== lockPath || result.device !== String(options.expectedLockDevice) ||
      result.inode !== String(options.expectedLockInode)) {
    throw new Error("Audit anchor lock recovery readback failed");
  }
  try {
    lstatSync(lockPath);
    throw new Error("Audit anchor lock recovery left the target present");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  return {
    path: anchorPath,
    lockPath,
    removed: true,
    device: options.expectedLockDevice,
    inode: options.expectedLockInode
  };
}

/**
 * Explicitly removes one stale audit-anchor lock quarantine left by a crash.
 * The host stop gate is mandatory because the lock payload does not carry a
 * trustworthy process start-time identity of its own.
 */
export function recoverAuditAnchorLockOrphan(
  options: AuditAnchorLockRecoveryOptions & { minAgeMs?: number }
): AuditAnchorLockOrphanRecoveryResult {
  validateAnchorPath(options.path);
  validateLockIdentity(options.expectedLockDevice, options.expectedLockInode);
  const minAgeMs = options.minAgeMs ?? 60_000;
  if (!Number.isSafeInteger(minAgeMs) || minAgeMs < MIN_ANCHOR_LOCK_RECOVERY_AGE_MS || minAgeMs > MAX_ANCHOR_LOCK_RECOVERY_AGE_MS) {
    throw new Error("Audit anchor lock recovery age is malformed");
  }
  const anchorPath = canonicalAnchorPath(options.path);
  validateAnchorDirectory(anchorPath);
  options.assertServiceStopped();
  const lockPath = `${anchorPath}.lock`;
  const parentPath = dirname(lockPath);
  const parentBefore = protectedDirectoryIdentity(parentPath);
  const lockBaseName = basename(lockPath);
  const basenameHash = anchorLockBasenameHash(lockPath);
  const stale: string[] = [];
  const recent: string[] = [];
  const now = Date.now();
  for (const name of readdirSync(parentPath)) {
    const createdAt = parseAnchorLockQuarantineTimestamp(name, lockBaseName, basenameHash);
    if (createdAt === undefined) continue;
    const candidatePath = join(parentPath, name);
    let candidate: ReturnType<typeof lstatSync>;
    try { candidate = lstatSync(candidatePath); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    const uid = process.getuid?.();
    if (!candidate.isFile() || candidate.isSymbolicLink() || candidate.nlink !== 1 || uid === undefined || candidate.uid !== uid ||
        (candidate.mode & 0o077) !== 0 || candidate.dev !== options.expectedLockDevice || candidate.ino !== options.expectedLockInode) continue;
    if (now >= createdAt && now - createdAt >= minAgeMs) stale.push(name);
    else recent.push(name);
  }
  const parentAfter = protectedDirectoryIdentity(parentPath);
  if (parentBefore.device !== parentAfter.device || parentBefore.inode !== parentAfter.inode) {
    throw new Error("Audit anchor lock recovery parent changed during scan");
  }
  let target: ReturnType<typeof lstatSync> | undefined;
  try { target = lstatSync(lockPath); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const targetOccupied = target !== undefined && (target.dev !== options.expectedLockDevice || target.ino !== options.expectedLockInode);
  const makeResult = (status: AuditAnchorLockOrphanRecoveryResult["status"], quarantinePath: string | null): AuditAnchorLockOrphanRecoveryResult => ({
    status,
    path: anchorPath,
    lockPath,
    quarantinePath,
    device: options.expectedLockDevice,
    inode: options.expectedLockInode
  });
  if (targetOccupied || stale.length > 1 || recent.length > 1 || (stale.length > 0 && recent.length > 0)) {
    return makeResult("ambiguous", null);
  }
  if (stale.length === 0) {
    return makeResult(recent.length === 1 ? "not_stale" : "absent", recent.length === 1 ? join(parentPath, recent[0]!) : null);
  }
  const candidatePath = join(parentPath, stale[0]!);
  const parentFinal = protectedDirectoryIdentity(parentPath);
  if (parentBefore.device !== parentFinal.device || parentBefore.inode !== parentFinal.inode) {
    throw new Error("Audit anchor lock recovery parent changed before removal");
  }
  const current = lstatSync(candidatePath);
  const uid = process.getuid?.();
  if (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1 || uid === undefined || current.uid !== uid ||
      (current.mode & 0o077) !== 0 || current.dev !== options.expectedLockDevice || current.ino !== options.expectedLockInode) {
    throw new Error("Audit anchor lock recovery artifact changed");
  }
  unlinkSync(candidatePath);
  syncDirectory(parentPath);
  try { lstatSync(candidatePath); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return makeResult("recovered", candidatePath);
    throw error;
  }
  throw new Error("Audit anchor lock recovery postcondition failed");
}

function anchorLockBasenameHash(path: string): string {
  return createHash("sha256").update(basename(path), "utf8").digest("hex");
}

function parseAnchorLockQuarantineTimestamp(name: string, lockBaseName: string, basenameHash: string): number | undefined {
  const escapedBaseName = lockBaseName.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const escapedHash = basenameHash.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const match = new RegExp(`^${escapedBaseName}\\.removing-(\\d{1,13})-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-${escapedHash}$`, "u").exec(name);
  if (!match) return undefined;
  const timestamp = Number(match[1]);
  return Number.isSafeInteger(timestamp) ? timestamp : undefined;
}

function protectedDirectoryIdentity(path: string): { device: number; inode: number } {
  const directory = lstatSync(path);
  const uid = process.getuid?.();
  if (!directory.isDirectory() || directory.isSymbolicLink() || uid === undefined || directory.uid !== uid || (directory.mode & 0o077) !== 0 || realpathSync(path) !== path) {
    throw new Error("Audit anchor lock recovery parent is not protected");
  }
  return { device: directory.dev, inode: directory.ino };
}

function anchorMac(key: Buffer, keyId: string, sequence: number, eventHash: string): string {
  return createHmac("sha256", key)
    .update(HMAC_DOMAIN, "utf8")
    .update(canonicalJson({ keyId, sequence, eventHash }), "utf8")
    .digest("hex");
}

function readAnchorIfPresent(path: string): AuditAnchorRecord | undefined {
  let content: Buffer;
  try {
    const stat = lstatSync(path);
    const uid = process.getuid?.();
    if (!stat.isFile() || stat.isSymbolicLink() || uid === undefined || stat.uid !== uid || (stat.mode & 0o077) !== 0 || stat.size < 2 || stat.size > MAX_ANCHOR_BYTES) {
      throw new Error("Audit anchor is not a protected regular file");
    }
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const opened = lstatSync(path);
      if (opened.dev !== stat.dev || opened.ino !== stat.ino) throw new Error("Audit anchor target changed while opening");
      content = readFileSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  let value: unknown;
  try {
    value = parseJsonUtf8Strict(content);
  } catch {
    throw new Error("Audit anchor is not valid JSON");
  }
  if (!isPlainDataRecord(value) || !hasExactKeys(value, ["format", "keyId", "sequence", "eventHash", "mac"])) throw new Error("Audit anchor is malformed");
  const record = value as Record<string, unknown>;
  if (record.format !== ANCHOR_FORMAT || typeof record.keyId !== "string" ||
      !ANCHOR_KEY_ID_PATTERN.test(record.keyId) || typeof record.sequence !== "number" ||
      !Number.isSafeInteger(record.sequence) || record.sequence < 1 ||
      typeof record.eventHash !== "string" || !HASH_PATTERN.test(record.eventHash) ||
      typeof record.mac !== "string" || !HASH_PATTERN.test(record.mac)) {
    throw new Error("Audit anchor is malformed");
  }
  return {
    format: ANCHOR_FORMAT,
    keyId: record.keyId,
    sequence: record.sequence,
    eventHash: record.eventHash,
    mac: record.mac
  };
}

function writeAnchor(path: string, record: AuditAnchorRecord): void {
  validateAnchorDirectory(path);
  const bytes = Buffer.from(`${canonicalJson(record)}\n`, "utf8");
  if (bytes.byteLength > MAX_ANCHOR_BYTES) throw new Error("Audit anchor is too large");
  const temporaryPath = `${path}.tmp-${randomBytes(12).toString("hex")}`;
  const fd = openSync(temporaryPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try {
    writeAll(fd, bytes);
    fsyncSync(fd);
    chmodSync(temporaryPath, 0o600);
  } catch (error) {
    closeSync(fd);
    unlinkSync(temporaryPath);
    throw error;
  }
  closeSync(fd);
  try {
    renameSync(temporaryPath, path);
    const directoryFd = openSync(dirname(path), constants.O_RDONLY | constants.O_NOFOLLOW);
    try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
  } catch (error) {
    try { unlinkSync(temporaryPath); } catch { /* Preserve the publication error. */ }
    throw error;
  }
}

function withAnchorLock<T>(path: string, operation: () => T): T {
  const lockPath = `${path}.lock`;
  let fd: number;
  try {
    fd = openSync(lockPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error("Audit anchor lock is held or requires operator recovery");
    }
    throw error;
  }
  let identity: { dev: number; ino: number } | undefined;
  try {
    const stat = lstatSync(lockPath);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 ||
        (process.getuid?.() !== undefined && stat.uid !== process.getuid?.())) {
      throw new Error("Audit anchor lock is not a protected regular file");
    }
    identity = { dev: stat.dev, ino: stat.ino };
    const owner = Buffer.from(`${process.pid}:${randomBytes(16).toString("hex")}\n`, "utf8");
    writeAll(fd, owner);
    fsyncSync(fd);
    syncDirectory(dirname(path));
  } catch (error) {
    closeSync(fd);
    if (identity !== undefined) {
      try {
        const current = lstatSync(lockPath);
        if (current.dev === identity.dev && current.ino === identity.ino) {
          removeExactAnchorLock(lockPath, identity.dev, identity.ino);
        }
      } catch { /* Preserve the lock setup error and require recovery. */ }
    }
    throw error;
  }
  if (identity === undefined) throw new Error("Audit anchor lock identity is unavailable");
  const lockIdentity = identity;
  try {
    return operation();
  } finally {
    closeSync(fd);
    const current = lstatSync(lockPath);
    if (current.dev !== lockIdentity.dev || current.ino !== lockIdentity.ino) {
      throw new Error("Audit anchor lock target changed during operation");
    }
    removeExactAnchorLock(lockPath, lockIdentity.dev, lockIdentity.ino);
  }
}

/**
 * Removes an exact anchor lock without unlinking a replacement pathname.
 * The private same-directory rename selects the checked inode atomically;
 * post-rename identity verification fails closed and leaves mismatches for
 * explicit operator recovery.
 */
function removeExactAnchorLock(path: string, device: number, inode: number): void {
  const current = lstatSync(path);
  if (!current.isFile() || current.isSymbolicLink() || current.dev !== device || current.ino !== inode) {
    throw new Error("Audit anchor lock ownership changed before removal");
  }
  const quarantine = `${path}.removing-${Date.now()}-${randomUUID()}-${anchorLockBasenameHash(path)}`;
  try {
    renameSync(path, quarantine);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  const quarantined = lstatSync(quarantine);
  if (!quarantined.isFile() || quarantined.isSymbolicLink() || quarantined.dev !== device || quarantined.ino !== inode) {
    throw new Error("Audit anchor lock changed during removal");
  }
  unlinkSync(quarantine);
  syncDirectory(dirname(path));
}

function syncDirectory(path: string): void {
  const directoryFd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
}

function writeAll(fd: number, bytes: Buffer): void {
  let offset = 0;
  while (offset < bytes.byteLength) offset += requireWrite(fd, bytes, offset);
}

function requireWrite(fd: number, bytes: Buffer, offset: number): number {
  // Node's synchronous fs API is intentionally used here so an audit append
  // cannot return before its keyed sidecar publication reaches stable storage.
  const written = writeSync(fd, bytes, offset, bytes.byteLength - offset, null);
  if (written < 1) throw new Error("Audit anchor write made no progress");
  return written;
}

function validateAnchorPath(path: string): void {
  if (!isAbsolute(path) || resolve(path) !== path || path.includes("\0") || path.endsWith("/")) {
    throw new Error("Audit anchor path must be canonical and absolute");
  }
}

function canonicalAnchorPath(path: string): string {
  return join(realpathSync(dirname(path)), basename(path));
}

function validateAnchorDirectory(path: string): void {
  const directory = dirname(path);
  const stat = lstatSync(directory);
  const uid = process.getuid?.();
  if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(directory) !== directory || uid === undefined || stat.uid !== uid || (stat.mode & 0o077) !== 0) {
    throw new Error("Audit anchor directory must be a protected owner-only directory");
  }
}

function validateKeyId(keyId: string): void {
  if (!ANCHOR_KEY_ID_PATTERN.test(keyId)) throw new Error("Audit anchor key ID is invalid");
}

function validateLockIdentity(device: number, inode: number): void {
  if (!Number.isSafeInteger(device) || device < 0 || !Number.isSafeInteger(inode) || inode < 1) {
    throw new Error("Audit anchor lock identity is invalid");
  }
}

function isNativeLockRecoveryResult(value: unknown): value is {
  rootPath: string;
  path: string;
  removed: boolean;
  device: string;
  inode: string;
} {
  if (!isPlainDataRecord(value) || !hasExactKeys(value, ["rootPath", "path", "removed", "device", "inode"])) return false;
  const record = value as Record<string, unknown>;
  return typeof record.rootPath === "string" && typeof record.path === "string" &&
    typeof record.removed === "boolean" && typeof record.device === "string" &&
    typeof record.inode === "string";
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function macEquals(actual: string, expected: string): boolean {
  const left = Buffer.from(actual, "hex");
  const right = Buffer.from(expected, "hex");
  return left.byteLength === right.byteLength && timingSafeEqual(left, right);
}
