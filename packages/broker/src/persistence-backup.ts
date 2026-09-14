import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { constants, createReadStream, type Dirent } from "node:fs";
import { chmod, lstat, open, readdir, rename, statfs, unlink } from "node:fs/promises";
import { backup, DatabaseSync } from "node:sqlite";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";

const BACKUP_NAME_PATTERN = /^broker-backup-(\d{1,16})-([a-f0-9]{24})\.sqlite\.enc$/u;
const LEGACY_PLAINTEXT_BACKUP_NAME_PATTERN = /^broker-backup-(\d{1,16})-([a-f0-9]{24})\.sqlite$/u;
const BACKUP_TEMP_NAME_PATTERN = /^\.broker-backup-(\d{1,16})-[a-f0-9]{24}\.(?:sqlite|sqlite\.enc)\.tmp-[a-f0-9]{24}(?:-(?:wal|shm|journal))?$/u;
const MAX_BACKUP_BYTES = 512 * 1024 * 1024;
const MAX_BACKUP_FILES = 256;
const MAX_BACKUP_TEMP_FILES = 256;
const BACKUP_TEMP_STALE_MS = 60 * 60 * 1000;
const BACKUP_HEADROOM_BYTES = 4 * 1024 * 1024;
const DEFAULT_RETAIN_COUNT = 7;
const BACKUP_KEY_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
const BACKUP_CIPHER = "aes-256-gcm" as const;
const BACKUP_MAGIC = Buffer.from("MOPSBAK1", "ascii");
const BACKUP_FORMAT_VERSION = 1;
const BACKUP_NONCE_BYTES = 12;
const BACKUP_TAG_BYTES = 16;
const BACKUP_HEADER_PREFIX_BYTES = BACKUP_MAGIC.byteLength + 1 + 2;
const BACKUP_MAX_KEY_ID_BYTES = 128;
const MAX_ENCRYPTED_BACKUP_BYTES = MAX_BACKUP_BYTES + BACKUP_MAX_KEY_ID_BYTES + 64;
const BACKUP_READ_CHUNK_BYTES = 64 * 1024;

export type BrokerBackupFaultPoint = "after_backup" | "after_temp_verify";

export interface BrokerBackupManifest {
  path: string;
  createdAtMs: number;
  bytes: number;
  sha256: string;
  auditEventCount: number;
  auditTailHash: string;
  encrypted: true;
  keyId: string;
}

/**
 * Broker-owned backup key source. Production startup should implement this
 * with a protected Keychain item; callers must never persist or log the key.
 */
export interface BrokerBackupKeySource {
  keyId: string;
  loadKey: () => Promise<Uint8Array> | Uint8Array;
}

export interface BrokerBackupOptions {
  /** Required encrypted-backup key source; absence fails closed. */
  keySource?: BrokerBackupKeySource;
  retainCount?: number;
  nowMs?: number;
  /** @internal Test-only crash-boundary hook; production callers must leave unset. */
  faultInjector?: (point: BrokerBackupFaultPoint) => void;
  /** @internal Test-only capacity probe; production callers must leave unset. */
  capacityProbe?: (directory: string) => Promise<number>;
}

export interface BrokerBackupPruneResult {
  directory: string;
  retained: readonly string[];
  removed: readonly string[];
}

/**
 * Creates an owner-only, integrity-checked SQLite backup in a caller-selected
 * protected directory. The temporary file is never exposed as a valid backup
 * name, and the final rename is atomic within that directory.
 */
export async function createBrokerBackup(
  source: DatabaseSync,
  directory: string,
  options: BrokerBackupOptions = {}
): Promise<BrokerBackupManifest> {
  if (!source) throw new BrokerError("PRECONDITION_FAILED", "Broker persistence source is unavailable");
  const keySource = validateBackupKeySource(options.keySource);
  const nowMs = options.nowMs ?? Date.now();
  validateNow(nowMs);
  const retainCount = options.retainCount ?? DEFAULT_RETAIN_COUNT;
  validateRetainCount(retainCount);
  const protectedDirectory = await validateProtectedDirectory(directory);
  const name = `broker-backup-${nowMs}-${randomBytes(12).toString("hex")}.sqlite.enc`;
  const destination = join(protectedDirectory, name);
  const rawTemporary = join(protectedDirectory, `.${name.replace(/\.enc$/u, "")}.tmp-${randomBytes(12).toString("hex")}`);
  const encryptedTemporary = join(protectedDirectory, `.${name}.tmp-${randomBytes(12).toString("hex")}`);
  const verifyTemporary = join(protectedDirectory, `.${name.replace(/\.enc$/u, "")}.tmp-${randomBytes(12).toString("hex")}`);
  let encryptedTemporaryIdentity: Awaited<ReturnType<typeof lstat>> | undefined;
  try {
    await assertBackupCapacity(protectedDirectory, source, options.capacityProbe);
    await backup(source, rawTemporary, { rate: 64 });
    options.faultInjector?.("after_backup");
    await chmod(rawTemporary, 0o600);
    await syncFile(rawTemporary);
    const verified = await inspectSnapshot(rawTemporary);
    await encryptBackupSnapshot(rawTemporary, encryptedTemporary, keySource);
    await decryptBackupSnapshot(encryptedTemporary, verifyTemporary, keySource);
    await chmod(verifyTemporary, 0o600);
    const decrypted = await inspectSnapshot(verifyTemporary);
    if (decrypted.sha256 !== verified.sha256 || decrypted.auditTailHash !== verified.auditTailHash ||
        decrypted.auditEventCount !== verified.auditEventCount) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Encrypted Broker persistence backup failed integrity readback");
    }
    encryptedTemporaryIdentity = await lstat(encryptedTemporary);
    options.faultInjector?.("after_temp_verify");
    const encryptedBeforeRename = await lstat(encryptedTemporary);
    if (!sameFileIdentity(encryptedTemporaryIdentity, encryptedBeforeRename)) {
      throw new BrokerError("CONFLICT", "Encrypted Broker backup changed before publication", true);
    }
    await rename(encryptedTemporary, destination);
    await cleanupTemporaryBackupFiles(rawTemporary);
    await cleanupTemporaryBackupFiles(verifyTemporary);
    await syncDirectory(protectedDirectory);
    const final = await inspectEncryptedBackup(destination, keySource, verifyTemporary);
    if (final.auditEventCount !== verified.auditEventCount || final.auditTailHash !== verified.auditTailHash) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Broker persistence backup changed during publication");
    }
    await pruneBrokerBackups(protectedDirectory, retainCount);
    return { ...final, path: destination, createdAtMs: nowMs, encrypted: true, keyId: keySource.keyId };
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker persistence backup could not be created", true);
  } finally {
    await cleanupTemporaryBackupFiles(rawTemporary).catch(() => undefined);
    await cleanupTemporaryBackupFiles(encryptedTemporary).catch(() => undefined);
    await cleanupTemporaryBackupFiles(verifyTemporary).catch(() => undefined);
  }
}

async function assertBackupCapacity(
  directory: string,
  source: DatabaseSync,
  capacityProbe?: (directory: string) => Promise<number>
): Promise<void> {
  const pageCount = (source.prepare("PRAGMA page_count").get() as { page_count?: unknown } | undefined)?.page_count;
  const pageSize = (source.prepare("PRAGMA page_size").get() as { page_size?: unknown } | undefined)?.page_size;
  if (!Number.isSafeInteger(pageCount) || !Number.isSafeInteger(pageSize) || (pageCount as number) < 0 || (pageSize as number) < 1) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker persistence size could not be measured", true);
  }
  const databaseBytes = (pageCount as number) * (pageSize as number);
  if (!Number.isSafeInteger(databaseBytes) || databaseBytes > MAX_BACKUP_BYTES) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker persistence exceeds the backup byte budget");
  }
  // Backup creation briefly holds the raw SQLite snapshot, encrypted output,
  // and a decrypted verification copy in the same protected directory.
  const requiredBytes = databaseBytes * 4 + BACKUP_HEADROOM_BYTES;
  let availableBytes: number;
  if (capacityProbe !== undefined) {
    try {
      availableBytes = await capacityProbe(directory);
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Broker backup capacity could not be measured", true);
    }
  } else {
    try {
      const filesystem = await statfs(directory);
      availableBytes = filesystem.bavail * filesystem.bsize;
    } catch {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Broker backup capacity could not be measured", true);
    }
  }
  if (!Number.isSafeInteger(availableBytes) || availableBytes < requiredBytes) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker backup destination lacks bounded free space", true);
  }
}

/**
 * Restores a verified backup into a new, non-existent database path. Refusing
 * an existing destination prevents this primitive from silently replacing a
 * live Broker database; an operator must select and inspect a fresh target.
 */
export async function restoreBrokerBackup(
  backupPath: string,
  destinationPath: string,
  keySource?: BrokerBackupKeySource
): Promise<BrokerBackupManifest> {
  const source = await validateProtectedFile(backupPath);
  const validatedKeySource = validateBackupKeySource(keySource);
  const sourceSummary = await inspectEncryptedBackup(source.path, validatedKeySource);
  const destination = validateAbsolutePath(destinationPath, "Broker restore destination");
  const protectedDirectory = await validateProtectedDirectory(dirname(destination));
  if (resolve(destination) === resolve(source.path)) {
    throw new BrokerError("CONFLICT", "Broker restore destination must differ from the backup");
  }
  const existing = await lstat(destination).catch(() => undefined);
  if (existing) throw new BrokerError("CONFLICT", "Broker restore destination already exists");
  const temporary = join(protectedDirectory, `.${basename(source.path).replace(/\.enc$/u, "")}.tmp-${randomBytes(12).toString("hex")}`);
  let temporaryIdentity: Awaited<ReturnType<typeof lstat>> | undefined;
  let moved = false;
  try {
    await decryptBackupSnapshot(source.path, temporary, validatedKeySource);
    await chmod(temporary, 0o600);
    await syncFile(temporary);
    temporaryIdentity = await lstat(temporary);
    const sourceAfterCopy = await validateProtectedFile(source.path);
    if (!sameFileIdentity(source.stat, sourceAfterCopy.stat)) {
      throw new BrokerError("CONFLICT", "Broker backup changed during restore", true);
    }
    const copiedSummary = await inspectSnapshot(temporary);
    if (copiedSummary.sha256 !== sourceSummary.plaintextSha256 || copiedSummary.auditTailHash !== sourceSummary.auditTailHash ||
        copiedSummary.auditEventCount !== sourceSummary.auditEventCount) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Broker backup integrity changed during restore");
    }
    const temporaryBeforeRename = await lstat(temporary);
    if (!sameFileIdentity(temporaryIdentity, temporaryBeforeRename)) {
      throw new BrokerError("CONFLICT", "Broker restore temporary changed before publication", true);
    }
    await rename(temporary, destination);
    moved = true;
    await syncDirectory(protectedDirectory);
    const restored = await inspectSnapshot(destination);
    if (restored.sha256 !== sourceSummary.plaintextSha256 || restored.auditTailHash !== sourceSummary.auditTailHash ||
        restored.auditEventCount !== sourceSummary.auditEventCount) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Restored Broker database failed final integrity readback");
    }
    const encryptedHash = await hashFile(source.path);
    const sourceAfterHash = await validateProtectedFile(source.path);
    if (!sameFileIdentity(source.stat, sourceAfterHash.stat)) {
      throw new BrokerError("CONFLICT", "Broker backup changed during restore hashing", true);
    }
    return {
      bytes: Number(source.stat.size),
      sha256: encryptedHash,
      auditEventCount: restored.auditEventCount,
      auditTailHash: restored.auditTailHash,
      encrypted: true,
      keyId: validatedKeySource.keyId,
      path: destination,
      createdAtMs: Date.now()
    };
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker persistence restore could not be completed", true);
  } finally {
    if (!moved && temporaryIdentity !== undefined) {
      const current = await lstat(temporary).catch(() => undefined);
      if (current !== undefined && sameFileIdentity(temporaryIdentity, current)) {
        await unlink(temporary).catch(() => undefined);
      }
    }
  }
}

/** Deletes only exact Broker backup names while retaining the newest bounded set. */
export async function pruneBrokerBackups(directory: string, retainCount = DEFAULT_RETAIN_COUNT): Promise<BrokerBackupPruneResult> {
  validateRetainCount(retainCount);
  const protectedDirectory = await validateProtectedDirectory(directory);
  const entries = await readdir(protectedDirectory, { withFileTypes: true });
  if (entries.some((entry) => LEGACY_PLAINTEXT_BACKUP_NAME_PATTERN.test(entry.name))) {
    throw new BrokerError("POLICY_DENIED", "Unencrypted Broker backup entries require explicit migration");
  }
  const temporaryEntries = entries.filter((entry) => BACKUP_TEMP_NAME_PATTERN.test(entry.name));
  if (temporaryEntries.length > MAX_BACKUP_TEMP_FILES) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker backup directory exceeds the bounded temporary-file budget");
  }
  const removed: string[] = await cleanupStaleBackupTemps(protectedDirectory, temporaryEntries);
  const candidates = entries.filter((entry) => BACKUP_NAME_PATTERN.test(entry.name));
  if (candidates.length > MAX_BACKUP_FILES) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker backup directory exceeds the bounded file budget");
  }
  const files: Array<{ name: string; path: string; stat: Awaited<ReturnType<typeof lstat>> }> = [];
  for (const entry of candidates) {
    const path = join(protectedDirectory, entry.name);
    const stat = await lstat(path);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o600 || !isOwnedByCurrentUser(stat.uid)) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Broker backup directory contains an unsafe backup entry");
    }
    if (stat.size > MAX_ENCRYPTED_BACKUP_BYTES) throw new BrokerError("AUDIT_UNAVAILABLE", "Broker backup exceeds the byte budget");
    files.push({ name: entry.name, path, stat });
  }
  files.sort((left, right) => {
    const leftTimestamp = backupTimestamp(left.name);
    const rightTimestamp = backupTimestamp(right.name);
    return rightTimestamp - leftTimestamp || right.name.localeCompare(left.name);
  });
  const retained = files.slice(0, retainCount).map((file) => file.path);
  for (const file of files.slice(retainCount)) {
    const current = await lstat(file.path);
    if (!sameFileIdentity(file.stat, current)) throw new BrokerError("CONFLICT", "Broker backup changed during retention cleanup", true);
    await unlink(file.path);
    removed.push(file.path);
  }
  if (removed.length > 0) await syncDirectory(protectedDirectory);
  return { directory: protectedDirectory, retained, removed };
}

async function cleanupStaleBackupTemps(
  directory: string,
  entries: readonly Dirent[]
): Promise<string[]> {
  const removed: string[] = [];
  const nowMs = Date.now();
  for (const entry of entries) {
    const path = join(directory, entry.name);
    const stat = await lstat(path);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0 || !isOwnedByCurrentUser(stat.uid)) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Broker backup directory contains an unsafe temporary entry");
    }
    if (nowMs - stat.mtimeMs < BACKUP_TEMP_STALE_MS) continue;
    const current = await lstat(path);
    if (!sameFileIdentity(stat, current)) throw new BrokerError("CONFLICT", "Broker backup temporary entry changed during cleanup", true);
    await unlink(path);
    removed.push(path);
  }
  if (removed.length > 0) await syncDirectory(directory);
  return removed;
}

async function cleanupTemporaryBackupFiles(basePath: string): Promise<void> {
  for (const suffix of ["", "-wal", "-shm", "-journal"] as const) {
    const path = `${basePath}${suffix}`;
    let stat: Awaited<ReturnType<typeof lstat>>;
    try {
      stat = await lstat(path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0 || !isOwnedByCurrentUser(stat.uid)) {
      throw new BrokerError("CONFLICT", "Broker backup temporary target is unsafe", true);
    }
    const current = await lstat(path);
    if (!sameFileIdentity(stat, current)) throw new BrokerError("CONFLICT", "Broker backup temporary target changed", true);
    await unlink(path);
  }
}

interface ProtectedFile {
  path: string;
  stat: Awaited<ReturnType<typeof lstat>>;
}

async function validateProtectedDirectory(directory: string): Promise<string> {
  const path = validateAbsolutePath(directory, "Broker persistence directory");
  const stat = await lstat(path).catch(() => undefined);
  if (!stat || !stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || !isOwnedByCurrentUser(stat.uid)) {
    throw new BrokerError("POLICY_DENIED", "Broker persistence directory must be an owner-only regular directory");
  }
  return path;
}

async function validateProtectedFile(pathValue: string): Promise<ProtectedFile> {
  const path = validateAbsolutePath(pathValue, "Broker backup path");
  await validateProtectedDirectory(dirname(path));
  const stat = await lstat(path).catch(() => undefined);
  if (!stat || !stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o600 || !isOwnedByCurrentUser(stat.uid)) {
    throw new BrokerError("POLICY_DENIED", "Broker backup must be an owner-only regular file");
  }
  if (!BACKUP_NAME_PATTERN.test(basename(path)) || stat.size > MAX_ENCRYPTED_BACKUP_BYTES) {
    throw new BrokerError("PRECONDITION_FAILED", "Broker backup filename or size is invalid");
  }
  return { path, stat };
}

function validateAbsolutePath(pathValue: string, label: string): string {
  if (typeof pathValue !== "string" || !isAbsolute(pathValue) || resolve(pathValue) !== pathValue || pathValue.includes("\0") || pathValue.length > 4096) {
    throw new BrokerError("PRECONDITION_FAILED", `${label} is malformed`);
  }
  return pathValue;
}

function validateNow(nowMs: number): void {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || nowMs > 9_999_999_999_999_999) {
    throw new BrokerError("PRECONDITION_FAILED", "Broker persistence timestamp is invalid");
  }
}

function validateRetainCount(retainCount: number): void {
  if (!Number.isSafeInteger(retainCount) || retainCount < 1 || retainCount > 128) {
    throw new BrokerError("PRECONDITION_FAILED", "Broker backup retention count is invalid");
  }
}

function isOwnedByCurrentUser(uid: number): boolean {
  const currentUid = typeof process.getuid === "function" ? process.getuid() : undefined;
  return currentUid !== undefined && uid === currentUid;
}

function sameFileIdentity(left: Awaited<ReturnType<typeof lstat>>, right: Awaited<ReturnType<typeof lstat>>): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size && left.mtimeMs === right.mtimeMs;
}

function backupTimestamp(name: string): number {
  const match = BACKUP_NAME_PATTERN.exec(name);
  if (match === null) throw new BrokerError("PRECONDITION_FAILED", "Broker backup filename is invalid");
  return Number(match[1]);
}

async function syncFile(path: string): Promise<void> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function syncDirectory(directory: string): Promise<void> {
  const handle = await open(directory, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function validateBackupKeySource(value: BrokerBackupKeySource | undefined): BrokerBackupKeySource {
  if (value === undefined || value === null || typeof value !== "object" ||
      typeof value.keyId !== "string" || !BACKUP_KEY_ID_PATTERN.test(value.keyId) ||
      Buffer.byteLength(value.keyId, "utf8") > BACKUP_MAX_KEY_ID_BYTES ||
      typeof value.loadKey !== "function") {
    throw new BrokerError("POLICY_DENIED", "Encrypted Broker backups require a valid protected key source");
  }
  return value;
}

async function loadBackupKey(source: BrokerBackupKeySource): Promise<Buffer> {
  let loaded: Uint8Array;
  try {
    loaded = await source.loadKey();
  } catch {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker backup encryption key is unavailable", true);
  }
  if (!(loaded instanceof Uint8Array) || loaded.byteLength !== 32) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker backup encryption key has an invalid length");
  }
  return Buffer.from(loaded);
}

interface BackupHeader {
  bytes: Buffer;
  keyId: string;
  nonce: Buffer;
  ciphertextStart: number;
  ciphertextEnd: number;
  tag: Buffer;
}

function buildBackupHeader(keyId: string, nonce: Buffer): Buffer {
  const keyIdBytes = Buffer.from(keyId, "utf8");
  if (!BACKUP_KEY_ID_PATTERN.test(keyId) || keyIdBytes.byteLength > BACKUP_MAX_KEY_ID_BYTES || nonce.byteLength !== BACKUP_NONCE_BYTES) {
    throw new BrokerError("PRECONDITION_FAILED", "Broker backup encryption header is malformed");
  }
  const header = Buffer.alloc(BACKUP_HEADER_PREFIX_BYTES + keyIdBytes.byteLength + BACKUP_NONCE_BYTES);
  BACKUP_MAGIC.copy(header, 0);
  header.writeUInt8(BACKUP_FORMAT_VERSION, BACKUP_MAGIC.byteLength);
  header.writeUInt16BE(keyIdBytes.byteLength, BACKUP_MAGIC.byteLength + 1);
  keyIdBytes.copy(header, BACKUP_HEADER_PREFIX_BYTES);
  nonce.copy(header, BACKUP_HEADER_PREFIX_BYTES + keyIdBytes.byteLength);
  return header;
}

async function readAt(handle: Awaited<ReturnType<typeof open>>, target: Buffer, position: number): Promise<void> {
  let offset = 0;
  while (offset < target.byteLength) {
    const result = await handle.read(target, offset, target.byteLength - offset, position + offset);
    if (result.bytesRead <= 0) throw new BrokerError("AUDIT_UNAVAILABLE", "Encrypted Broker backup is truncated");
    offset += result.bytesRead;
  }
}

async function writeAll(handle: Awaited<ReturnType<typeof open>>, value: Uint8Array): Promise<void> {
  let offset = 0;
  while (offset < value.byteLength) {
    const result = await handle.write(value, offset, value.byteLength - offset);
    if (result.bytesWritten <= 0) throw new BrokerError("AUDIT_UNAVAILABLE", "Encrypted Broker backup could not be written", true);
    offset += result.bytesWritten;
  }
}

async function readBackupHeader(
  handle: Awaited<ReturnType<typeof open>>,
  fileSize: number
): Promise<BackupHeader> {
  if (!Number.isSafeInteger(fileSize) || fileSize > MAX_ENCRYPTED_BACKUP_BYTES || fileSize < BACKUP_HEADER_PREFIX_BYTES + BACKUP_NONCE_BYTES + BACKUP_TAG_BYTES) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Encrypted Broker backup size is invalid");
  }
  const prefix = Buffer.alloc(BACKUP_HEADER_PREFIX_BYTES);
  await readAt(handle, prefix, 0);
  if (!prefix.subarray(0, BACKUP_MAGIC.byteLength).equals(BACKUP_MAGIC) ||
      prefix.readUInt8(BACKUP_MAGIC.byteLength) !== BACKUP_FORMAT_VERSION) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Encrypted Broker backup format is unsupported");
  }
  const keyIdBytes = prefix.readUInt16BE(BACKUP_MAGIC.byteLength + 1);
  if (keyIdBytes < 1 || keyIdBytes > BACKUP_MAX_KEY_ID_BYTES) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Encrypted Broker backup key identity is malformed");
  }
  const header = Buffer.alloc(BACKUP_HEADER_PREFIX_BYTES + keyIdBytes + BACKUP_NONCE_BYTES);
  prefix.copy(header);
  await readAt(handle, header.subarray(BACKUP_HEADER_PREFIX_BYTES), BACKUP_HEADER_PREFIX_BYTES);
  const keyId = header.subarray(BACKUP_HEADER_PREFIX_BYTES, BACKUP_HEADER_PREFIX_BYTES + keyIdBytes).toString("utf8");
  if (!BACKUP_KEY_ID_PATTERN.test(keyId) || Buffer.byteLength(keyId, "utf8") !== keyIdBytes) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Encrypted Broker backup key identity is malformed");
  }
  const nonce = Buffer.from(header.subarray(BACKUP_HEADER_PREFIX_BYTES + keyIdBytes));
  const tagOffset = fileSize - BACKUP_TAG_BYTES;
  const tag = Buffer.alloc(BACKUP_TAG_BYTES);
  await readAt(handle, tag, tagOffset);
  return {
    bytes: header,
    keyId,
    nonce,
    ciphertextStart: header.byteLength,
    ciphertextEnd: tagOffset - 1,
    tag
  };
}

async function encryptBackupSnapshot(sourcePath: string, destinationPath: string, keySource: BrokerBackupKeySource): Promise<void> {
  const source = await open(sourcePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  let destination: Awaited<ReturnType<typeof open>> | undefined;
  let key: Buffer | undefined;
  try {
    destination = await open(destinationPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    const sourceStat = await source.stat();
    if (!sourceStat.isFile() || sourceStat.isSymbolicLink() || (sourceStat.mode & 0o777) !== 0o600 || !isOwnedByCurrentUser(sourceStat.uid)) {
      throw new BrokerError("POLICY_DENIED", "Broker backup source is not protected");
    }
    key = await loadBackupKey(keySource);
    const header = buildBackupHeader(keySource.keyId, randomBytes(BACKUP_NONCE_BYTES));
    const cipher = createCipheriv(BACKUP_CIPHER, key, header.subarray(header.byteLength - BACKUP_NONCE_BYTES));
    cipher.setAAD(header);
    await writeAll(destination, header);
    const buffer = Buffer.alloc(BACKUP_READ_CHUNK_BYTES);
    let position = 0;
    while (position < sourceStat.size) {
      const result = await source.read(buffer, 0, Math.min(buffer.byteLength, sourceStat.size - position), position);
      if (result.bytesRead <= 0) throw new BrokerError("AUDIT_UNAVAILABLE", "Broker backup source ended unexpectedly");
      position += result.bytesRead;
      await writeAll(destination, cipher.update(buffer.subarray(0, result.bytesRead)));
    }
    await writeAll(destination, cipher.final());
    await writeAll(destination, cipher.getAuthTag());
    await destination.sync();
    const sourceAfter = await source.stat();
    if (!sameFileIdentity(sourceStat, sourceAfter)) throw new BrokerError("CONFLICT", "Broker backup source changed during encryption", true);
  } finally {
    key?.fill(0);
    await destination?.close();
    await source.close();
  }
}

async function decryptBackupSnapshot(sourcePath: string, destinationPath: string, keySource: BrokerBackupKeySource): Promise<void> {
  const source = await open(sourcePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  let destination: Awaited<ReturnType<typeof open>> | undefined;
  let destinationIdentity: Awaited<ReturnType<typeof lstat>> | undefined;
  let key: Buffer | undefined;
  try {
    destination = await open(destinationPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    destinationIdentity = await destination.stat();
    const sourceStat = await source.stat();
    if (!sourceStat.isFile() || sourceStat.isSymbolicLink() || (sourceStat.mode & 0o777) !== 0o600 || !isOwnedByCurrentUser(sourceStat.uid)) {
      throw new BrokerError("POLICY_DENIED", "Encrypted Broker backup source is not protected");
    }
    const parsed = await readBackupHeader(source, sourceStat.size);
    if (parsed.keyId !== keySource.keyId) throw new BrokerError("POLICY_DENIED", "Broker backup key identity does not match the configured source");
    key = await loadBackupKey(keySource);
    const decipher = createDecipheriv(BACKUP_CIPHER, key, parsed.nonce);
    decipher.setAAD(parsed.bytes);
    decipher.setAuthTag(parsed.tag);
    let position = parsed.ciphertextStart;
    const buffer = Buffer.alloc(BACKUP_READ_CHUNK_BYTES);
    while (position <= parsed.ciphertextEnd) {
      const amount = Math.min(buffer.byteLength, parsed.ciphertextEnd - position + 1);
      const result = await source.read(buffer, 0, amount, position);
      if (result.bytesRead <= 0) throw new BrokerError("AUDIT_UNAVAILABLE", "Encrypted Broker backup ciphertext is truncated");
      position += result.bytesRead;
      await writeAll(destination, decipher.update(buffer.subarray(0, result.bytesRead)));
    }
    await writeAll(destination, decipher.final());
    await destination.sync();
    const sourceAfter = await source.stat();
    if (!sameFileIdentity(sourceStat, sourceAfter)) throw new BrokerError("CONFLICT", "Encrypted Broker backup changed during decryption", true);
  } catch (error) {
    if (destinationIdentity !== undefined) {
      const current = await lstat(destinationPath).catch(() => undefined);
      if (current !== undefined && sameFileIdentity(destinationIdentity, current)) {
        await unlink(destinationPath).catch(() => undefined);
      }
    }
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("AUDIT_UNAVAILABLE", "Encrypted Broker backup could not be decrypted", true);
  } finally {
    key?.fill(0);
    await destination?.close();
    await source.close();
  }
}

interface EncryptedBackupSummary {
  bytes: number;
  sha256: string;
  auditEventCount: number;
  auditTailHash: string;
  plaintextSha256: string;
  keyId: string;
}

async function inspectEncryptedBackup(
  path: string,
  keySource: BrokerBackupKeySource,
  verificationPath = join(dirname(path), `.${basename(path).replace(/\.enc$/u, "")}.tmp-${randomBytes(12).toString("hex")}`)
): Promise<EncryptedBackupSummary> {
  const source = await validateProtectedFile(path);
  const handle = await open(source.path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const parsed = await readBackupHeader(handle, Number(source.stat.size));
    if (parsed.keyId !== keySource.keyId) throw new BrokerError("POLICY_DENIED", "Broker backup key identity does not match the configured source");
  } finally {
    await handle.close();
  }
  try {
    await decryptBackupSnapshot(source.path, verificationPath, keySource);
    await chmod(verificationPath, 0o600);
    const plaintext = await inspectSnapshot(verificationPath);
    const sourceAfter = await lstat(source.path);
    if (!sameFileIdentity(source.stat, sourceAfter)) throw new BrokerError("CONFLICT", "Encrypted Broker backup changed during inspection", true);
    const encryptedHash = await hashFile(source.path);
    const sourceAfterHash = await lstat(source.path);
    if (!sameFileIdentity(source.stat, sourceAfterHash)) throw new BrokerError("CONFLICT", "Encrypted Broker backup changed during hashing", true);
    return {
      bytes: Number(sourceAfterHash.size),
      sha256: encryptedHash,
      auditEventCount: plaintext.auditEventCount,
      auditTailHash: plaintext.auditTailHash,
      plaintextSha256: plaintext.sha256,
      keyId: keySource.keyId
    };
  } finally {
    await cleanupTemporaryBackupFiles(verificationPath).catch(() => undefined);
  }
}

type BrokerBackupSnapshotSummary = Pick<BrokerBackupManifest, "bytes" | "sha256" | "auditEventCount" | "auditTailHash">;

async function inspectSnapshot(path: string): Promise<BrokerBackupSnapshotSummary> {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o600 || !isOwnedByCurrentUser(stat.uid)) {
    throw new BrokerError("POLICY_DENIED", "Broker persistence snapshot must be an owner-only regular file");
  }
  if (stat.size > MAX_BACKUP_BYTES) throw new BrokerError("AUDIT_UNAVAILABLE", "Broker persistence snapshot exceeds the byte budget");
  const database = new DatabaseSync(path, { readOnly: true });
  let summary: BrokerBackupSnapshotSummary;
  try {
    const check = database.prepare("PRAGMA quick_check").get() as { quick_check?: unknown } | undefined;
    if (check?.quick_check !== "ok") throw new BrokerError("AUDIT_UNAVAILABLE", "Broker persistence snapshot failed SQLite integrity check");
    const rows = database.prepare(`
      SELECT request_id, principal_id, tool, event_type, decision, result_class,
        target_ref, policy_version, evidence_json, timestamp_ms, previous_hash, event_hash
      FROM audit_events ORDER BY sequence
    `).all() as Array<Record<string, unknown>>;
    let previousHash = "0".repeat(64);
    for (const row of rows) {
      if (row.previous_hash !== previousHash || typeof row.evidence_json !== "string") {
        throw new BrokerError("AUDIT_UNAVAILABLE", "Broker persistence snapshot failed audit integrity verification");
      }
      let evidence: unknown;
      try { evidence = JSON.parse(row.evidence_json); }
      catch { throw new BrokerError("AUDIT_UNAVAILABLE", "Broker persistence snapshot contains malformed audit evidence"); }
      const expected = sha256(canonicalJson({
        requestId: row.request_id,
        principalId: row.principal_id,
        tool: row.tool,
        eventType: row.event_type,
        decision: row.decision,
        resultClass: row.result_class,
        targetRef: row.target_ref,
        policyVersion: row.policy_version,
        evidence,
        timestampMs: row.timestamp_ms,
        previousHash
      }));
      if (row.event_hash !== expected) throw new BrokerError("AUDIT_UNAVAILABLE", "Broker persistence snapshot failed audit hash verification");
      previousHash = expected;
    }
    summary = {
      bytes: stat.size,
      sha256: await hashFile(path),
      auditEventCount: rows.length,
      auditTailHash: previousHash
    };
  } finally {
    database.close();
  }
  const current = await lstat(path);
  if (!sameFileIdentity(stat, current)) throw new BrokerError("CONFLICT", "Broker persistence snapshot changed during verification", true);
  return summary;
}

async function hashFile(path: string): Promise<string> {
  const hash = createHash("sha256");
  let bytes = 0;
  for await (const chunk of createReadStream(path, { highWaterMark: 64 * 1024 })) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += buffer.byteLength;
    if (bytes > MAX_BACKUP_BYTES) throw new BrokerError("AUDIT_UNAVAILABLE", "Broker persistence snapshot exceeds the byte budget");
    hash.update(buffer);
  }
  return hash.digest("hex");
}
