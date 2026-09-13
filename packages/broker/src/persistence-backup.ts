import { createHash, randomBytes } from "node:crypto";
import { constants, createReadStream, type Dirent } from "node:fs";
import { chmod, copyFile, lstat, open, readdir, rename, unlink } from "node:fs/promises";
import { backup, DatabaseSync } from "node:sqlite";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";

const BACKUP_NAME_PATTERN = /^broker-backup-(\d{1,16})-([a-f0-9]{24})\.sqlite$/u;
const BACKUP_TEMP_NAME_PATTERN = /^\.broker-backup-(\d{1,16})-[a-f0-9]{24}\.sqlite\.tmp-[a-f0-9]{24}$/u;
const MAX_BACKUP_BYTES = 512 * 1024 * 1024;
const MAX_BACKUP_FILES = 256;
const MAX_BACKUP_TEMP_FILES = 256;
const BACKUP_TEMP_STALE_MS = 60 * 60 * 1000;
const DEFAULT_RETAIN_COUNT = 7;

export type BrokerBackupFaultPoint = "after_backup" | "after_temp_verify";

export interface BrokerBackupManifest {
  path: string;
  createdAtMs: number;
  bytes: number;
  sha256: string;
  auditEventCount: number;
  auditTailHash: string;
}

export interface BrokerBackupOptions {
  retainCount?: number;
  nowMs?: number;
  /** @internal Test-only crash-boundary hook; production callers must leave unset. */
  faultInjector?: (point: BrokerBackupFaultPoint) => void;
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
  const nowMs = options.nowMs ?? Date.now();
  validateNow(nowMs);
  const retainCount = options.retainCount ?? DEFAULT_RETAIN_COUNT;
  validateRetainCount(retainCount);
  const protectedDirectory = await validateProtectedDirectory(directory);
  const name = `broker-backup-${nowMs}-${randomBytes(12).toString("hex")}.sqlite`;
  const destination = join(protectedDirectory, name);
  const temporary = join(protectedDirectory, `.${name}.tmp-${randomBytes(12).toString("hex")}`);
  let moved = false;
  try {
    await backup(source, temporary, { rate: 64 });
    options.faultInjector?.("after_backup");
    await chmod(temporary, 0o600);
    await syncFile(temporary);
    const verified = await inspectSnapshot(temporary);
    options.faultInjector?.("after_temp_verify");
    await rename(temporary, destination);
    moved = true;
    await syncDirectory(protectedDirectory);
    const final = await inspectSnapshot(destination);
    if (final.sha256 !== verified.sha256 || final.auditTailHash !== verified.auditTailHash) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Broker persistence backup changed during publication");
    }
    await pruneBrokerBackups(protectedDirectory, retainCount);
    return { ...final, path: destination, createdAtMs: nowMs };
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker persistence backup could not be created", true);
  } finally {
    if (!moved) await unlink(temporary).catch(() => undefined);
  }
}

/**
 * Restores a verified backup into a new, non-existent database path. Refusing
 * an existing destination prevents this primitive from silently replacing a
 * live Broker database; an operator must select and inspect a fresh target.
 */
export async function restoreBrokerBackup(
  backupPath: string,
  destinationPath: string
): Promise<BrokerBackupManifest> {
  const source = await validateProtectedFile(backupPath);
  const sourceSummary = await inspectSnapshot(source.path);
  const destination = validateAbsolutePath(destinationPath, "Broker restore destination");
  const protectedDirectory = await validateProtectedDirectory(dirname(destination));
  if (resolve(destination) === resolve(source.path)) {
    throw new BrokerError("CONFLICT", "Broker restore destination must differ from the backup");
  }
  const existing = await lstat(destination).catch(() => undefined);
  if (existing) throw new BrokerError("CONFLICT", "Broker restore destination already exists");
  const temporary = join(protectedDirectory, `.broker-restore-${randomBytes(12).toString("hex")}.tmp`);
  let moved = false;
  try {
    await copyFile(source.path, temporary, constants.COPYFILE_EXCL);
    await chmod(temporary, 0o600);
    await syncFile(temporary);
    const sourceAfterCopy = await validateProtectedFile(source.path);
    if (!sameFileIdentity(source.stat, sourceAfterCopy.stat)) {
      throw new BrokerError("CONFLICT", "Broker backup changed during restore", true);
    }
    const copiedSummary = await inspectSnapshot(temporary);
    if (copiedSummary.sha256 !== sourceSummary.sha256 || copiedSummary.auditTailHash !== sourceSummary.auditTailHash) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Broker backup integrity changed during restore");
    }
    await rename(temporary, destination);
    moved = true;
    await syncDirectory(protectedDirectory);
    const final = await inspectSnapshot(destination);
    if (final.sha256 !== sourceSummary.sha256 || final.auditTailHash !== sourceSummary.auditTailHash) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Restored Broker database failed final integrity readback");
    }
    return { ...final, path: destination, createdAtMs: Date.now() };
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("AUDIT_UNAVAILABLE", "Broker persistence restore could not be completed", true);
  } finally {
    if (!moved) await unlink(temporary).catch(() => undefined);
  }
}

/** Deletes only exact Broker backup names while retaining the newest bounded set. */
export async function pruneBrokerBackups(directory: string, retainCount = DEFAULT_RETAIN_COUNT): Promise<BrokerBackupPruneResult> {
  validateRetainCount(retainCount);
  const protectedDirectory = await validateProtectedDirectory(directory);
  const entries = await readdir(protectedDirectory, { withFileTypes: true });
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
    if (stat.size > MAX_BACKUP_BYTES) throw new BrokerError("AUDIT_UNAVAILABLE", "Broker backup exceeds the byte budget");
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
  const stat = await lstat(path).catch(() => undefined);
  if (!stat || !stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o600 || !isOwnedByCurrentUser(stat.uid)) {
    throw new BrokerError("POLICY_DENIED", "Broker backup must be an owner-only regular file");
  }
  if (!BACKUP_NAME_PATTERN.test(basename(path)) || stat.size > MAX_BACKUP_BYTES) {
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

async function inspectSnapshot(path: string): Promise<Omit<BrokerBackupManifest, "path" | "createdAtMs">> {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o600 || !isOwnedByCurrentUser(stat.uid)) {
    throw new BrokerError("POLICY_DENIED", "Broker persistence snapshot must be an owner-only regular file");
  }
  if (stat.size > MAX_BACKUP_BYTES) throw new BrokerError("AUDIT_UNAVAILABLE", "Broker persistence snapshot exceeds the byte budget");
  const database = new DatabaseSync(path, { readOnly: true });
  let summary: Omit<BrokerBackupManifest, "path" | "createdAtMs">;
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
