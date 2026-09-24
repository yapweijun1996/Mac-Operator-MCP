import { constants } from "node:fs";
import { randomBytes } from "node:crypto";
import { lstat, link, open, readdir, rename, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { BrokerError, decodeUtf8Strict } from "@mac-operator/contracts";
import { validateProtectedDirectory } from "./persistence-backup.js";

const AUDIT_ARCHIVE_PATTERN = /^audit-export-(\d{1,16})-([a-f0-9]{24})\.json\.enc$/u;
const LEDGER_ARCHIVE_PATTERN = /^ledger-export-(\d{1,16})-([a-f0-9]{24})\.json\.enc$/u;
const ARCHIVE_TEMP_PATTERN = /^\.(?:audit|ledger)-export-\d{1,16}-[a-f0-9]{24}\.json\.enc\.tmp-[a-f0-9]{24}$/u;
const ARCHIVE_QUARANTINE_PATTERN = /^\.(?:audit|ledger)-export-\d{1,16}-[a-f0-9]{24}\.json\.enc\.prune-\d{1,16}-[a-f0-9]{24}$/u;
const MAX_ARCHIVE_FILES = 512;
const MAX_ARCHIVE_RETAIN_COUNT = 100_000;
const MAX_ARCHIVE_MIN_AGE_MS = 365 * 24 * 60 * 60 * 1000;
const MAX_ARCHIVE_BYTES = 129 * 1024 * 1024;
const ARCHIVE_MAGIC_BYTES = 8;
const ARCHIVE_HEADER_PREFIX_BYTES = ARCHIVE_MAGIC_BYTES + 1 + 2;
const ARCHIVE_NONCE_BYTES = 12;
const ARCHIVE_TAG_BYTES = 16;
const ARCHIVE_KEY_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;

export interface ArchivePruneOptions {
  retainAuditCount: number;
  retainLedgerCount: number;
  minAgeMs: number;
  nowMs?: number;
}

export interface ArchivePruneResult {
  directory: string;
  retainedAudit: readonly string[];
  retainedLedger: readonly string[];
  removedAudit: readonly string[];
  removedLedger: readonly string[];
}

interface ArchiveEntry {
  kind: "audit" | "ledger";
  name: string;
  path: string;
  createdAtMs: number;
  stat: Awaited<ReturnType<typeof lstat>>;
}

/**
 * Removes only owner-created encrypted archive names after a complete
 * protected-directory and candidate-identity readback. Recent files are
 * always retained, even when the requested count is zero.
 */
export async function pruneArchiveArtifacts(
  directory: string,
  options: ArchivePruneOptions
): Promise<ArchivePruneResult> {
  const nowMs = validateOptions(options);
  const protectedDirectory = await validateProtectedDirectory(directory);
  const entries = await readdir(protectedDirectory, { withFileTypes: true });
  if (entries.length > MAX_ARCHIVE_FILES * 2) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Archive directory exceeds the bounded entry budget");
  }
  if (entries.some((entry) => ARCHIVE_TEMP_PATTERN.test(entry.name) || ARCHIVE_QUARANTINE_PATTERN.test(entry.name))) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Archive directory contains an unfinished retention artifact");
  }

  const candidates = entries.flatMap((entry): ArchiveEntry[] => {
    const auditMatch = AUDIT_ARCHIVE_PATTERN.exec(entry.name);
    const ledgerMatch = LEDGER_ARCHIVE_PATTERN.exec(entry.name);
    if (auditMatch === null && ledgerMatch === null) return [];
    const match = auditMatch ?? ledgerMatch!;
    const createdAtMs = Number(match[1]);
    if (!Number.isSafeInteger(createdAtMs) || createdAtMs < 0) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Archive filename timestamp is malformed");
    }
    const path = join(protectedDirectory, entry.name);
    return [{
      kind: auditMatch === null ? "ledger" : "audit",
      name: entry.name,
      path,
      createdAtMs,
      stat: undefined as never
    }];
  });
  if (candidates.length > MAX_ARCHIVE_FILES) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Archive directory exceeds the bounded archive-file budget");
  }

  for (const candidate of candidates) {
    candidate.stat = await lstat(candidate.path);
    if (!candidate.stat.isFile() || candidate.stat.isSymbolicLink() ||
        (candidate.stat.mode & 0o777) !== 0o600 || !isOwnedByCurrentUser(candidate.stat.uid) ||
        candidate.stat.size > MAX_ARCHIVE_BYTES) {
        throw new BrokerError("AUDIT_UNAVAILABLE", "Archive directory contains an unsafe archive entry");
    }
    await validateArchiveHeader(candidate);
  }

  const cutoffMs = nowMs - options.minAgeMs;
  const toRemove = new Set<string>();
  for (const kind of ["audit", "ledger"] as const) {
    const retainCount = kind === "audit" ? options.retainAuditCount : options.retainLedgerCount;
    const eligible = candidates
      .filter((candidate) => candidate.kind === kind && candidate.createdAtMs <= cutoffMs)
      .sort(compareNewestFirst);
    for (const candidate of eligible.slice(retainCount)) toRemove.add(candidate.path);
  }

  const removedAudit: string[] = [];
  const removedLedger: string[] = [];
  const removalCandidates = candidates
    .filter((candidate) => toRemove.has(candidate.path))
    .sort((left, right) => left.kind.localeCompare(right.kind) || left.createdAtMs - right.createdAtMs || left.name.localeCompare(right.name));
  for (const candidate of removalCandidates) {
    await removeExactArchiveFile(candidate.path, candidate.stat);
    (candidate.kind === "audit" ? removedAudit : removedLedger).push(candidate.path);
  }
  if (removedAudit.length > 0 || removedLedger.length > 0) await syncDirectory(protectedDirectory);

  return {
    directory: protectedDirectory,
    retainedAudit: candidates.filter((candidate) => candidate.kind === "audit" && !toRemove.has(candidate.path)).sort(compareNewestFirst).map((candidate) => candidate.path),
    retainedLedger: candidates.filter((candidate) => candidate.kind === "ledger" && !toRemove.has(candidate.path)).sort(compareNewestFirst).map((candidate) => candidate.path),
    removedAudit,
    removedLedger
  };
}

function validateOptions(options: ArchivePruneOptions): number {
  const nowMs = options?.nowMs ?? Date.now();
  if (options === null || typeof options !== "object" ||
      !Number.isSafeInteger(options.retainAuditCount) || options.retainAuditCount < 0 || options.retainAuditCount > MAX_ARCHIVE_RETAIN_COUNT ||
      !Number.isSafeInteger(options.retainLedgerCount) || options.retainLedgerCount < 0 || options.retainLedgerCount > MAX_ARCHIVE_RETAIN_COUNT ||
      !Number.isSafeInteger(options.minAgeMs) || options.minAgeMs < 0 || options.minAgeMs > MAX_ARCHIVE_MIN_AGE_MS ||
      !Number.isSafeInteger(nowMs) || nowMs < 0 || nowMs > 9_999_999_999_999_999) {
    throw new BrokerError("PRECONDITION_FAILED", "Archive retention options are malformed");
  }
  return nowMs;
}

function compareNewestFirst(left: ArchiveEntry, right: ArchiveEntry): number {
  return right.createdAtMs - left.createdAtMs || right.name.localeCompare(left.name);
}

async function removeExactArchiveFile(
  path: string,
  expected: Awaited<ReturnType<typeof lstat>>
): Promise<void> {
  const current = await lstat(path).catch((error: unknown) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  });
  if (current === undefined) throw new BrokerError("CONFLICT", "Archive changed before retention cleanup", true);
  if (!sameIdentity(expected, current)) throw new BrokerError("CONFLICT", "Archive changed before retention cleanup", true);
  const quarantine = `${path}.prune-${Date.now()}-${randomSuffix()}`;
  try {
    await rename(path, quarantine);
    const quarantined = await lstat(quarantine);
    if (!sameIdentity(expected, quarantined)) {
      throw new BrokerError("CONFLICT", "Archive changed during retention cleanup", true);
    }
    await unlink(quarantine);
    await syncDirectory(dirname(path));
  } catch (error) {
    const quarantined = await lstat(quarantine).catch(() => undefined);
    if (quarantined !== undefined && sameIdentity(expected, quarantined)) {
      try {
        await link(quarantine, path);
        await unlink(quarantine);
      } catch {
        // Preserve the quarantine artifact for explicit stopped-service recovery.
      }
    }
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("AUDIT_UNAVAILABLE", "Archive retention cleanup could not be verified", true);
  }
}

async function validateArchiveHeader(candidate: ArchiveEntry): Promise<void> {
  const handle = await open(candidate.path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat({ bigint: false });
    if (!sameIdentity(candidate.stat, opened)) throw new BrokerError("CONFLICT", "Archive changed while opening", true);
    if (opened.size <= ARCHIVE_HEADER_PREFIX_BYTES + ARCHIVE_NONCE_BYTES + ARCHIVE_TAG_BYTES) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Archive is truncated");
    }
    const prefix = Buffer.alloc(ARCHIVE_HEADER_PREFIX_BYTES);
    await readFully(handle, prefix, 0);
    const expectedMagic = Buffer.from(candidate.kind === "audit" ? "MOPSAUD1" : "MOPSLDG1", "ascii");
    const keyIdBytes = prefix.readUInt16BE(ARCHIVE_MAGIC_BYTES + 1);
    if (!prefix.subarray(0, ARCHIVE_MAGIC_BYTES).equals(expectedMagic) ||
        prefix.readUInt8(ARCHIVE_MAGIC_BYTES) !== 1 || keyIdBytes < 1 || keyIdBytes > 128 ||
        opened.size <= ARCHIVE_HEADER_PREFIX_BYTES + keyIdBytes + ARCHIVE_NONCE_BYTES + ARCHIVE_TAG_BYTES) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Archive header is malformed");
    }
    const headerTail = Buffer.alloc(keyIdBytes + ARCHIVE_NONCE_BYTES);
    await readFully(handle, headerTail, ARCHIVE_HEADER_PREFIX_BYTES);
    const keyId = decodeUtf8Strict(headerTail.subarray(0, keyIdBytes));
    if (!ARCHIVE_KEY_ID_PATTERN.test(keyId) || Buffer.byteLength(keyId, "utf8") !== keyIdBytes) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Archive key identity is malformed");
    }
    const after = await handle.stat({ bigint: false });
    if (!sameIdentity(opened, after)) throw new BrokerError("CONFLICT", "Archive changed while reading", true);
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("AUDIT_UNAVAILABLE", "Archive header could not be verified");
  } finally {
    await handle.close();
  }
}

async function readFully(handle: Awaited<ReturnType<typeof open>>, buffer: Buffer, position: number): Promise<void> {
  let offset = 0;
  while (offset < buffer.byteLength) {
    const result = await handle.read(buffer, offset, buffer.byteLength - offset, position + offset);
    if (result.bytesRead <= 0) throw new BrokerError("AUDIT_UNAVAILABLE", "Archive is truncated");
    offset += result.bytesRead;
  }
}

function randomSuffix(): string {
  return randomBytes(12).toString("hex");
}

async function syncDirectory(directory: string): Promise<void> {
  const handle = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function sameIdentity(left: Awaited<ReturnType<typeof lstat>>, right: Awaited<ReturnType<typeof lstat>>): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid && left.gid === right.gid &&
    left.mode === right.mode && left.size === right.size && left.mtimeMs === right.mtimeMs;
}

function isOwnedByCurrentUser(uid: number): boolean {
  return typeof process.getuid === "function" && uid === process.getuid();
}
