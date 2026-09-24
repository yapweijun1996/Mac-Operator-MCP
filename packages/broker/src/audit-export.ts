import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { chmod, link, lstat, open, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { BrokerError, canonicalJson, decodeUtf8Strict, parseJsonStrict, sha256 } from "@mac-operator/contracts";
import { ARCHIVE_CAPACITY_HEADROOM_BYTES, assertArchiveCapacity, type ArchiveCapacityProbe } from "./archive-capacity.js";
import { validateProtectedDirectory, type BrokerBackupKeySource } from "./persistence-backup.js";
import { isPlainDataRecord } from "./plain-record.js";

const AUDIT_EXPORT_MAGIC = Buffer.from("MOPSAUD1", "ascii");
const AUDIT_EXPORT_VERSION = 1;
const AUDIT_EXPORT_NAME_PATTERN = /^audit-export-(\d{1,16})-([a-f0-9]{24})\.json\.enc$/u;
const AUDIT_EXPORT_TEMP_PATTERN = /^\.audit-export-\d{1,16}-[a-f0-9]{24}\.json\.enc\.tmp-[a-f0-9]{24}$/u;
const AUDIT_EXPORT_KEY_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
const AUDIT_EXPORT_HASH_PATTERN = /^[a-f0-9]{64}$/u;
const AUDIT_EXPORT_NONCE_BYTES = 12;
const AUDIT_EXPORT_TAG_BYTES = 16;
const AUDIT_EXPORT_HEADER_PREFIX_BYTES = AUDIT_EXPORT_MAGIC.byteLength + 1 + 2;
const AUDIT_EXPORT_MAX_KEY_ID_BYTES = 128;
const AUDIT_EXPORT_MAX_PLAINTEXT_BYTES = 128 * 1024 * 1024 + 256 * 1024;
const AUDIT_EXPORT_MAX_ENCRYPTED_BYTES = AUDIT_EXPORT_MAX_PLAINTEXT_BYTES + AUDIT_EXPORT_MAX_KEY_ID_BYTES + 64;
const AUDIT_EXPORT_MAX_EVENTS = 1_000_000;

export interface AuditArchiveEvent {
  sequence: number;
  request_id: string;
  principal_id: string;
  tool: string;
  event_type: string;
  decision: string;
  result_class: string;
  target_ref: string;
  policy_version: string;
  evidence_json: string;
  timestamp_ms: number;
  previous_hash: string;
  event_hash: string;
}

interface AuditArchivePayload {
  format: "mac-operator-audit-export-v1";
  schemaVersion: 1;
  createdAtMs: number;
  events: readonly AuditArchiveEvent[];
  integrity: {
    eventCount: number;
    firstSequence: number | null;
    tailSequence: number | null;
    tailHash: string | null;
  };
}

export interface AuditArchiveManifest {
  path: string;
  createdAtMs: number;
  bytes: number;
  sha256: string;
  auditEventCount: number;
  firstSequence: number | null;
  tailSequence: number | null;
  auditTailHash: string | null;
  encrypted: true;
  keyId: string;
}

export interface AuditArchiveOptions {
  /** Required protected key source; missing material fails closed. */
  keySource?: BrokerBackupKeySource;
  nowMs?: number;
  /** @internal Test-only capacity probe; production callers must leave this unset. */
  capacityProbe?: ArchiveCapacityProbe;
}

/**
 * Writes a redacted audit-chain snapshot as an owner-only encrypted artifact.
 * The source rows must already have passed BrokerStore's stored-row checks.
 * This function never removes, compacts, or rewrites the live audit ledger.
 */
export async function createAuditArchive(
  rows: readonly Record<string, unknown>[],
  directory: string,
  options: AuditArchiveOptions = {}
): Promise<AuditArchiveManifest> {
  const keySource = validateKeySource(options.keySource);
  const createdAtMs = options.nowMs ?? Date.now();
  validateTimestamp(createdAtMs);
  const events = normalizeAuditEvents(rows);
  const payload = buildPayload(events, createdAtMs);
  const plaintext = Buffer.from(canonicalJson(payload), "utf8");
  if (plaintext.byteLength > AUDIT_EXPORT_MAX_PLAINTEXT_BYTES) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export exceeds its bounded byte budget");
  }

  const protectedDirectory = await validateProtectedDirectory(directory);
  await assertArchiveCapacity(
    protectedDirectory,
    plaintext.byteLength + ARCHIVE_CAPACITY_HEADROOM_BYTES,
    options.capacityProbe
  );
  const name = `audit-export-${createdAtMs}-${randomBytes(12).toString("hex")}.json.enc`;
  const destination = join(protectedDirectory, name);
  const temporary = join(protectedDirectory, `.${name}.tmp-${randomBytes(12).toString("hex")}`);
  const key = await loadKey(keySource);
  try {
    await writeEncryptedFile(temporary, plaintext, keySource.keyId, key);
    const temporaryIdentity = await lstat(temporary);
    const inspected = await inspectAuditArchiveFile(temporary, keySource, true);
    if (inspected.auditEventCount !== events.length || inspected.createdAtMs !== createdAtMs) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export failed encrypted readback");
    }
    await publishExclusive(temporary, destination, temporaryIdentity);
    await syncDirectory(protectedDirectory);
    const final = await inspectAuditArchive(destination, keySource);
    if (final.auditEventCount !== events.length || final.createdAtMs !== createdAtMs) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export changed during publication");
    }
    return final;
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export could not be created", true);
  } finally {
    key.fill(0);
    await removeExactTemporary(temporary).catch(() => undefined);
    plaintext.fill(0);
  }
}

/** Inspect and verify an encrypted archive without returning audit rows. */
export async function inspectAuditArchive(
  path: string,
  keySource?: BrokerBackupKeySource
): Promise<AuditArchiveManifest> {
  return inspectAuditArchiveFile(path, validateKeySource(keySource), false);
}

async function inspectAuditArchiveFile(
  path: string,
  keySource: BrokerBackupKeySource,
  temporary: boolean
): Promise<AuditArchiveManifest> {
  const validatedPath = validateArchivePath(path, temporary);
  await validateProtectedDirectory(dirname(validatedPath));
  const ciphertext = await readProtectedArchive(validatedPath);
  const key = await loadKey(keySource);
  try {
    const payload = decryptPayload(ciphertext, keySource.keyId, key);
    const parsed = parseJsonStrict(decodeUtf8Strict(payload));
    const archive = validatePayload(parsed);
    return {
      path: validatedPath,
      createdAtMs: archive.createdAtMs,
      bytes: ciphertext.byteLength,
      sha256: sha256(ciphertext),
      auditEventCount: archive.integrity.eventCount,
      firstSequence: archive.integrity.firstSequence,
      tailSequence: archive.integrity.tailSequence,
      auditTailHash: archive.integrity.tailHash,
      encrypted: true,
      keyId: keySource.keyId
    };
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export failed integrity verification");
  } finally {
    key.fill(0);
    ciphertext.fill(0);
  }
}

function buildPayload(events: readonly AuditArchiveEvent[], createdAtMs: number): AuditArchivePayload {
  const last = events.at(-1);
  return {
    format: "mac-operator-audit-export-v1",
    schemaVersion: 1,
    createdAtMs,
    events,
    integrity: {
      eventCount: events.length,
      firstSequence: events[0]?.sequence ?? null,
      tailSequence: last?.sequence ?? null,
      tailHash: last?.event_hash ?? null
    }
  };
}

function normalizeAuditEvents(rows: readonly Record<string, unknown>[]): AuditArchiveEvent[] {
  if (!Array.isArray(rows) || rows.length > AUDIT_EXPORT_MAX_EVENTS) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export event count is outside the supported range");
  }
  const events: AuditArchiveEvent[] = [];
  let previousSequence = 0;
  let previousHash = "0".repeat(64);
  for (const row of rows) {
    if (!isPlainDataRecord(row) || !hasExactKeys(row, [
      "sequence", "request_id", "principal_id", "tool", "event_type", "decision",
      "result_class", "target_ref", "policy_version", "evidence_json", "timestamp_ms",
      "previous_hash", "event_hash"
    ])) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export contains an unexpected row shape");
    }
    const event = row as unknown as AuditArchiveEvent;
    validateAuditArchiveEvent(event);
    if (event.sequence !== previousSequence + 1 || event.previous_hash !== previousHash) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export sequence or chain link is invalid");
    }
    const evidence = parseEvidence(event.evidence_json);
    const expectedHash = sha256(canonicalJson({
      requestId: event.request_id,
      principalId: event.principal_id,
      tool: event.tool,
      eventType: event.event_type,
      decision: event.decision,
      resultClass: event.result_class,
      targetRef: event.target_ref,
      policyVersion: event.policy_version,
      evidence,
      timestampMs: event.timestamp_ms,
      previousHash
    }));
    if (event.event_hash !== expectedHash) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export event hash is invalid");
    }
    events.push({ ...event });
    previousSequence = event.sequence;
    previousHash = event.event_hash;
  }
  return events;
}

function validatePayload(value: unknown): AuditArchivePayload {
  if (!isPlainDataRecord(value) || !hasExactKeys(value, ["format", "schemaVersion", "createdAtMs", "events", "integrity"]) ||
      value.format !== "mac-operator-audit-export-v1" || value.schemaVersion !== 1 ||
      !Number.isSafeInteger(value.createdAtMs) || (value.createdAtMs as number) < 0 ||
      !Array.isArray(value.events) || !isPlainDataRecord(value.integrity) ||
      !hasExactKeys(value.integrity, ["eventCount", "firstSequence", "tailSequence", "tailHash"])) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export payload is malformed");
  }
  const events = normalizeAuditEvents(value.events as readonly Record<string, unknown>[]);
  const integrity = value.integrity as Record<string, unknown>;
  const eventCount = integrity.eventCount;
  const firstSequence = integrity.firstSequence;
  const tailSequence = integrity.tailSequence;
  const tailHash = integrity.tailHash;
  if (!Number.isSafeInteger(eventCount) || eventCount !== events.length ||
      (firstSequence !== null && (!Number.isSafeInteger(firstSequence) || (firstSequence as number) < 1)) ||
      (tailSequence !== null && (!Number.isSafeInteger(tailSequence) || (tailSequence as number) < 1)) ||
      (tailHash !== null && (typeof tailHash !== "string" || !AUDIT_EXPORT_HASH_PATTERN.test(tailHash)))) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export integrity summary is malformed");
  }
  const expectedFirst = events[0]?.sequence ?? null;
  const expectedTail = events.at(-1)?.sequence ?? null;
  const expectedHash = events.at(-1)?.event_hash ?? null;
  if (firstSequence !== expectedFirst || tailSequence !== expectedTail || tailHash !== expectedHash) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export integrity summary does not match its events");
  }
  return {
    format: "mac-operator-audit-export-v1",
    schemaVersion: 1,
    createdAtMs: value.createdAtMs as number,
    events,
    integrity: {
      eventCount: eventCount as number,
      firstSequence: firstSequence as number | null,
      tailSequence: tailSequence as number | null,
      tailHash: tailHash as string | null
    }
  };
}

function validateAuditArchiveEvent(event: AuditArchiveEvent): void {
  const bounded = (value: unknown, maximum: number): value is string =>
    typeof value === "string" && value.length >= 1 && value.length <= maximum && !value.includes("\0");
  if (!Number.isSafeInteger(event.sequence) || event.sequence < 1 ||
      !bounded(event.request_id, 256) || !bounded(event.principal_id, 128) ||
      !bounded(event.tool, 160) || !/^(?:mac_[a-z0-9_]{1,123}|internal_[A-Za-z0-9._:-]{1,140})$/u.test(event.tool) ||
      !["decision", "intent", "completion"].includes(event.event_type) ||
      !["allow", "deny"].includes(event.decision) || !bounded(event.result_class, 128) ||
      !bounded(event.target_ref, 4096) || !bounded(event.policy_version, 160) ||
      !bounded(event.evidence_json, 1_048_576) || !Number.isSafeInteger(event.timestamp_ms) || event.timestamp_ms < 0 ||
      !AUDIT_EXPORT_HASH_PATTERN.test(event.previous_hash) || !AUDIT_EXPORT_HASH_PATTERN.test(event.event_hash)) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export event is malformed");
  }
  parseEvidence(event.evidence_json);
}

function parseEvidence(value: string): unknown {
  try {
    return parseJsonStrict(value);
  } catch {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export evidence JSON is malformed");
  }
}

function hasExactKeys(value: Readonly<Record<string, unknown>>, keys: readonly string[]): boolean {
  const expected = new Set(keys);
  const actual = Object.keys(value);
  return actual.length === expected.size && actual.every((key) => expected.has(key));
}

function validateKeySource(value: BrokerBackupKeySource | undefined): BrokerBackupKeySource {
  if (value === undefined || value === null || typeof value !== "object" ||
      typeof value.keyId !== "string" || !AUDIT_EXPORT_KEY_ID_PATTERN.test(value.keyId) ||
      Buffer.byteLength(value.keyId, "utf8") > AUDIT_EXPORT_MAX_KEY_ID_BYTES || typeof value.loadKey !== "function") {
    throw new BrokerError("POLICY_DENIED", "Encrypted audit exports require a valid protected key source");
  }
  return value;
}

async function loadKey(source: BrokerBackupKeySource): Promise<Buffer> {
  let loaded: Uint8Array;
  try {
    loaded = await source.loadKey();
  } catch {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export encryption key is unavailable", true);
  }
  if (!(loaded instanceof Uint8Array) || loaded.byteLength !== 32) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export encryption key has an invalid length");
  }
  return Buffer.from(loaded);
}

async function writeEncryptedFile(path: string, plaintext: Buffer, keyId: string, key: Buffer): Promise<void> {
  const nonce = randomBytes(AUDIT_EXPORT_NONCE_BYTES);
  const header = buildHeader(keyId, nonce);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(header);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try {
    await writeAll(handle, Buffer.concat([header, ciphertext, tag]));
    await handle.sync();
  } finally {
    await handle.close();
    ciphertext.fill(0);
  }
  await chmod(path, 0o600);
}

function decryptPayload(file: Buffer, keyId: string, key: Buffer): Buffer {
  if (file.byteLength < AUDIT_EXPORT_HEADER_PREFIX_BYTES + AUDIT_EXPORT_NONCE_BYTES + AUDIT_EXPORT_TAG_BYTES) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export is truncated");
  }
  const prefix = file.subarray(0, AUDIT_EXPORT_HEADER_PREFIX_BYTES);
  if (!prefix.subarray(0, AUDIT_EXPORT_MAGIC.byteLength).equals(AUDIT_EXPORT_MAGIC) ||
      prefix.readUInt8(AUDIT_EXPORT_MAGIC.byteLength) !== AUDIT_EXPORT_VERSION) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export format is unsupported");
  }
  const keyIdBytes = prefix.readUInt16BE(AUDIT_EXPORT_MAGIC.byteLength + 1);
  const headerBytes = AUDIT_EXPORT_HEADER_PREFIX_BYTES + keyIdBytes + AUDIT_EXPORT_NONCE_BYTES;
  if (keyIdBytes < 1 || keyIdBytes > AUDIT_EXPORT_MAX_KEY_ID_BYTES || file.byteLength <= headerBytes + AUDIT_EXPORT_TAG_BYTES) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export header is malformed");
  }
  const header = file.subarray(0, headerBytes);
  let storedKeyId: string;
  try {
    storedKeyId = decodeUtf8Strict(header.subarray(AUDIT_EXPORT_HEADER_PREFIX_BYTES, AUDIT_EXPORT_HEADER_PREFIX_BYTES + keyIdBytes));
  } catch {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export key identity is malformed");
  }
  if (storedKeyId !== keyId || !AUDIT_EXPORT_KEY_ID_PATTERN.test(storedKeyId) ||
      Buffer.byteLength(storedKeyId, "utf8") !== keyIdBytes) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export key identity does not match");
  }
  const nonce = header.subarray(AUDIT_EXPORT_HEADER_PREFIX_BYTES + keyIdBytes);
  const tag = file.subarray(file.byteLength - AUDIT_EXPORT_TAG_BYTES);
  const ciphertext = file.subarray(headerBytes, file.byteLength - AUDIT_EXPORT_TAG_BYTES);
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAAD(header);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export authentication failed");
  }
}

function buildHeader(keyId: string, nonce: Buffer): Buffer {
  const keyIdBytes = Buffer.from(keyId, "utf8");
  if (!AUDIT_EXPORT_KEY_ID_PATTERN.test(keyId) || keyIdBytes.byteLength < 1 ||
      keyIdBytes.byteLength > AUDIT_EXPORT_MAX_KEY_ID_BYTES || nonce.byteLength !== AUDIT_EXPORT_NONCE_BYTES) {
    throw new BrokerError("PRECONDITION_FAILED", "Audit export header is malformed");
  }
  const header = Buffer.alloc(AUDIT_EXPORT_HEADER_PREFIX_BYTES + keyIdBytes.byteLength + nonce.byteLength);
  AUDIT_EXPORT_MAGIC.copy(header, 0);
  header.writeUInt8(AUDIT_EXPORT_VERSION, AUDIT_EXPORT_MAGIC.byteLength);
  header.writeUInt16BE(keyIdBytes.byteLength, AUDIT_EXPORT_MAGIC.byteLength + 1);
  keyIdBytes.copy(header, AUDIT_EXPORT_HEADER_PREFIX_BYTES);
  nonce.copy(header, AUDIT_EXPORT_HEADER_PREFIX_BYTES + keyIdBytes.byteLength);
  return header;
}

async function readProtectedArchive(path: string): Promise<Buffer> {
  const pathStat = await lstat(path).catch(() => undefined);
  if (!pathStat || !pathStat.isFile() || pathStat.isSymbolicLink() || (pathStat.mode & 0o777) !== 0o600 ||
      typeof process.getuid !== "function" || pathStat.uid !== process.getuid() || pathStat.size > AUDIT_EXPORT_MAX_ENCRYPTED_BYTES) {
    throw new BrokerError("POLICY_DENIED", "Audit export must be an owner-only bounded regular file");
  }
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat({ bigint: false });
    if (!sameIdentity(pathStat, opened)) throw new BrokerError("CONFLICT", "Audit export changed while opening", true);
    const size = opened.size;
    if (!Number.isSafeInteger(size) || size > AUDIT_EXPORT_MAX_ENCRYPTED_BYTES) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export exceeds its bounded byte budget");
    }
    const result = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
      const read = await handle.read(result, offset, size - offset, null);
      if (read.bytesRead <= 0) {
        result.fill(0);
        throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export is truncated");
      }
      offset += read.bytesRead;
    }
    const after = await handle.stat({ bigint: false });
    if (!sameIdentity(opened, after) || after.size !== result.byteLength) {
      result.fill(0);
      throw new BrokerError("CONFLICT", "Audit export changed while reading", true);
    }
    return result;
  } finally {
    await handle.close();
  }
}

function validateArchivePath(path: string, temporary: boolean): string {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path || path.includes("\0") || path.length > 4096 ||
      path !== join(dirname(path), basename(path))) {
    throw new BrokerError("PRECONDITION_FAILED", "Audit export path is malformed");
  }
  const nameValid = AUDIT_EXPORT_NAME_PATTERN.test(basename(path));
  const tempValid = AUDIT_EXPORT_TEMP_PATTERN.test(basename(path));
  if ((temporary && !tempValid) || (!temporary && !nameValid)) {
    throw new BrokerError("PRECONDITION_FAILED", "Audit export filename is invalid");
  }
  return path;
}

async function publishExclusive(
  source: string,
  destination: string,
  expected: Stats
): Promise<void> {
  try {
    await link(source, destination);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new BrokerError("CONFLICT", "Audit export publication destination already exists", true);
    }
    throw error;
  }
  const sourceAfter = await lstat(source, { bigint: false }).catch(() => undefined);
  const destinationAfter = await lstat(destination, { bigint: false }).catch(() => undefined);
  if (!sourceAfter || !destinationAfter || !sameIdentity(expected, sourceAfter) || !sameIdentity(sourceAfter, destinationAfter)) {
    throw new BrokerError("CONFLICT", "Audit export publication identity could not be verified", true);
  }
  await unlink(source);
}

async function removeExactTemporary(path: string): Promise<void> {
  const stat = await lstat(path).catch(() => undefined);
  if (!stat) return;
  if (!AUDIT_EXPORT_TEMP_PATTERN.test(basename(path)) || !stat.isFile() || stat.isSymbolicLink() ||
      (stat.mode & 0o777) !== 0o600 || typeof process.getuid !== "function" || stat.uid !== process.getuid()) return;
  const current = await lstat(path).catch(() => undefined);
  if (current && sameIdentity(stat, current)) await unlink(path);
}

async function writeAll(handle: Awaited<ReturnType<typeof open>>, value: Buffer): Promise<void> {
  let offset = 0;
  while (offset < value.byteLength) {
    const result = await handle.write(value, offset, value.byteLength - offset, null);
    if (result.bytesWritten <= 0) throw new BrokerError("AUDIT_UNAVAILABLE", "Audit export write made no progress", true);
    offset += result.bytesWritten;
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

function sameIdentity(left: Stats, right: Stats): boolean {
  // Hard-link publication updates ctime on the inode. Identity checks bind
  // the inode and content metadata while intentionally excluding that link
  // bookkeeping field.
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid && left.gid === right.gid &&
    (left.mode & 0o7777) === (right.mode & 0o7777) && left.size === right.size && left.mtimeMs === right.mtimeMs;
}

function validateTimestamp(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 9_999_999_999_999_999) {
    throw new BrokerError("PRECONDITION_FAILED", "Audit export timestamp is invalid");
  }
}
