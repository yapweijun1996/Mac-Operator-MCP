import { validateContainerTaskJobMetadata } from "./container-job-metadata.js";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { chmod, link, lstat, open, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import {
  BrokerError,
  canonicalJson,
  decodeUtf8Strict,
  parseJsonStrict,
  sha256,
  type CapabilityFamily
} from "@mac-operator/contracts";
import { ARCHIVE_CAPACITY_HEADROOM_BYTES, assertArchiveCapacity, type ArchiveCapacityProbe } from "./archive-capacity.js";
import { validateProtectedDirectory, type BrokerBackupKeySource } from "./persistence-backup.js";
import type { BrokerJob, GuestTaskResultJournal, RequestRecord } from "./persistence.js";
import { isValidEdgeId, isValidEdgeKeyId } from "./edge-keyring.js";
import { isPlainDataRecord } from "./plain-record.js";
import { assertContentDoesNotContainSecrets } from "./secret-policy.js";

const LEDGER_EXPORT_MAGIC = Buffer.from("MOPSLDG1", "ascii");
const LEDGER_EXPORT_VERSION = 1;
const LEDGER_EXPORT_NAME_PATTERN = /^ledger-export-(\d{1,16})-([a-f0-9]{24})\.json\.enc$/u;
const LEDGER_EXPORT_TEMP_PATTERN = /^\.ledger-export-\d{1,16}-[a-f0-9]{24}\.json\.enc\.tmp-[a-f0-9]{24}$/u;
const LEDGER_EXPORT_KEY_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
const LEDGER_EXPORT_HASH_PATTERN = /^[a-f0-9]{64}$/u;
const LEDGER_EXPORT_NONCE_BYTES = 12;
const LEDGER_EXPORT_TAG_BYTES = 16;
const LEDGER_EXPORT_HEADER_PREFIX_BYTES = LEDGER_EXPORT_MAGIC.byteLength + 1 + 2;
const LEDGER_EXPORT_MAX_KEY_ID_BYTES = 128;
const LEDGER_EXPORT_MAX_RECORDS = 100_000;
const LEDGER_EXPORT_MAX_PLAINTEXT_BYTES = 128 * 1024 * 1024 + 512 * 1024;
const LEDGER_EXPORT_MAX_ENCRYPTED_BYTES = LEDGER_EXPORT_MAX_PLAINTEXT_BYTES + LEDGER_EXPORT_MAX_KEY_ID_BYTES + 64;
const TERMINAL_REQUEST_STATES = new Set<RequestRecord["state"]>([
  "DENIED", "SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT", "VERIFICATION_FAILED", "UNKNOWN"
]);
const TERMINAL_JOB_STATES = new Set<BrokerJob["state"]>(["completed", "failed", "cancelled", "unknown"]);
const CAPABILITY_FAMILY_SET = new Set<CapabilityFamily>([
  "read", "write", "process", "network", "gui", "destructive", "privileged"
]);

export interface LedgerArchiveManifest {
  path: string;
  createdAtMs: number;
  bytes: number;
  sha256: string;
  requestCount: number;
  jobCount: number;
  snapshotDigest: string;
  encrypted: true;
  keyId: string;
}

export interface LedgerArchiveOptions {
  /** Required protected key source; missing material fails closed. */
  keySource?: BrokerBackupKeySource;
  nowMs?: number;
  /** @internal Test-only capacity probe; production callers must leave this unset. */
  capacityProbe?: ArchiveCapacityProbe;
}

interface LedgerArchivePayload {
  format: "mac-operator-ledger-export-v1";
  schemaVersion: 1;
  createdAtMs: number;
  requests: readonly RequestRecord[];
  jobs: readonly BrokerJob[];
  integrity: {
    requestCount: number;
    jobCount: number;
    snapshotDigest: string;
  };
}

/**
 * Writes an encrypted snapshot of terminal Request/Job history. This is a
 * recovery artifact only: the live SQLite ledger is never deleted or changed.
 */
export async function createLedgerArchive(
  requests: readonly RequestRecord[],
  jobs: readonly BrokerJob[],
  directory: string,
  options: LedgerArchiveOptions = {}
): Promise<LedgerArchiveManifest> {
  const keySource = validateKeySource(options.keySource);
  const createdAtMs = options.nowMs ?? Date.now();
  validateTimestamp(createdAtMs);
  const normalizedRequests = normalizeRequests(requests);
  const normalizedJobs = normalizeJobs(jobs);
  const payload = buildPayload(normalizedRequests, normalizedJobs, createdAtMs);
  const plaintext = Buffer.from(canonicalJson(payload), "utf8");
  if (plaintext.byteLength > LEDGER_EXPORT_MAX_PLAINTEXT_BYTES) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export exceeds its bounded byte budget");
  }

  const protectedDirectory = await validateProtectedDirectory(directory);
  await assertArchiveCapacity(
    protectedDirectory,
    plaintext.byteLength + ARCHIVE_CAPACITY_HEADROOM_BYTES,
    options.capacityProbe
  );
  const name = `ledger-export-${createdAtMs}-${randomBytes(12).toString("hex")}.json.enc`;
  const destination = join(protectedDirectory, name);
  const temporary = join(protectedDirectory, `.${name}.tmp-${randomBytes(12).toString("hex")}`);
  const key = await loadKey(keySource);
  try {
    await writeEncryptedFile(temporary, plaintext, keySource.keyId, key);
    const temporaryIdentity = await lstat(temporary);
    const inspected = await inspectLedgerArchiveFile(temporary, keySource, true);
    if (inspected.requestCount !== normalizedRequests.length || inspected.jobCount !== normalizedJobs.length ||
        inspected.createdAtMs !== createdAtMs || inspected.snapshotDigest !== payload.integrity.snapshotDigest) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export failed encrypted readback");
    }
    await publishExclusive(temporary, destination, temporaryIdentity);
    await syncDirectory(protectedDirectory);
    const final = await inspectLedgerArchive(destination, keySource);
    if (final.requestCount !== normalizedRequests.length || final.jobCount !== normalizedJobs.length ||
        final.createdAtMs !== createdAtMs || final.snapshotDigest !== payload.integrity.snapshotDigest) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export changed during publication");
    }
    return final;
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export could not be created", true);
  } finally {
    key.fill(0);
    await removeExactTemporary(temporary).catch(() => undefined);
    plaintext.fill(0);
  }
}

/** Inspect and verify an encrypted terminal Request/Job archive. */
export async function inspectLedgerArchive(
  path: string,
  keySource?: BrokerBackupKeySource
): Promise<LedgerArchiveManifest> {
  return inspectLedgerArchiveFile(path, validateKeySource(keySource), false);
}

async function inspectLedgerArchiveFile(
  path: string,
  keySource: BrokerBackupKeySource,
  temporary: boolean
): Promise<LedgerArchiveManifest> {
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
      requestCount: archive.integrity.requestCount,
      jobCount: archive.integrity.jobCount,
      snapshotDigest: archive.integrity.snapshotDigest,
      encrypted: true,
      keyId: keySource.keyId
    };
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export failed integrity verification");
  } finally {
    key.fill(0);
    ciphertext.fill(0);
  }
}

function buildPayload(
  requests: readonly RequestRecord[],
  jobs: readonly BrokerJob[],
  createdAtMs: number
): LedgerArchivePayload {
  const snapshotDigest = sha256(canonicalJson({ requests, jobs }));
  return {
    format: "mac-operator-ledger-export-v1",
    schemaVersion: 1,
    createdAtMs,
    requests,
    jobs,
    integrity: {
      requestCount: requests.length,
      jobCount: jobs.length,
      snapshotDigest
    }
  };
}

function normalizeRequests(rows: readonly RequestRecord[]): RequestRecord[] {
  if (!Array.isArray(rows) || rows.length > LEDGER_EXPORT_MAX_RECORDS) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export request count is outside the supported range");
  }
  const normalized = rows.map((row) => {
    validateRequestRecord(row);
    if (!TERMINAL_REQUEST_STATES.has(row.state)) {
      throw new BrokerError("CONFLICT", "Ledger export can include terminal Requests only");
    }
    return {
      requestId: row.requestId,
      edgeId: row.edgeId,
      principalId: row.principalId,
      sessionId: row.sessionId,
      tool: row.tool,
      policyVersion: row.policyVersion,
      payloadDigest: row.payloadDigest,
      mutation: row.mutation,
      capabilityFamilies: [...row.capabilityFamilies],
      state: row.state,
      resultClass: row.resultClass,
      targetRef: row.targetRef,
      approvalId: row.approvalId,
      jobId: row.jobId,
      receivedAtMs: row.receivedAtMs,
      updatedAtMs: row.updatedAtMs,
      revision: row.revision
    };
  });
  normalized.sort((left, right) => left.receivedAtMs - right.receivedAtMs || left.requestId.localeCompare(right.requestId));
  return normalized;
}

function normalizeJobs(rows: readonly BrokerJob[]): BrokerJob[] {
  if (!Array.isArray(rows) || rows.length > LEDGER_EXPORT_MAX_RECORDS) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export Job count is outside the supported range");
  }
  const normalized = rows.map((row) => {
    validateJobRecord(row);
    if (!TERMINAL_JOB_STATES.has(row.state)) {
      throw new BrokerError("CONFLICT", "Ledger export can include terminal Jobs only");
    }
    return {
      jobId: row.jobId,
      ownerEdgeId: row.ownerEdgeId,
      ownerEdgeKeyId: row.ownerEdgeKeyId,
      ownerPrincipalId: row.ownerPrincipalId,
      ownerSessionId: row.ownerSessionId,
      tool: row.tool,
      targetRef: row.targetRef,
      policyVersion: row.policyVersion,
      payloadDigest: row.payloadDigest,
      idempotencyKey: row.idempotencyKey,
      state: row.state,
      resultClass: row.resultClass,
      createdAtMs: row.createdAtMs,
      startedAtMs: row.startedAtMs,
      finishedAtMs: row.finishedAtMs,
      exitCode: row.exitCode,
      stdout: row.stdout,
      stderr: row.stderr,
      truncated: row.truncated,
      cancelRequested: row.cancelRequested,
      revision: row.revision,
      ...(row.writeMetadata === undefined ? {} : { writeMetadata: row.writeMetadata }),
      ...(row.processMetadata === undefined ? {} : { processMetadata: row.processMetadata }),
      ...(row.guestMetadata === undefined ? {} : { guestMetadata: row.guestMetadata }),
      ...(row.containerMetadata === undefined ? {} : { containerMetadata: row.containerMetadata }),
      ...(row.guestResultJournal === undefined ? {} : { guestResultJournal: row.guestResultJournal }),
      ...(row.serviceMetadata === undefined ? {} : { serviceMetadata: row.serviceMetadata }),
      ...(row.privilegedPayload === undefined ? {} : { privilegedPayload: row.privilegedPayload })
    };
  });
  normalized.sort((left, right) => left.createdAtMs - right.createdAtMs || left.jobId.localeCompare(right.jobId));
  return normalized;
}

function validatePayload(value: unknown): LedgerArchivePayload {
  if (!isPlainDataRecord(value) || !hasExactKeys(value, ["format", "schemaVersion", "createdAtMs", "requests", "jobs", "integrity"]) ||
      value.format !== "mac-operator-ledger-export-v1" || value.schemaVersion !== 1 ||
      !Number.isSafeInteger(value.createdAtMs) || (value.createdAtMs as number) < 0 ||
      !Array.isArray(value.requests) || !Array.isArray(value.jobs) || !isPlainDataRecord(value.integrity) ||
      !hasExactKeys(value.integrity, ["requestCount", "jobCount", "snapshotDigest"])) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export payload is malformed");
  }
  const requests = normalizeRequests(value.requests as readonly RequestRecord[]);
  const jobs = normalizeJobs(value.jobs as readonly BrokerJob[]);
  const integrity = value.integrity as Record<string, unknown>;
  if (!Number.isSafeInteger(integrity.requestCount) || integrity.requestCount !== requests.length ||
      !Number.isSafeInteger(integrity.jobCount) || integrity.jobCount !== jobs.length ||
      typeof integrity.snapshotDigest !== "string" || !LEDGER_EXPORT_HASH_PATTERN.test(integrity.snapshotDigest)) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export integrity summary is malformed");
  }
  const snapshotDigest = sha256(canonicalJson({ requests, jobs }));
  if (integrity.snapshotDigest !== snapshotDigest) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export snapshot digest does not match its records");
  }
  return {
    format: "mac-operator-ledger-export-v1",
    schemaVersion: 1,
    createdAtMs: value.createdAtMs as number,
    requests,
    jobs,
    integrity: {
      requestCount: integrity.requestCount as number,
      jobCount: integrity.jobCount as number,
      snapshotDigest
    }
  };
}

function validateRequestRecord(value: unknown): asserts value is RequestRecord {
  const requiredKeys = [
    "requestId", "edgeId", "principalId", "sessionId", "tool", "policyVersion", "payloadDigest",
    "mutation", "capabilityFamilies", "state", "resultClass", "targetRef", "approvalId", "jobId",
    "receivedAtMs", "updatedAtMs", "revision"
  ];
  if (!isPlainDataRecord(value) ||
      (!hasExactKeys(value, requiredKeys) && !hasExactKeys(value, [...requiredKeys, "edgeKeyId"]))) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export Request record is malformed");
  }
  const row = value as unknown as RequestRecord;
  if (!/^[A-Za-z0-9._:@/+-]{1,128}$/u.test(row.requestId) || !isValidEdgeId(row.edgeId) ||
      (row.edgeKeyId !== undefined && row.edgeKeyId !== null &&
        (!row.edgeKeyId.startsWith(`${row.edgeId}:`) || !isValidEdgeKeyId(row.edgeKeyId.slice(row.edgeId.length + 1)))) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(row.principalId) || !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(row.sessionId) ||
      !/^mac_[a-z0-9_]{1,123}$/u.test(row.tool) || !/^policy-[A-Za-z0-9._:-]{1,120}$/u.test(row.policyVersion) ||
      !/^[a-f0-9]{64}$/u.test(row.payloadDigest) || typeof row.mutation !== "boolean" ||
      !Array.isArray(row.capabilityFamilies) || row.capabilityFamilies.some((family) => !CAPABILITY_FAMILY_SET.has(family)) ||
      !TERMINAL_REQUEST_STATES.has(row.state) || (row.resultClass !== null && !bounded(row.resultClass, 128)) ||
      (row.targetRef !== null && !bounded(row.targetRef, 4096)) ||
      (row.approvalId !== null && !/^approval:[A-Za-z0-9._:-]{1,240}$/u.test(row.approvalId)) ||
      (row.jobId !== null && !/^job:[A-Za-z0-9._-]{1,240}$/u.test(row.jobId)) ||
      !validTimestamp(row.receivedAtMs) || !validTimestamp(row.updatedAtMs) || row.updatedAtMs < row.receivedAtMs ||
      !Number.isSafeInteger(row.revision) || row.revision < 0) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export Request record is malformed");
  }
}

function validateJobRecord(value: unknown): asserts value is BrokerJob {
  if (!isPlainDataRecord(value)) throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export Job record is malformed");
  const row = value as unknown as BrokerJob;
  const expected = [
    "jobId", "ownerEdgeId", "ownerEdgeKeyId", "ownerPrincipalId", "ownerSessionId", "tool", "targetRef",
    "policyVersion", "payloadDigest", "idempotencyKey", "state", "resultClass", "createdAtMs", "startedAtMs",
    "finishedAtMs", "exitCode", "stdout", "stderr", "truncated", "cancelRequested", "revision"
  ];
  const optional = ["writeMetadata", "processMetadata", "guestMetadata", "guestResultJournal", "serviceMetadata", "privilegedPayload", "containerMetadata"];
  if (!hasExactKeys(value, [...expected, ...optional.filter((key) => Object.prototype.hasOwnProperty.call(value, key))])) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export Job record has an unexpected shape");
  }
  if (!/^job:[A-Za-z0-9._-]{1,240}$/u.test(row.jobId) ||
      (row.ownerEdgeId !== null && !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(row.ownerEdgeId)) ||
      (row.ownerEdgeKeyId !== null && !/^[A-Za-z0-9._:-]{1,128}$/u.test(row.ownerEdgeKeyId)) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(row.ownerPrincipalId) || !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(row.ownerSessionId) ||
      !/^mac_[a-z0-9_]{1,123}$/u.test(row.tool) || !bounded(row.targetRef, 4096) ||
      !/^policy-[A-Za-z0-9._:-]{1,120}$/u.test(row.policyVersion) || !/^[a-f0-9]{64}$/u.test(row.payloadDigest) ||
      !/^[A-Za-z0-9._:-]{1,128}$/u.test(row.idempotencyKey) || !TERMINAL_JOB_STATES.has(row.state) ||
      !["success", "denied", "failed", "verification_failed", "unknown"].includes(row.resultClass) ||
      !validTimestamp(row.createdAtMs) || (row.startedAtMs !== null && !validTimestamp(row.startedAtMs)) ||
      (row.finishedAtMs !== null && !validTimestamp(row.finishedAtMs)) ||
      (row.startedAtMs !== null && row.startedAtMs < row.createdAtMs) ||
      (row.finishedAtMs !== null && row.startedAtMs !== null && row.finishedAtMs < row.startedAtMs) ||
      (row.exitCode !== null && (!Number.isSafeInteger(row.exitCode) || row.exitCode < -2_147_483_648 || row.exitCode > 2_147_483_647)) ||
      !boundedOutput(row.stdout) || !boundedOutput(row.stderr) || typeof row.truncated !== "boolean" ||
      typeof row.cancelRequested !== "boolean" || !Number.isSafeInteger(row.revision) || row.revision < 0) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export Job record is malformed");
  }
  if (row.containerMetadata !== undefined) validateContainerTaskJobMetadata(row.containerMetadata);
  if (row.guestResultJournal !== undefined) validateGuestTaskResultJournalRecord(row.guestResultJournal, row.guestMetadata, row.state);
}

function validateGuestTaskResultJournalRecord(
  value: GuestTaskResultJournal,
  metadata: BrokerJob["guestMetadata"],
  jobState: BrokerJob["state"]
): void {
  const fail = (): never => { throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export guest result journal is malformed"); };
  if (!isPlainDataRecord(value) || !hasExactKeys(value, ["admission", "recordedAtMs", "result"]) ||
      !Number.isSafeInteger(value.recordedAtMs) || value.recordedAtMs < 0 ||
      !isPlainDataRecord(value.admission) || !isPlainDataRecord(value.result) ||
      !isPlainDataRecord(metadata) || jobState !== "unknown") fail();
  const admission = value.admission;
  if (!hasExactKeys(admission as unknown as Readonly<Record<string, unknown>>, [
        "requestId", "nonce", "requestDigest", "guestIdentity", "profileDigest", "taskDigest", "timeoutMs", "outputCapBytes", "recordedAtMs"
      ]) || !isPlainDataRecord(admission.guestIdentity) ||
      !hasExactKeys(admission.guestIdentity, ["imageSha256", "runtimeVersion"]) ||
      typeof admission.requestId !== "string" || !/^request:guest-[A-Za-z0-9._:-]{16,128}$/u.test(admission.requestId) ||
      typeof admission.nonce !== "string" || !/^guest-nonce-[A-Za-z0-9._:-]{16,128}$/u.test(admission.nonce) ||
      typeof admission.requestDigest !== "string" || !/^[a-f0-9]{64}$/u.test(admission.requestDigest) ||
      typeof admission.guestIdentity.imageSha256 !== "string" || !/^[a-f0-9]{64}$/u.test(admission.guestIdentity.imageSha256) ||
      typeof admission.guestIdentity.runtimeVersion !== "string" || !/^[A-Za-z0-9._:+/-]{1,128}$/u.test(admission.guestIdentity.runtimeVersion) ||
      typeof admission.profileDigest !== "string" || !/^[a-f0-9]{64}$/u.test(admission.profileDigest) ||
      typeof admission.taskDigest !== "string" || !/^[a-f0-9]{64}$/u.test(admission.taskDigest) ||
      !Number.isSafeInteger(admission.timeoutMs) || admission.timeoutMs < 1 || admission.timeoutMs > 900_000 ||
      !Number.isSafeInteger(admission.outputCapBytes) || admission.outputCapBytes < 1 || admission.outputCapBytes > 4 * 1024 * 1024 ||
      !Number.isSafeInteger(admission.recordedAtMs) || admission.recordedAtMs < 0 ||
      value.recordedAtMs < admission.recordedAtMs) fail();
  const result = value.result;
  if (!hasExactKeys(result, ["state", "resultClass", "exitCode", "stdout", "stderr", "truncated", "durationMs", "verification"]) ||
      !isPlainDataRecord(result.verification) ||
      (!hasExactKeys(result.verification, ["status"]) && !hasExactKeys(result.verification, ["status", "summary"])) ||
      !["completed", "failed", "cancelled", "timed_out", "unknown"].includes(String(result.state)) ||
      !["SUCCEEDED", "EXECUTION_FAILED", "CANCELLED", "TIMEOUT", "OUTPUT_LIMIT", "UNKNOWN_OUTCOME"].includes(String(result.resultClass)) ||
      (result.exitCode !== null && (!Number.isSafeInteger(result.exitCode) || (result.exitCode as number) < -2_147_483_648 || (result.exitCode as number) > 2_147_483_647)) ||
      !boundedOutput(result.stdout) || !boundedOutput(result.stderr) || typeof result.truncated !== "boolean" ||
      !Number.isSafeInteger(result.durationMs) || (result.durationMs as number) < 0 || (result.durationMs as number) > 1_200_000 ||
      !["verified", "failed", "unknown", "not_run"].includes(String(result.verification.status)) ||
      (result.verification.summary !== undefined && !bounded(result.verification.summary, 512)) ||
      result.resultClass === "SUCCEEDED" && (result.state !== "completed" || result.verification.status !== "verified") ||
      result.resultClass === "CANCELLED" && result.state !== "cancelled" ||
      result.resultClass === "TIMEOUT" && result.state !== "timed_out" ||
      result.resultClass === "UNKNOWN_OUTCOME" && result.state !== "unknown" ||
      (result.resultClass === "EXECUTION_FAILED" || result.resultClass === "OUTPUT_LIMIT") && result.state !== "failed") fail();
  let matchesAdmission = false;
  try { matchesAdmission = canonicalJson(value.admission) === canonicalJson(metadata); } catch { /* malformed archive data */ }
  if (!matchesAdmission || Buffer.byteLength(canonicalJson(value), "utf8") > 1_100_000) fail();
}

function bounded(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= maxLength && !value.includes("\0");
}

function boundedOutput(value: unknown): value is string {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > 262_144 || value.includes("\0")) return false;
  try {
    assertContentDoesNotContainSecrets(Buffer.from(value, "utf8"));
    return true;
  } catch {
    return false;
  }
}

function validTimestamp(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function hasExactKeys(value: Readonly<Record<string, unknown>>, keys: readonly string[]): boolean {
  const expected = new Set(keys);
  const actual = Object.keys(value);
  return actual.length === expected.size && actual.every((key) => expected.has(key));
}

function validateKeySource(value: BrokerBackupKeySource | undefined): BrokerBackupKeySource {
  if (value === undefined || value === null || typeof value !== "object" ||
      typeof value.keyId !== "string" || !LEDGER_EXPORT_KEY_ID_PATTERN.test(value.keyId) ||
      Buffer.byteLength(value.keyId, "utf8") > LEDGER_EXPORT_MAX_KEY_ID_BYTES || typeof value.loadKey !== "function") {
    throw new BrokerError("POLICY_DENIED", "Encrypted ledger exports require a valid protected key source");
  }
  return value;
}

async function loadKey(source: BrokerBackupKeySource): Promise<Buffer> {
  let loaded: Uint8Array;
  try {
    loaded = await source.loadKey();
  } catch {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export encryption key is unavailable", true);
  }
  if (!(loaded instanceof Uint8Array) || loaded.byteLength !== 32) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export encryption key has an invalid length");
  }
  return Buffer.from(loaded);
}

async function writeEncryptedFile(path: string, plaintext: Buffer, keyId: string, key: Buffer): Promise<void> {
  const nonce = randomBytes(LEDGER_EXPORT_NONCE_BYTES);
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
  if (file.byteLength < LEDGER_EXPORT_HEADER_PREFIX_BYTES + LEDGER_EXPORT_NONCE_BYTES + LEDGER_EXPORT_TAG_BYTES) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export is truncated");
  }
  const prefix = file.subarray(0, LEDGER_EXPORT_HEADER_PREFIX_BYTES);
  if (!prefix.subarray(0, LEDGER_EXPORT_MAGIC.byteLength).equals(LEDGER_EXPORT_MAGIC) ||
      prefix.readUInt8(LEDGER_EXPORT_MAGIC.byteLength) !== LEDGER_EXPORT_VERSION) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export format is unsupported");
  }
  const keyIdBytes = prefix.readUInt16BE(LEDGER_EXPORT_MAGIC.byteLength + 1);
  const headerBytes = LEDGER_EXPORT_HEADER_PREFIX_BYTES + keyIdBytes + LEDGER_EXPORT_NONCE_BYTES;
  if (keyIdBytes < 1 || keyIdBytes > LEDGER_EXPORT_MAX_KEY_ID_BYTES || file.byteLength <= headerBytes + LEDGER_EXPORT_TAG_BYTES) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export header is malformed");
  }
  const header = file.subarray(0, headerBytes);
  let storedKeyId: string;
  try {
    storedKeyId = decodeUtf8Strict(header.subarray(LEDGER_EXPORT_HEADER_PREFIX_BYTES, LEDGER_EXPORT_HEADER_PREFIX_BYTES + keyIdBytes));
  } catch {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export key identity is malformed");
  }
  if (storedKeyId !== keyId || !LEDGER_EXPORT_KEY_ID_PATTERN.test(storedKeyId) ||
      Buffer.byteLength(storedKeyId, "utf8") !== keyIdBytes) {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export key identity does not match");
  }
  const nonce = header.subarray(LEDGER_EXPORT_HEADER_PREFIX_BYTES + keyIdBytes);
  const tag = file.subarray(file.byteLength - LEDGER_EXPORT_TAG_BYTES);
  const ciphertext = file.subarray(headerBytes, file.byteLength - LEDGER_EXPORT_TAG_BYTES);
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAAD(header);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export authentication failed");
  }
}

function buildHeader(keyId: string, nonce: Buffer): Buffer {
  const keyIdBytes = Buffer.from(keyId, "utf8");
  if (!LEDGER_EXPORT_KEY_ID_PATTERN.test(keyId) || keyIdBytes.byteLength < 1 ||
      keyIdBytes.byteLength > LEDGER_EXPORT_MAX_KEY_ID_BYTES || nonce.byteLength !== LEDGER_EXPORT_NONCE_BYTES) {
    throw new BrokerError("PRECONDITION_FAILED", "Ledger export header is malformed");
  }
  const header = Buffer.alloc(LEDGER_EXPORT_HEADER_PREFIX_BYTES + keyIdBytes.byteLength + nonce.byteLength);
  LEDGER_EXPORT_MAGIC.copy(header, 0);
  header.writeUInt8(LEDGER_EXPORT_VERSION, LEDGER_EXPORT_MAGIC.byteLength);
  header.writeUInt16BE(keyIdBytes.byteLength, LEDGER_EXPORT_MAGIC.byteLength + 1);
  keyIdBytes.copy(header, LEDGER_EXPORT_HEADER_PREFIX_BYTES);
  nonce.copy(header, LEDGER_EXPORT_HEADER_PREFIX_BYTES + keyIdBytes.byteLength);
  return header;
}

async function readProtectedArchive(path: string): Promise<Buffer> {
  const pathStat = await lstat(path).catch(() => undefined);
  if (!pathStat || !pathStat.isFile() || pathStat.isSymbolicLink() || (pathStat.mode & 0o777) !== 0o600 ||
      typeof process.getuid !== "function" || pathStat.uid !== process.getuid() || pathStat.size > LEDGER_EXPORT_MAX_ENCRYPTED_BYTES) {
    throw new BrokerError("POLICY_DENIED", "Ledger export must be an owner-only bounded regular file");
  }
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat({ bigint: false });
    if (!sameIdentity(pathStat, opened)) throw new BrokerError("CONFLICT", "Ledger export changed while opening", true);
    const size = opened.size;
    if (!Number.isSafeInteger(size) || size > LEDGER_EXPORT_MAX_ENCRYPTED_BYTES) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export exceeds its bounded byte budget");
    }
    const result = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
      const read = await handle.read(result, offset, size - offset, null);
      if (read.bytesRead <= 0) {
        result.fill(0);
        throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export is truncated");
      }
      offset += read.bytesRead;
    }
    const after = await handle.stat({ bigint: false });
    if (!sameIdentity(opened, after) || after.size !== result.byteLength) {
      result.fill(0);
      throw new BrokerError("CONFLICT", "Ledger export changed while reading", true);
    }
    return result;
  } finally {
    await handle.close();
  }
}

function validateArchivePath(path: string, temporary: boolean): string {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path || path.includes("\0") || path.length > 4096 ||
      path !== join(dirname(path), basename(path))) {
    throw new BrokerError("PRECONDITION_FAILED", "Ledger export path is malformed");
  }
  const nameValid = LEDGER_EXPORT_NAME_PATTERN.test(basename(path));
  const tempValid = LEDGER_EXPORT_TEMP_PATTERN.test(basename(path));
  if ((temporary && !tempValid) || (!temporary && !nameValid)) {
    throw new BrokerError("PRECONDITION_FAILED", "Ledger export filename is invalid");
  }
  return path;
}

async function publishExclusive(source: string, destination: string, expected: Stats): Promise<void> {
  try {
    await link(source, destination);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new BrokerError("CONFLICT", "Ledger export publication destination already exists", true);
    }
    throw error;
  }
  const sourceAfter = await lstat(source, { bigint: false }).catch(() => undefined);
  const destinationAfter = await lstat(destination, { bigint: false }).catch(() => undefined);
  if (!sourceAfter || !destinationAfter || !sameIdentity(expected, sourceAfter) || !sameIdentity(sourceAfter, destinationAfter)) {
    throw new BrokerError("CONFLICT", "Ledger export publication identity could not be verified", true);
  }
  await unlink(source);
}

async function removeExactTemporary(path: string): Promise<void> {
  const stat = await lstat(path).catch(() => undefined);
  if (!stat) return;
  if (!LEDGER_EXPORT_TEMP_PATTERN.test(basename(path)) || !stat.isFile() || stat.isSymbolicLink() ||
      (stat.mode & 0o777) !== 0o600 || typeof process.getuid !== "function" || stat.uid !== process.getuid()) return;
  const current = await lstat(path).catch(() => undefined);
  if (current && sameIdentity(stat, current)) await unlink(path);
}

async function writeAll(handle: Awaited<ReturnType<typeof open>>, value: Buffer): Promise<void> {
  let offset = 0;
  while (offset < value.byteLength) {
    const result = await handle.write(value, offset, value.byteLength - offset, null);
    if (result.bytesWritten <= 0) throw new BrokerError("AUDIT_UNAVAILABLE", "Ledger export write made no progress", true);
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
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid && left.gid === right.gid &&
    (left.mode & 0o7777) === (right.mode & 0o7777) && left.size === right.size && left.mtimeMs === right.mtimeMs;
}

function validateTimestamp(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 9_999_999_999_999_999) {
    throw new BrokerError("PRECONDITION_FAILED", "Ledger export timestamp is invalid");
  }
}
