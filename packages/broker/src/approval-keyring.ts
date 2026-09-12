import { constants } from "node:fs";
import { randomUUID } from "node:crypto";
import { lstat, open, rename, unlink } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import { approvalKeyIdentity, type ApprovalIssuerKey } from "./approval-authority.js";
import {
  assertProtectedSecretDirectory,
  loadApprovalIssuerKey,
  syncProtectedDirectory
} from "./credentials.js";
import type { ApprovalKeyConfigActivationIdentity, BrokerStore } from "./persistence.js";

const MAX_CONFIG_BYTES = 128 * 1024;

export interface ApprovalIssuerKeyConfigEntry {
  issuerId: string;
  keyId: string;
  path: string;
  notBeforeMs: number;
  expiresAtMs: number;
  allowUnattended: boolean;
}

export interface ApprovalIssuerKeyConfig {
  schemaVersion: "0.1";
  revision: number;
  keys: readonly ApprovalIssuerKeyConfigEntry[];
}

export interface LoadedApprovalIssuerKeyConfig {
  document: ApprovalIssuerKeyConfig;
  keys: readonly ApprovalIssuerKey[];
  payloadDigest: string;
}

/**
 * Broker-owned activation boundary for issuer-key metadata.
 * Activation is explicit and monotonic; startup restore only accepts the
 * exact revision and digest already persisted by the BrokerStore.
 */
export class ApprovalIssuerKeyManager {
  private activeSnapshot: LoadedApprovalIssuerKeyConfig | undefined;

  constructor(
    private readonly configPath: string,
    private readonly store: BrokerStore,
    private readonly now: () => number = Date.now
  ) {}

  async activate(expectedPreviousRevision?: number): Promise<LoadedApprovalIssuerKeyConfig> {
    const loaded = await loadApprovalIssuerKeyConfig(this.configPath, this.store);
    const persisted = this.store.activeApprovalKeyConfigIdentity();
    const persistedRevision = persisted?.revision ?? 0;
    const expected = expectedPreviousRevision ?? persistedRevision;
    if (expected !== persistedRevision) {
      throw new BrokerError("CONFLICT", "Persisted approval key configuration revision changed concurrently");
    }
    if (persisted && persisted.revision === loaded.document.revision && persisted.payloadDigest === loaded.payloadDigest) {
      this.activeSnapshot = loaded;
      return loaded;
    }
    const identity: ApprovalKeyConfigActivationIdentity = {
      revision: loaded.document.revision,
      payloadDigest: loaded.payloadDigest,
      activatedAtMs: this.now()
    };
    this.store.activateApprovalKeyConfig(identity, expected);
    this.activeSnapshot = loaded;
    return loaded;
  }

  async restore(): Promise<LoadedApprovalIssuerKeyConfig> {
    const loaded = await loadApprovalIssuerKeyConfig(this.configPath, this.store);
    const persisted = this.store.activeApprovalKeyConfigIdentity();
    if (!persisted || persisted.revision !== loaded.document.revision || persisted.payloadDigest !== loaded.payloadDigest) {
      throw new BrokerError("PRECONDITION_FAILED", "Issuer key configuration does not match persisted activation");
    }
    this.activeSnapshot = loaded;
    return loaded;
  }

  current(): LoadedApprovalIssuerKeyConfig {
    if (!this.activeSnapshot) throw new BrokerError("PRECONDITION_FAILED", "Issuer key configuration is not activated");
    return this.activeSnapshot;
  }
}

/** Loads issuer metadata and key bytes from protected, owner-only files. */
export async function loadApprovalIssuerKeyConfig(
  path: string,
  store: BrokerStore
): Promise<LoadedApprovalIssuerKeyConfig> {
  const document = parseConfig(await readProtectedConfig(path));
  const identities = new Set<string>();
  const keys: ApprovalIssuerKey[] = [];
  for (const entry of document.keys) {
    const identity = approvalKeyIdentity(entry.issuerId, entry.keyId);
    if (identities.has(identity)) throw new Error(`Duplicate approval issuer key: ${identity}`);
    identities.add(identity);
    if (store.isRevoked("approval_key", identity)) {
      throw new Error(`Approval issuer key is revoked: ${identity}`);
    }
    keys.push(await loadApprovalIssuerKey(
      entry.path,
      entry.issuerId,
      entry.keyId,
      entry.notBeforeMs,
      entry.expiresAtMs,
      entry.allowUnattended
    ));
  }
  return { document, keys, payloadDigest: sha256(canonicalJson(document)) };
}

/** Atomically writes issuer metadata; secret bytes remain in separate key files. */
export async function writeApprovalIssuerKeyConfig(path: string, document: ApprovalIssuerKeyConfig): Promise<string> {
  validateConfig(document);
  if (!isAbsolute(path) || resolve(path) !== path || path.includes("\0")) {
    throw new Error("Approval issuer key config path must be canonical and absolute");
  }
  await assertProtectedSecretDirectory(dirname(path));
  const content = Buffer.from(`${canonicalJson(document)}\n`, "utf8");
  if (content.byteLength > MAX_CONFIG_BYTES) throw new Error("Approval issuer key config is too large");
  await rejectUnsafeExistingConfig(path);
  const temporaryPath = `${path}.tmp-${randomUUID()}`;
  const handle = await open(
    temporaryPath,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
    0o600
  );
  try {
    await handle.writeFile(content);
    await handle.sync();
  } catch (error) {
    await handle.close();
    await unlink(temporaryPath).catch(() => undefined);
    throw error;
  }
  await handle.close();
  try {
    await rename(temporaryPath, path);
    await syncProtectedDirectory(dirname(path));
  } catch (error) {
    await unlink(temporaryPath).catch(() => undefined);
    throw error;
  }
  return sha256(canonicalJson(document));
}

async function readProtectedConfig(path: string): Promise<Buffer> {
  if (!isAbsolute(path) || resolve(path) !== path || path.includes("\0")) {
    throw new Error("Approval issuer key config path must be canonical and absolute");
  }
  await assertProtectedSecretDirectory(dirname(path));
  const pathStat = await lstat(path);
  const currentUid = process.getuid?.();
  if (!pathStat.isFile() || pathStat.isSymbolicLink()) throw new Error("Approval issuer key config must be a regular non-symlink file");
  if (currentUid === undefined || pathStat.uid !== currentUid) throw new Error("Approval issuer key config must be owned by the Broker user");
  if ((pathStat.mode & 0o077) !== 0) throw new Error("Approval issuer key config must not be accessible by group or other users");
  if (pathStat.size < 2 || pathStat.size > MAX_CONFIG_BYTES) throw new Error("Approval issuer key config size is invalid");
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const openedStat = await handle.stat();
    if (!openedStat.isFile() || openedStat.dev !== pathStat.dev || openedStat.ino !== pathStat.ino) {
      throw new Error("Approval issuer key config target changed while opening");
    }
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

async function rejectUnsafeExistingConfig(path: string): Promise<void> {
  try {
    const current = await lstat(path);
    const uid = process.getuid?.();
    if (!current.isFile() || current.isSymbolicLink() || uid === undefined || current.uid !== uid || (current.mode & 0o077) !== 0) {
      throw new Error("Existing approval issuer key config is not protected");
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

function parseConfig(content: Buffer): ApprovalIssuerKeyConfig {
  let value: unknown;
  try { value = JSON.parse(content.toString("utf8")) as unknown; }
  catch { throw new Error("Approval issuer key config is not valid JSON"); }
  validateConfig(value);
  return value as ApprovalIssuerKeyConfig;
}

function validateConfig(value: unknown): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Approval issuer key config is malformed");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !new Set(["schemaVersion", "revision", "keys"]).has(key)) ||
      record.schemaVersion !== "0.1" || !Number.isSafeInteger(record.revision) || (record.revision as number) < 1 ||
      !Array.isArray(record.keys) || record.keys.length < 1 || record.keys.length > 32) {
    throw new Error("Approval issuer key config is malformed");
  }
  const identities = new Set<string>();
  for (const entry of record.keys) {
    validateEntry(entry);
    const typedEntry = entry as ApprovalIssuerKeyConfigEntry;
    const identity = approvalKeyIdentity(typedEntry.issuerId, typedEntry.keyId);
    if (identities.has(identity)) throw new Error(`Duplicate approval issuer key: ${identity}`);
    identities.add(identity);
  }
}

function validateEntry(value: unknown): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Approval issuer key config entry is malformed");
  const record = value as Record<string, unknown>;
  const keys = new Set(["issuerId", "keyId", "path", "notBeforeMs", "expiresAtMs", "allowUnattended"]);
  if (Object.keys(record).some((key) => !keys.has(key)) ||
      typeof record.issuerId !== "string" || !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(record.issuerId) ||
      typeof record.keyId !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(record.keyId) ||
      typeof record.path !== "string" || !isAbsolute(record.path) || resolve(record.path) !== record.path || record.path.includes("\0") ||
      !Number.isSafeInteger(record.notBeforeMs) || (record.notBeforeMs as number) < 0 ||
      !Number.isSafeInteger(record.expiresAtMs) || (record.expiresAtMs as number) <= (record.notBeforeMs as number) ||
      typeof record.allowUnattended !== "boolean") {
    throw new Error("Approval issuer key config entry is malformed");
  }
}
