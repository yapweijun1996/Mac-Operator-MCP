import { constants } from "node:fs";
import { randomUUID } from "node:crypto";
import { lstat, open, rename, unlink } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { BrokerError, canonicalJson, decodeUtf8Strict, sha256 } from "@mac-operator/contracts";
import { EdgeKeyring, type EdgeAuthenticationKey } from "./edge-keyring.js";
import {
  assertProtectedSecretDirectory,
  loadAuthenticationKey,
  loadKeychainAuthenticationKey,
  syncProtectedDirectory
} from "./credentials.js";
import type { EdgeKeyConfigActivationIdentity, BrokerStore } from "./persistence.js";

const MAX_CONFIG_BYTES = 128 * 1024;
const ENTRY_KEYS = new Set([
  "edgeId", "keyId", "keySource", "path", "service", "account", "keyDigest", "notBeforeMs", "expiresAtMs"
]);

export interface EdgeAuthenticationKeyConfigEntry {
  edgeId: string;
  keyId: string;
  keySource: "file" | "keychain";
  path?: string;
  service?: string;
  account?: string;
  keyDigest: string;
  notBeforeMs: number;
  expiresAtMs: number;
}

export interface EdgeAuthenticationKeyConfig {
  schemaVersion: "0.1";
  revision: number;
  keys: readonly EdgeAuthenticationKeyConfigEntry[];
}

export interface LoadedEdgeAuthenticationKeyConfig {
  document: EdgeAuthenticationKeyConfig;
  keys: readonly EdgeAuthenticationKey[];
  keyring: EdgeKeyring;
  payloadDigest: string;
}

/**
 * Broker-owned activation boundary for Edge authentication-key metadata.
 * Activation is monotonic and audited; restart restore requires the exact
 * persisted revision and payload digest before a keyring can be used.
 */
export class EdgeAuthenticationKeyManager {
  private activeSnapshot: LoadedEdgeAuthenticationKeyConfig | undefined;

  constructor(
    private readonly configPath: string,
    private readonly store: BrokerStore,
    private readonly now: () => number = Date.now
  ) {}

  async activate(expectedPreviousRevision?: number): Promise<LoadedEdgeAuthenticationKeyConfig> {
    const loaded = await loadEdgeAuthenticationKeyConfig(this.configPath, this.store);
    const persisted = this.store.activeEdgeKeyConfigIdentity();
    const persistedRevision = persisted?.revision ?? 0;
    const expected = expectedPreviousRevision ?? persistedRevision;
    if (expected !== persistedRevision) {
      throw new BrokerError("CONFLICT", "Persisted Edge key configuration revision changed concurrently");
    }
    if (persisted && persisted.revision === loaded.document.revision && persisted.payloadDigest === loaded.payloadDigest) {
      this.activeSnapshot = loaded;
      return loaded;
    }
    const identity: EdgeKeyConfigActivationIdentity = {
      revision: loaded.document.revision,
      payloadDigest: loaded.payloadDigest,
      activatedAtMs: this.now()
    };
    this.store.activateEdgeKeyConfig(identity, expected);
    this.activeSnapshot = loaded;
    return loaded;
  }

  async restore(): Promise<LoadedEdgeAuthenticationKeyConfig> {
    const loaded = await loadEdgeAuthenticationKeyConfig(this.configPath, this.store);
    const persisted = this.store.activeEdgeKeyConfigIdentity();
    if (!persisted || persisted.revision !== loaded.document.revision || persisted.payloadDigest !== loaded.payloadDigest) {
      throw new BrokerError("PRECONDITION_FAILED", "Edge key configuration does not match persisted activation");
    }
    this.activeSnapshot = loaded;
    return loaded;
  }

  current(): LoadedEdgeAuthenticationKeyConfig {
    if (!this.activeSnapshot) throw new BrokerError("PRECONDITION_FAILED", "Edge key configuration is not activated");
    return this.activeSnapshot;
  }
}

/**
 * Loads Edge authentication keys from explicitly selected protected sources.
 * This function never infers a source from request arguments and rejects
 * revoked key identities before constructing the keyring.
 */
export async function loadEdgeAuthenticationKeyConfig(
  path: string,
  store: BrokerStore
): Promise<LoadedEdgeAuthenticationKeyConfig> {
  const document = parseConfig(await readProtectedConfig(path));
  const keys: EdgeAuthenticationKey[] = [];
  for (const entry of document.keys) {
    const identity = `${entry.edgeId}:${entry.keyId}`;
    if (store.isRevoked("edge_key", identity)) {
      throw new Error(`Edge authentication key is revoked: ${identity}`);
    }
    const key = entry.keySource === "keychain"
      ? await loadKeychainAuthenticationKey(entry.service!, entry.account!)
      : await loadAuthenticationKey(entry.path!);
    if (sha256(key) !== entry.keyDigest) {
      throw new Error(`Edge authentication key digest precondition failed: ${identity}`);
    }
    keys.push({
      edgeId: entry.edgeId,
      keyId: entry.keyId,
      key,
      notBeforeMs: entry.notBeforeMs,
      expiresAtMs: entry.expiresAtMs
    });
  }
  const keyring = new EdgeKeyring(keys);
  return { document, keys, keyring, payloadDigest: sha256(canonicalJson(document)) };
}

/** Atomically writes non-secret Edge key metadata; secret bytes stay in files or Keychain. */
export async function writeEdgeAuthenticationKeyConfig(
  path: string,
  document: EdgeAuthenticationKeyConfig
): Promise<string> {
  validateConfig(document);
  validateConfigPath(path);
  await assertProtectedSecretDirectory(dirname(path));
  const content = Buffer.from(`${canonicalJson(document)}\n`, "utf8");
  if (content.byteLength > MAX_CONFIG_BYTES) throw new Error("Edge authentication key config is too large");
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
  validateConfigPath(path);
  await assertProtectedSecretDirectory(dirname(path));
  const pathStat = await lstat(path);
  const currentUid = process.getuid?.();
  if (!pathStat.isFile() || pathStat.isSymbolicLink()) {
    throw new Error("Edge authentication key config must be a regular non-symlink file");
  }
  if (currentUid === undefined || pathStat.uid !== currentUid) {
    throw new Error("Edge authentication key config must be owned by the Broker user");
  }
  if ((pathStat.mode & 0o077) !== 0) {
    throw new Error("Edge authentication key config must not be accessible by group or other users");
  }
  if (pathStat.size < 2 || pathStat.size > MAX_CONFIG_BYTES) {
    throw new Error("Edge authentication key config size is invalid");
  }
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const openedStat = await handle.stat();
    if (!openedStat.isFile() || openedStat.dev !== pathStat.dev || openedStat.ino !== pathStat.ino) {
      throw new Error("Edge authentication key config target changed while opening");
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
      throw new Error("Existing Edge authentication key config is not protected");
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

function validateConfigPath(path: string): void {
  if (!isAbsolute(path) || resolve(path) !== path || path.includes("\0")) {
    throw new Error("Edge authentication key config path must be canonical and absolute");
  }
}

function parseConfig(content: Buffer): EdgeAuthenticationKeyConfig {
  let value: unknown;
  try {
    value = JSON.parse(decodeUtf8Strict(content)) as unknown;
  } catch {
    throw new Error("Edge authentication key config is not valid JSON");
  }
  validateConfig(value);
  return value as EdgeAuthenticationKeyConfig;
}

function validateConfig(value: unknown): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Edge authentication key config is malformed");
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !new Set(["schemaVersion", "revision", "keys"]).has(key)) ||
      record.schemaVersion !== "0.1" || !Number.isSafeInteger(record.revision) || (record.revision as number) < 1 ||
      !Array.isArray(record.keys) || record.keys.length < 1 || record.keys.length > 32) {
    throw new Error("Edge authentication key config is malformed");
  }
  const identities = new Set<string>();
  for (const entry of record.keys) {
    validateEntry(entry);
    const typedEntry = entry as EdgeAuthenticationKeyConfigEntry;
    const identity = `${typedEntry.edgeId}:${typedEntry.keyId}`;
    if (identities.has(identity)) throw new Error(`Duplicate Edge authentication key: ${identity}`);
    identities.add(identity);
  }
}

function validateEntry(value: unknown): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Edge authentication key config entry is malformed");
  }
  const record = value as Record<string, unknown>;
  const keySource = record.keySource;
  const fileSource = keySource === "file" &&
    typeof record.path === "string" && isAbsolute(record.path) && resolve(record.path) === record.path && !record.path.includes("\0") &&
    record.service === undefined && record.account === undefined;
  const keychainSource = keySource === "keychain" && record.path === undefined &&
    typeof record.service === "string" && /^com\.mac-operator\.[A-Za-z0-9.-]{1,96}$/u.test(record.service) &&
    typeof record.account === "string" && /^[A-Za-z0-9._:-]{1,128}$/u.test(record.account);
  if (Object.keys(record).some((key) => !ENTRY_KEYS.has(key)) ||
      typeof record.edgeId !== "string" || !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(record.edgeId) ||
      typeof record.keyId !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(record.keyId) ||
      typeof record.keyDigest !== "string" || !/^[a-f0-9]{64}$/u.test(record.keyDigest) ||
      (!fileSource && !keychainSource) ||
      !Number.isSafeInteger(record.notBeforeMs) || (record.notBeforeMs as number) < 0 ||
      !Number.isSafeInteger(record.expiresAtMs) || (record.expiresAtMs as number) <= (record.notBeforeMs as number)) {
    throw new Error("Edge authentication key config entry is malformed");
  }
}
