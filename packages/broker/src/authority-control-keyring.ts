import { constants } from "node:fs";
import { randomUUID } from "node:crypto";
import { lstat, open, rename, unlink } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { BrokerError, canonicalJson, decodeUtf8Strict, sha256 } from "@mac-operator/contracts";
import {
  assertProtectedSecretDirectory,
  loadAuthenticationKey,
  loadKeychainAuthenticationKey,
  syncProtectedDirectory
} from "./credentials.js";
import { AuthorityControlIpcClient, type AuthorityControlIpcClientOptions } from "./authority-control-ipc.js";
import type { AuthorityKeyConfigActivationIdentity, BrokerStore } from "./persistence.js";

const MAX_CONFIG_BYTES = 128 * 1024;
const MAX_KEYS = 1;
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;

export interface AuthorityControlKeyConfigEntry {
  keyId: string;
  keySource: "file" | "keychain";
  path?: string;
  service?: string;
  account?: string;
  keyDigest: string;
  notBeforeMs: number;
  expiresAtMs: number;
}

export interface AuthorityControlKeyConfig {
  schemaVersion: "0.1";
  revision: number;
  keys: readonly AuthorityControlKeyConfigEntry[];
}

export interface AuthorityControlAuthenticationKey {
  keyId: string;
  key: Buffer;
  notBeforeMs: number;
  expiresAtMs: number;
}

export interface LoadedAuthorityControlKeyConfig {
  document: AuthorityControlKeyConfig;
  key: AuthorityControlAuthenticationKey;
  payloadDigest: string;
}

/**
 * Broker-owned activation boundary for the owner-only Authority Control key.
 * Exactly one configured key is active at a time; rotation is an explicit,
 * monotonic startup/configuration change rather than an implicit hot reload.
 */
export class AuthorityControlKeyManager {
  private activeSnapshot: LoadedAuthorityControlKeyConfig | undefined;

  constructor(
    private readonly configPath: string,
    private readonly store: BrokerStore,
    private readonly now: () => number = Date.now
  ) {}

  async activate(expectedPreviousRevision?: number): Promise<LoadedAuthorityControlKeyConfig> {
    const loaded = await loadAuthorityControlKeyConfig(this.configPath, this.store);
    const persisted = this.store.activeAuthorityKeyConfigIdentity();
    const persistedRevision = persisted?.revision ?? 0;
    const expected = expectedPreviousRevision ?? persistedRevision;
    if (expected !== persistedRevision) {
      loaded.key.key.fill(0);
      throw new BrokerError("CONFLICT", "Persisted authority key configuration revision changed concurrently");
    }
    if (persisted && persisted.revision === loaded.document.revision && persisted.payloadDigest === loaded.payloadDigest) {
      this.dispose();
      this.activeSnapshot = loaded;
      return loaded;
    }
    const identity: AuthorityKeyConfigActivationIdentity = {
      revision: loaded.document.revision,
      payloadDigest: loaded.payloadDigest,
      activatedAtMs: this.now()
    };
    try {
      this.store.activateAuthorityKeyConfig(identity, expected);
    } catch (error) {
      loaded.key.key.fill(0);
      throw error;
    }
    this.dispose();
    this.activeSnapshot = loaded;
    return loaded;
  }

  async restore(): Promise<LoadedAuthorityControlKeyConfig> {
    const loaded = await loadAuthorityControlKeyConfig(this.configPath, this.store);
    const persisted = this.store.activeAuthorityKeyConfigIdentity();
    if (!persisted || persisted.revision !== loaded.document.revision || persisted.payloadDigest !== loaded.payloadDigest) {
      loaded.key.key.fill(0);
      throw new BrokerError("PRECONDITION_FAILED", "Authority key configuration does not match persisted activation");
    }
    this.dispose();
    this.activeSnapshot = loaded;
    return loaded;
  }

  current(): LoadedAuthorityControlKeyConfig {
    if (!this.activeSnapshot) throw new BrokerError("PRECONDITION_FAILED", "Authority key configuration is not activated");
    return this.activeSnapshot;
  }

  createClient(options: Omit<AuthorityControlIpcClientOptions, "authenticationKey">): AuthorityControlIpcClient {
    const snapshot = this.current();
    const nowMs = this.now();
    if (!Number.isSafeInteger(nowMs) || nowMs < snapshot.key.notBeforeMs || nowMs >= snapshot.key.expiresAtMs) {
      throw new BrokerError("AUTH_EXPIRED", "Authority control key is outside its validity window");
    }
    return new AuthorityControlIpcClient({
      ...options,
      authenticationKey: Buffer.from(snapshot.key.key)
    });
  }

  dispose(): void {
    this.activeSnapshot?.key.key.fill(0);
    this.activeSnapshot = undefined;
  }
}

/** Loads the explicitly selected file or Keychain secret and checks its digest and revocation. */
export async function loadAuthorityControlKeyConfig(
  path: string,
  store: BrokerStore
): Promise<LoadedAuthorityControlKeyConfig> {
  const document = parseConfig(await readProtectedConfig(path));
  const entry = document.keys[0]!;
  if (store.isRevoked("authority_key", entry.keyId)) {
    throw new Error(`Authority control key is revoked: ${entry.keyId}`);
  }
  const key = entry.keySource === "keychain"
    ? await loadKeychainAuthenticationKey(entry.service!, entry.account!)
    : await loadAuthenticationKey(entry.path!);
  try {
    if (sha256(key) !== entry.keyDigest) throw new Error("Authority control key digest precondition failed");
    return {
      document,
      key: {
        keyId: entry.keyId,
        key: Buffer.from(key),
        notBeforeMs: entry.notBeforeMs,
        expiresAtMs: entry.expiresAtMs
      },
      payloadDigest: sha256(canonicalJson(document))
    };
  } finally {
    key.fill(0);
  }
}

/** Atomically writes non-secret authority-key metadata; secret bytes stay in a file or Keychain. */
export async function writeAuthorityControlKeyConfig(
  path: string,
  document: AuthorityControlKeyConfig
): Promise<string> {
  validateConfig(document);
  validateConfigPath(path);
  await assertProtectedSecretDirectory(dirname(path));
  const content = Buffer.from(`${canonicalJson(document)}\n`, "utf8");
  if (content.byteLength > MAX_CONFIG_BYTES) throw new Error("Authority control key config is too large");
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

function validateConfigPath(path: string): void {
  if (!isAbsolute(path) || resolve(path) !== path || path.includes("\0")) {
    throw new Error("Authority control key config path must be canonical and absolute");
  }
}

async function readProtectedConfig(path: string): Promise<Buffer> {
  validateConfigPath(path);
  await assertProtectedSecretDirectory(dirname(path));
  const pathStat = await lstat(path);
  const currentUid = process.getuid?.();
  if (!pathStat.isFile() || pathStat.isSymbolicLink()) {
    throw new Error("Authority control key config must be a regular non-symlink file");
  }
  if (currentUid === undefined || pathStat.uid !== currentUid) {
    throw new Error("Authority control key config must be owned by the Broker user");
  }
  if ((pathStat.mode & 0o077) !== 0) {
    throw new Error("Authority control key config must not be accessible by group or other users");
  }
  if (pathStat.size < 2 || pathStat.size > MAX_CONFIG_BYTES) {
    throw new Error("Authority control key config size is invalid");
  }
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const openedStat = await handle.stat();
    if (!openedStat.isFile() || openedStat.dev !== pathStat.dev || openedStat.ino !== pathStat.ino) {
      throw new Error("Authority control key config target changed while opening");
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
      throw new Error("Existing authority control key config is not protected");
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

function parseConfig(content: Buffer): AuthorityControlKeyConfig {
  let value: unknown;
  try { value = JSON.parse(decodeUtf8Strict(content)) as unknown; }
  catch { throw new Error("Authority control key config is not valid JSON"); }
  validateConfig(value);
  return value as AuthorityControlKeyConfig;
}

function validateConfig(value: unknown): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Authority control key config is malformed");
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !new Set(["schemaVersion", "revision", "keys"]).has(key)) ||
      record.schemaVersion !== "0.1" || !Number.isSafeInteger(record.revision) || (record.revision as number) < 1 ||
      !Array.isArray(record.keys) || record.keys.length !== MAX_KEYS) {
    throw new Error("Authority control key config is malformed");
  }
  const identities = new Set<string>();
  for (const entry of record.keys) {
    validateEntry(entry);
    const typedEntry = entry as AuthorityControlKeyConfigEntry;
    if (identities.has(typedEntry.keyId)) throw new Error(`Duplicate authority control key: ${typedEntry.keyId}`);
    identities.add(typedEntry.keyId);
  }
}

function validateEntry(value: unknown): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Authority control key config entry is malformed");
  }
  const record = value as Record<string, unknown>;
  const keys = new Set(["keyId", "keySource", "path", "service", "account", "keyDigest", "notBeforeMs", "expiresAtMs"]);
  const keySource = record.keySource;
  const fileSource = keySource === "file" &&
    typeof record.path === "string" && isAbsolute(record.path) && resolve(record.path) === record.path && !record.path.includes("\0") &&
    record.service === undefined && record.account === undefined;
  const keychainSource = keySource === "keychain" && record.path === undefined &&
    typeof record.service === "string" && /^com\.mac-operator\.[A-Za-z0-9.-]{1,96}$/u.test(record.service) &&
    typeof record.account === "string" && /^[A-Za-z0-9._:-]{1,128}$/u.test(record.account);
  if (Object.keys(record).some((key) => !keys.has(key)) ||
      typeof record.keyId !== "string" || !KEY_ID_PATTERN.test(record.keyId) ||
      (keySource !== "file" && keySource !== "keychain") || (!fileSource && !keychainSource) ||
      typeof record.keyDigest !== "string" || !DIGEST_PATTERN.test(record.keyDigest) ||
      !Number.isSafeInteger(record.notBeforeMs) || (record.notBeforeMs as number) < 0 ||
      !Number.isSafeInteger(record.expiresAtMs) || (record.expiresAtMs as number) <= (record.notBeforeMs as number)) {
    throw new Error("Authority control key config entry is malformed");
  }
}
