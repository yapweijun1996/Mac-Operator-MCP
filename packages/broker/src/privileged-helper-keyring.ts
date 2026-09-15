import { constants } from "node:fs";
import { randomUUID } from "node:crypto";
import { lstat, open, rename, unlink } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { BrokerError, canonicalJson, parseJsonUtf8Strict, sha256 } from "@mac-operator/contracts";
import {
  assertProtectedSecretDirectory,
  loadAuthenticationKey,
  loadKeychainAuthenticationKey,
  syncProtectedDirectory
} from "./credentials.js";
import type { HelperKeyConfigActivationIdentity, BrokerStore } from "./persistence.js";
import {
  BrokerPrivilegedHelperCommandFactory,
  PrivilegedHelperIpcServer,
  type BrokerPrivilegedHelperCommandFactoryOptions,
  type PrivilegedHelperIpcServerOptions
} from "./privileged-helper.js";
import {
  PrivilegedHelperAuthorityClient,
  type PrivilegedHelperAuthorityClientOptions
} from "./privileged-helper-authority-ipc.js";

const MAX_CONFIG_BYTES = 128 * 1024;
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;

export interface PrivilegedHelperKeyConfigEntry {
  keyId: string;
  keySource: "file" | "keychain";
  path?: string;
  service?: string;
  account?: string;
  keyDigest: string;
  notBeforeMs: number;
  expiresAtMs: number;
}

export interface PrivilegedHelperKeyConfig {
  schemaVersion: "0.1";
  revision: number;
  keys: readonly [PrivilegedHelperKeyConfigEntry];
}

export interface LoadedPrivilegedHelperKeyConfig {
  document: PrivilegedHelperKeyConfig;
  key: {
    keyId: string;
    key: Buffer;
    notBeforeMs: number;
    expiresAtMs: number;
  };
  payloadDigest: string;
}

/**
 * Protected, explicit-source key manager for the separately authenticated
 * privileged helper. Exactly one key is active; rotation is a monotonic
 * startup/configuration change and helper operations remain disabled unless a
 * separately reviewed adapter is provided.
 */
export class PrivilegedHelperKeyManager {
  private activeSnapshot: LoadedPrivilegedHelperKeyConfig | undefined;

  constructor(
    private readonly configPath: string,
    private readonly store: BrokerStore,
    private readonly now: () => number = Date.now
  ) {}

  async activate(expectedPreviousRevision?: number): Promise<LoadedPrivilegedHelperKeyConfig> {
    const loaded = await loadPrivilegedHelperKeyConfig(this.configPath, this.store);
    const persisted = this.store.activeHelperKeyConfigIdentity();
    const persistedRevision = persisted?.revision ?? 0;
    const expected = expectedPreviousRevision ?? persistedRevision;
    if (expected !== persistedRevision) {
      loaded.key.key.fill(0);
      throw new BrokerError("CONFLICT", "Persisted helper key configuration revision changed concurrently");
    }
    if (persisted && persisted.revision === loaded.document.revision && persisted.payloadDigest === loaded.payloadDigest) {
      this.dispose();
      this.activeSnapshot = loaded;
      return loaded;
    }
    try {
      this.store.activateHelperKeyConfig({
        revision: loaded.document.revision,
        payloadDigest: loaded.payloadDigest,
        activatedAtMs: this.now()
      }, expected);
    } catch (error) {
      loaded.key.key.fill(0);
      throw error;
    }
    this.dispose();
    this.activeSnapshot = loaded;
    return loaded;
  }

  async restore(): Promise<LoadedPrivilegedHelperKeyConfig> {
    const loaded = await loadPrivilegedHelperKeyConfig(this.configPath, this.store);
    const persisted = this.store.activeHelperKeyConfigIdentity();
    if (!persisted || persisted.revision !== loaded.document.revision || persisted.payloadDigest !== loaded.payloadDigest) {
      loaded.key.key.fill(0);
      throw new BrokerError("PRECONDITION_FAILED", "Helper key configuration does not match persisted activation");
    }
    this.dispose();
    this.activeSnapshot = loaded;
    return loaded;
  }

  current(): LoadedPrivilegedHelperKeyConfig {
    if (!this.activeSnapshot) throw new BrokerError("PRECONDITION_FAILED", "Helper key configuration is not activated");
    return this.activeSnapshot;
  }

  assertUsable(): Buffer {
    const snapshot = this.current();
    const nowMs = this.now();
    if (!Number.isSafeInteger(nowMs) || nowMs < snapshot.key.notBeforeMs || nowMs >= snapshot.key.expiresAtMs) {
      throw new BrokerError("AUTH_EXPIRED", "Privileged helper key is outside its validity window");
    }
    return Buffer.from(snapshot.key.key);
  }

  createCommandFactory(
    options: Omit<BrokerPrivilegedHelperCommandFactoryOptions, "authenticationKey">
  ): BrokerPrivilegedHelperCommandFactory {
    const key = this.assertUsable();
    const binding = this.captureBinding();
    try {
      return new BrokerPrivilegedHelperCommandFactory({
        ...options,
        authenticationKey: key,
        keyRevocationCheck: () => this.store.isRevoked("helper_key", binding.keyId),
        keyAuthorityCheck: () => this.assertBindingUsable(binding),
        authorizeCommand: (command) => {
          this.assertBindingUsable(binding);
          options.authorizeCommand(command);
        }
      });
    } finally {
      key.fill(0);
    }
  }

  createServer(
    options: Omit<PrivilegedHelperIpcServerOptions, "authenticationKey">
  ): PrivilegedHelperIpcServer {
    const key = this.assertUsable();
    const binding = this.captureBinding();
    try {
      return new PrivilegedHelperIpcServer({
        ...options,
        authenticationKey: key,
        keyAuthorityCheck: () => this.assertBindingUsable(binding),
        authorizeCommand: (command) => {
          this.assertBindingUsable(binding);
          options.authorizeCommand(command);
        },
        ...(options.authorizeStatus === undefined ? {} : {
          authorizeStatus: () => {
            this.assertBindingUsable(binding);
            options.authorizeStatus!();
          }
        })
      });
    } finally {
      key.fill(0);
    }
  }

  /**
   * Creates the helper-side Broker authority poller from the same active key
   * binding as the command server. The caller never receives the key bytes;
   * key rotation, revocation, and validity are rechecked for every poll.
   */
  createAuthorityPoller(
    options: Omit<PrivilegedHelperAuthorityClientOptions, "authenticationKey" | "keyAuthorityCheck">
  ): PrivilegedHelperAuthorityClient {
    const key = this.assertUsable();
    const binding = this.captureBinding();
    try {
      return new PrivilegedHelperAuthorityClient({
        ...options,
        authenticationKey: key,
        keyAuthorityCheck: () => this.assertBindingUsable(binding)
      });
    } finally {
      key.fill(0);
    }
  }

  dispose(): void {
    this.activeSnapshot?.key.key.fill(0);
    this.activeSnapshot = undefined;
  }

  private captureBinding(): HelperKeyBinding {
    const snapshot = this.current();
    return {
      keyId: snapshot.key.keyId,
      revision: snapshot.document.revision,
      payloadDigest: snapshot.payloadDigest,
      notBeforeMs: snapshot.key.notBeforeMs,
      expiresAtMs: snapshot.key.expiresAtMs
    };
  }

  private assertBindingUsable(binding: HelperKeyBinding): void {
    if (this.store.isRevoked("helper_key", binding.keyId)) {
      throw new BrokerError("REVOKED", "Privileged helper key has been revoked");
    }
    const active = this.store.activeHelperKeyConfigIdentity();
    if (!active || active.revision !== binding.revision || active.payloadDigest !== binding.payloadDigest) {
      throw new BrokerError("REVOKED", "Privileged helper key configuration is no longer active");
    }
    const nowMs = this.now();
    if (!Number.isSafeInteger(nowMs) || nowMs < binding.notBeforeMs || nowMs >= binding.expiresAtMs) {
      throw new BrokerError("AUTH_EXPIRED", "Privileged helper key is outside its validity window");
    }
  }
}

interface HelperKeyBinding {
  keyId: string;
  revision: number;
  payloadDigest: string;
  notBeforeMs: number;
  expiresAtMs: number;
}

export async function loadPrivilegedHelperKeyConfig(
  path: string,
  store: BrokerStore
): Promise<LoadedPrivilegedHelperKeyConfig> {
  const document = parseConfig(await readProtectedConfig(path));
  const entry = document.keys[0];
  if (store.isRevoked("helper_key", entry.keyId)) {
    throw new Error(`Privileged helper key is revoked: ${entry.keyId}`);
  }
  const key = entry.keySource === "keychain"
    ? await loadKeychainAuthenticationKey(entry.service!, entry.account!)
    : await loadAuthenticationKey(entry.path!);
  try {
    if (sha256(key) !== entry.keyDigest) throw new Error("Privileged helper key digest precondition failed");
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

export async function writePrivilegedHelperKeyConfig(
  path: string,
  document: PrivilegedHelperKeyConfig
): Promise<string> {
  validateConfig(document);
  validateConfigPath(path);
  await assertProtectedSecretDirectory(dirname(path));
  const content = Buffer.from(`${canonicalJson(document)}\n`, "utf8");
  if (content.byteLength > MAX_CONFIG_BYTES) throw new Error("Privileged helper key config is too large");
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
    throw new Error("Privileged helper key config path must be canonical and absolute");
  }
}

async function readProtectedConfig(path: string): Promise<Buffer> {
  validateConfigPath(path);
  await assertProtectedSecretDirectory(dirname(path));
  const pathStat = await lstat(path);
  const currentUid = process.getuid?.();
  if (!pathStat.isFile() || pathStat.isSymbolicLink()) throw new Error("Privileged helper key config must be a regular non-symlink file");
  if (currentUid === undefined || pathStat.uid !== currentUid) throw new Error("Privileged helper key config must be owned by the Broker user");
  if ((pathStat.mode & 0o077) !== 0) throw new Error("Privileged helper key config must not be accessible by group or other users");
  if (pathStat.size < 2 || pathStat.size > MAX_CONFIG_BYTES) throw new Error("Privileged helper key config size is invalid");
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const openedStat = await handle.stat();
    if (!openedStat.isFile() || openedStat.dev !== pathStat.dev || openedStat.ino !== pathStat.ino) throw new Error("Privileged helper key config target changed while opening");
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

async function rejectUnsafeExistingConfig(path: string): Promise<void> {
  try {
    const current = await lstat(path);
    const uid = process.getuid?.();
    if (!current.isFile() || current.isSymbolicLink() || uid === undefined || current.uid !== uid || (current.mode & 0o077) !== 0) throw new Error("Existing privileged helper key config is not protected");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

function parseConfig(content: Buffer): PrivilegedHelperKeyConfig {
  let value: unknown;
  try { value = parseJsonUtf8Strict(content); }
  catch { throw new Error("Privileged helper key config is not valid JSON"); }
  validateConfig(value);
  return value as PrivilegedHelperKeyConfig;
}

function validateConfig(value: unknown): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Privileged helper key config is malformed");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !new Set(["schemaVersion", "revision", "keys"]).has(key)) ||
      record.schemaVersion !== "0.1" || !Number.isSafeInteger(record.revision) || (record.revision as number) < 1 ||
      !Array.isArray(record.keys) || record.keys.length !== 1) throw new Error("Privileged helper key config is malformed");
  validateEntry(record.keys[0]);
}

function validateEntry(value: unknown): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Privileged helper key config entry is malformed");
  const record = value as Record<string, unknown>;
  const keys = new Set(["keyId", "keySource", "path", "service", "account", "keyDigest", "notBeforeMs", "expiresAtMs"]);
  const fileSource = record.keySource === "file" && typeof record.path === "string" && isAbsolute(record.path) && resolve(record.path) === record.path && !record.path.includes("\0") && record.service === undefined && record.account === undefined;
  const keychainSource = record.keySource === "keychain" && record.path === undefined && typeof record.service === "string" && /^com\.mac-operator\.[A-Za-z0-9.-]{1,96}$/u.test(record.service) && typeof record.account === "string" && /^[A-Za-z0-9._:-]{1,128}$/u.test(record.account);
  if (Object.keys(record).some((key) => !keys.has(key)) || typeof record.keyId !== "string" || !KEY_ID_PATTERN.test(record.keyId) || (!fileSource && !keychainSource) || typeof record.keyDigest !== "string" || !DIGEST_PATTERN.test(record.keyDigest) || !Number.isSafeInteger(record.notBeforeMs) || (record.notBeforeMs as number) < 0 || !Number.isSafeInteger(record.expiresAtMs) || (record.expiresAtMs as number) <= (record.notBeforeMs as number)) throw new Error("Privileged helper key config entry is malformed");
}
