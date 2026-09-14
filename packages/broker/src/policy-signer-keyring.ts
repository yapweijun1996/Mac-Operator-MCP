import { constants, lstat, open, rename, unlink } from "node:fs/promises";
import { createPrivateKey, createPublicKey, randomUUID } from "node:crypto";
import { dirname, isAbsolute, resolve } from "node:path";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import {
  PolicyBundleVerifier,
  type PolicyVerificationKey
} from "./policy-loader.js";
import {
  assertProtectedSecretDirectory,
  syncProtectedDirectory
} from "./credentials.js";
import type {
  BrokerStore,
  PolicySignerConfigActivationIdentity
} from "./persistence.js";

const MAX_CONFIG_BYTES = 128 * 1024;
const MAX_PUBLIC_KEY_BYTES = 64 * 1024;
const MAX_KEYS = 32;

export interface PolicySignerKeyConfigEntry {
  keyId: string;
  path: string;
  publicKeyDigest: string;
  notBeforeMs: number;
  expiresAtMs: number;
}

export interface PolicySignerKeyConfig {
  schemaVersion: "0.1";
  revision: number;
  keys: readonly PolicySignerKeyConfigEntry[];
}

export interface LoadedPolicySignerKeyConfig {
  document: PolicySignerKeyConfig;
  keys: readonly PolicyVerificationKey[];
  payloadDigest: string;
}

/**
 * Local operator boundary for policy signer metadata. This module is not
 * exposed through the MCP Edge; callers must explicitly activate or restore
 * a protected configuration before constructing a verifier.
 */
export class PolicySignerKeyManager {
  private activeSnapshot: LoadedPolicySignerKeyConfig | undefined;

  constructor(
    private readonly configPath: string,
    private readonly schemaDirectory: string,
    private readonly store: BrokerStore,
    private readonly now: () => number = Date.now,
    private readonly allowedClockSkewMs = 5_000
  ) {}

  async activate(expectedPreviousRevision?: number): Promise<LoadedPolicySignerKeyConfig> {
    const loaded = await loadPolicySignerKeyConfig(this.configPath);
    const persisted = this.store.activePolicySignerConfigIdentity();
    const persistedRevision = persisted?.revision ?? 0;
    const expected = expectedPreviousRevision ?? persistedRevision;
    if (expected !== persistedRevision) {
      throw new BrokerError("CONFLICT", "Persisted policy signer configuration revision changed concurrently");
    }
    if (persisted && persisted.revision === loaded.document.revision && persisted.payloadDigest === loaded.payloadDigest) {
      this.activeSnapshot = loaded;
      return loaded;
    }
    const identity: PolicySignerConfigActivationIdentity = {
      revision: loaded.document.revision,
      payloadDigest: loaded.payloadDigest,
      activatedAtMs: this.now()
    };
    this.store.activatePolicySignerConfig(identity, expected);
    this.activeSnapshot = loaded;
    return loaded;
  }

  async reload(expectedPreviousRevision?: number): Promise<LoadedPolicySignerKeyConfig> {
    return this.activate(expectedPreviousRevision);
  }

  async restore(): Promise<LoadedPolicySignerKeyConfig> {
    const loaded = await loadPolicySignerKeyConfig(this.configPath);
    const persisted = this.store.activePolicySignerConfigIdentity();
    if (!persisted || persisted.revision !== loaded.document.revision || persisted.payloadDigest !== loaded.payloadDigest) {
      throw new BrokerError("PRECONDITION_FAILED", "Policy signer configuration does not match persisted activation");
    }
    this.activeSnapshot = loaded;
    return loaded;
  }

  async rollback(precondition: {
    expectedCurrentRevision: number;
    reasonCode: string;
  }): Promise<LoadedPolicySignerKeyConfig> {
    const loaded = await loadPolicySignerKeyConfig(this.configPath);
    const historical = this.store.policySignerConfigHistoryIdentity(loaded.document.revision);
    if (!historical || historical.payloadDigest !== loaded.payloadDigest) {
      throw new BrokerError("PRECONDITION_FAILED", "Policy signer rollback target does not match verified history");
    }
    const rolledBackAtMs = this.now();
    this.store.rollbackPolicySignerConfig(
      {
        revision: loaded.document.revision,
        payloadDigest: loaded.payloadDigest,
        activatedAtMs: rolledBackAtMs
      },
      precondition.expectedCurrentRevision,
      precondition.reasonCode,
      rolledBackAtMs
    );
    this.activeSnapshot = loaded;
    return loaded;
  }

  async revoke(keyId: string, reason: string, nowMs = this.now()): Promise<void> {
    const snapshot = this.current();
    if (!snapshot.keys.some((key) => key.keyId === keyId)) {
      throw new BrokerError("TARGET_NOT_FOUND", "Policy signer key is not present in the active configuration");
    }
    this.store.revokePolicySigner(keyId, reason, nowMs);
  }

  current(): LoadedPolicySignerKeyConfig {
    if (!this.activeSnapshot) throw new BrokerError("PRECONDITION_FAILED", "Policy signer configuration is not activated");
    return this.activeSnapshot;
  }

  async createVerifier(): Promise<PolicyBundleVerifier> {
    const snapshot = this.current();
    return PolicyBundleVerifier.create({
      schemaDirectory: this.schemaDirectory,
      trustedKeys: snapshot.keys,
      revocationCheck: (keyId) => this.store.isRevoked("policy_signer", keyId),
      now: this.now,
      allowedClockSkewMs: this.allowedClockSkewMs
    });
  }
}

export async function loadPolicySignerKeyConfig(
  path: string
): Promise<LoadedPolicySignerKeyConfig> {
  const document = parseConfig(await readProtectedConfig(path));
  const identities = new Set<string>();
  const keys: PolicyVerificationKey[] = [];
  for (const entry of document.keys) {
    if (identities.has(entry.keyId)) throw new Error(`Duplicate policy signer key: ${entry.keyId}`);
    identities.add(entry.keyId);
    const publicKeyPem = await readProtectedPublicKey(entry.path);
    try {
      createPrivateKey(publicKeyPem);
      throw new Error(`Policy signer key must contain public material only: ${entry.keyId}`);
    } catch (error) {
      if (error instanceof Error && error.message.includes("public material only")) throw error;
    }
    const publicKey = createPublicKey(publicKeyPem);
    if (publicKey.asymmetricKeyType !== "ed25519") {
      throw new Error(`Policy signer key must be Ed25519: ${entry.keyId}`);
    }
    if (sha256(publicKeyPem) !== entry.publicKeyDigest) {
      throw new Error(`Policy signer public key digest does not match configuration: ${entry.keyId}`);
    }
    keys.push({
      keyId: entry.keyId,
      publicKeyPem,
      notBeforeMs: entry.notBeforeMs,
      expiresAtMs: entry.expiresAtMs
    });
  }
  return { document, keys, payloadDigest: sha256(canonicalJson(document)) };
}

/** Atomically writes metadata; private signer keys never enter this file. */
export async function writePolicySignerKeyConfig(path: string, document: PolicySignerKeyConfig): Promise<string> {
  validateConfig(document);
  if (!isAbsolute(path) || resolve(path) !== path || path.includes("\0")) {
    throw new Error("Policy signer key config path must be canonical and absolute");
  }
  await assertProtectedSecretDirectory(dirname(path));
  const content = Buffer.from(`${canonicalJson(document)}\n`, "utf8");
  if (content.byteLength > MAX_CONFIG_BYTES) throw new Error("Policy signer key config is too large");
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
    throw new Error("Policy signer key config path must be canonical and absolute");
  }
  await assertProtectedSecretDirectory(dirname(path));
  const pathStat = await lstat(path);
  const currentUid = process.getuid?.();
  if (!pathStat.isFile() || pathStat.isSymbolicLink()) {
    throw new Error("Policy signer key config must be a regular non-symlink file");
  }
  if (currentUid === undefined || pathStat.uid !== currentUid) {
    throw new Error("Policy signer key config must be owned by the Broker user");
  }
  if ((pathStat.mode & 0o077) !== 0) {
    throw new Error("Policy signer key config must not be accessible by group or other users");
  }
  if (pathStat.size < 2 || pathStat.size > MAX_CONFIG_BYTES) {
    throw new Error("Policy signer key config size is invalid");
  }
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const openedStat = await handle.stat();
    if (!openedStat.isFile() || openedStat.dev !== pathStat.dev || openedStat.ino !== pathStat.ino) {
      throw new Error("Policy signer key config target changed while opening");
    }
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

async function readProtectedPublicKey(path: string): Promise<Buffer> {
  if (!isAbsolute(path) || resolve(path) !== path || path.includes("\0")) {
    throw new Error("Policy signer public key path must be canonical and absolute");
  }
  await assertProtectedSecretDirectory(dirname(path));
  const pathStat = await lstat(path);
  const currentUid = process.getuid?.();
  if (!pathStat.isFile() || pathStat.isSymbolicLink()) {
    throw new Error("Policy signer public key must be a regular non-symlink file");
  }
  if (currentUid === undefined || pathStat.uid !== currentUid) {
    throw new Error("Policy signer public key must be owned by the Broker user");
  }
  if ((pathStat.mode & 0o077) !== 0) {
    throw new Error("Policy signer public key must not be accessible by group or other users");
  }
  if (pathStat.size < 2 || pathStat.size > MAX_PUBLIC_KEY_BYTES) {
    throw new Error("Policy signer public key file size is invalid");
  }
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const openedStat = await handle.stat();
    if (!openedStat.isFile() || openedStat.dev !== pathStat.dev || openedStat.ino !== pathStat.ino) {
      throw new Error("Policy signer public key target changed while opening");
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
      throw new Error("Existing policy signer key config is not protected");
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

function parseConfig(content: Buffer): PolicySignerKeyConfig {
  let value: unknown;
  try { value = JSON.parse(content.toString("utf8")) as unknown; }
  catch { throw new Error("Policy signer key config is not valid JSON"); }
  validateConfig(value);
  return value as PolicySignerKeyConfig;
}

function validateConfig(value: unknown): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Policy signer key config is malformed");
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !new Set(["schemaVersion", "revision", "keys"]).has(key)) ||
      record.schemaVersion !== "0.1" || !Number.isSafeInteger(record.revision) || (record.revision as number) < 1 ||
      !Array.isArray(record.keys) || record.keys.length < 1 || record.keys.length > MAX_KEYS) {
    throw new Error("Policy signer key config is malformed");
  }
  const identities = new Set<string>();
  for (const entry of record.keys) {
    validateEntry(entry);
    const typedEntry = entry as PolicySignerKeyConfigEntry;
    if (identities.has(typedEntry.keyId)) throw new Error(`Duplicate policy signer key: ${typedEntry.keyId}`);
    identities.add(typedEntry.keyId);
  }
}

function validateEntry(value: unknown): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Policy signer key config entry is malformed");
  }
  const record = value as Record<string, unknown>;
  const keys = new Set(["keyId", "path", "publicKeyDigest", "notBeforeMs", "expiresAtMs"]);
  if (Object.keys(record).some((key) => !keys.has(key)) ||
      typeof record.keyId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(record.keyId) ||
      typeof record.path !== "string" || !isAbsolute(record.path) || resolve(record.path) !== record.path || record.path.includes("\0") ||
      typeof record.publicKeyDigest !== "string" || !/^[a-f0-9]{64}$/u.test(record.publicKeyDigest) ||
      !Number.isSafeInteger(record.notBeforeMs) || (record.notBeforeMs as number) < 0 ||
      !Number.isSafeInteger(record.expiresAtMs) || (record.expiresAtMs as number) <= (record.notBeforeMs as number)) {
    throw new Error("Policy signer key config entry is malformed");
  }
}
