import { constants } from "node:fs";
import { randomBytes, randomUUID } from "node:crypto";
import { link, lstat, open, rename, unlink } from "node:fs/promises";
import { dirname, isAbsolute } from "node:path";
import { sha256 } from "@mac-operator/contracts";
import { keyIdentity } from "./edge-keyring.js";
import { approvalKeyIdentity, type ApprovalIssuerKey } from "./approval-authority.js";
import type { AuditAnchorKeySource } from "./audit-anchor.js";
import type { BrokerStore, RevocationKind } from "./persistence.js";
import type { BrokerBackupKeySource } from "./persistence-backup.js";
import {
  deleteKeychainGenericPassword,
  inspectKeychainGenericPassword,
  readKeychainGenericPassword,
  validateKeychainCoordinates,
  writeKeychainGenericPassword,
  type KeychainGenericPasswordMetadata
} from "./peer-credentials.js";

const HEX_KEY_PATTERN = /^[A-Fa-f0-9]{64}$/u;
const BACKUP_KEY_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;

/**
 * Explicit Keychain source for a 32-byte authentication key. This is not
 * selected by file paths or MCP arguments; startup/configuration code must
 * choose it deliberately and keep the returned bytes in memory only.
 */
export async function loadKeychainAuthenticationKey(
  service: string,
  account: string,
  trustedExecutablePath = process.execPath
): Promise<Buffer> {
  return readKeychainGenericPassword(service, account, trustedExecutablePath);
}

/**
 * Explicitly provisions one random 32-byte authentication key in the
 * Broker-owned file-based Keychain namespace. The item ACL is bound to the
 * supplied canonical Broker executable. The secret is returned only as a
 * digest; callers must reload it through `loadKeychainAuthenticationKey`.
 */
export async function provisionKeychainAuthenticationKey(
  service: string,
  account: string,
  trustedExecutablePath: string
): Promise<{ digest: string }> {
  if (!/^com\.mac-operator\.[A-Za-z0-9.-]{1,96}$/u.test(service) ||
      !/^[A-Za-z0-9._:-]{1,128}$/u.test(account)) {
    throw new Error("Keychain service or account is invalid");
  }
  const key = randomBytes(32);
  try {
    writeKeychainGenericPassword(service, account, key, trustedExecutablePath);
    return { digest: sha256(key) };
  } finally {
    key.fill(0);
  }
}

/**
 * Returns an explicit Keychain-backed source for encrypted Broker backups.
 * The source is configuration-owned; MCP arguments cannot select its item.
 */
export function createKeychainBrokerBackupKeySource(
  service: string,
  account: string,
  keyId: string
): BrokerBackupKeySource {
  validateKeychainCoordinates(service, account);
  if (!BACKUP_KEY_ID_PATTERN.test(keyId)) throw new Error("Broker backup key ID is invalid");
  return {
    keyId,
    loadKey: () => readKeychainGenericPassword(service, account, process.execPath)
  };
}

/** Returns a synchronous Keychain-backed source for the optional audit anchor. */
export function createKeychainAuditAnchorKeySource(
  service: string,
  account: string,
  keyId: string
): AuditAnchorKeySource {
  validateKeychainCoordinates(service, account);
  if (!BACKUP_KEY_ID_PATTERN.test(keyId)) throw new Error("Audit anchor key ID is invalid");
  return {
    keyId,
    loadKey: () => readKeychainGenericPassword(service, account, process.execPath)
  };
}

/** Provisions a dedicated 32-byte backup key with a Broker-executable ACL. */
export async function provisionKeychainBrokerBackupKey(
  service: string,
  account: string,
  trustedExecutablePath: string
): Promise<{ digest: string }> {
  validateKeychainCoordinates(service, account);
  const key = randomBytes(32);
  try {
    writeKeychainGenericPassword(service, account, key, trustedExecutablePath);
    return { digest: sha256(key) };
  } finally {
    key.fill(0);
  }
}

/**
 * Reads and validates the non-secret protection attributes required by the
 * Broker-owned Keychain contract. This is an operator/startup check only; it
 * is deliberately not a model-facing tool and never returns key bytes.
 */
export function verifyKeychainProtection(
  service: string,
  account: string,
  trustedExecutablePath: string
): KeychainGenericPasswordMetadata {
  validateKeychainCoordinates(service, account);
  const metadata = inspectKeychainGenericPassword(service, account, trustedExecutablePath);
  if (!metadata.identityMatches || metadata.protection !== "file-based-acl" ||
      metadata.synchronizable || !metadata.trustedApplicationMatches) {
    throw new Error("Keychain generic password protection is not approved");
  }
  return metadata;
}

/** Retires a Keychain item only after an exact secret digest and identity check. */
export async function retireKeychainAuthenticationKey(
  service: string,
  account: string,
  expectedDigest: string
): Promise<void> {
  validateKeychainCoordinates(service, account);
  if (!/^[a-f0-9]{64}$/u.test(expectedDigest)) throw new Error("Expected Keychain key digest is malformed");
  const key = await loadKeychainAuthenticationKey(service, account);
  try {
    if (sha256(key) !== expectedDigest) throw new Error("Keychain key digest precondition failed");
    deleteKeychainGenericPassword(service, account, key, process.execPath);
  } finally {
    key.fill(0);
  }
}

export async function loadAuthenticationKey(path: string): Promise<Buffer> {
  if (!isAbsolute(path)) throw new Error("Authentication key path must be absolute");
  await assertProtectedSecretDirectory(dirname(path));
  const pathStat = await lstat(path);
  const currentUid = process.getuid?.();
  if (!pathStat.isFile() || pathStat.isSymbolicLink()) {
    throw new Error("Authentication key must be a regular non-symlink file");
  }
  if (currentUid === undefined || pathStat.uid !== currentUid) {
    throw new Error("Authentication key must be owned by the Broker user");
  }
  if ((pathStat.mode & 0o077) !== 0) {
    throw new Error("Authentication key must not be accessible by group or other users");
  }
  if (pathStat.size < 32 || pathStat.size > 65) {
    throw new Error("Authentication key file has an invalid size");
  }

  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const openedStat = await handle.stat();
    if (!openedStat.isFile() || openedStat.dev !== pathStat.dev || openedStat.ino !== pathStat.ino) {
      throw new Error("Authentication key target changed while opening");
    }
    const content = await handle.readFile();
    if (content.byteLength === 32) return Buffer.from(content);
    const text = content.toString("ascii").trim();
    if (!HEX_KEY_PATTERN.test(text)) throw new Error("Authentication key must be 32 raw bytes or 64 hexadecimal characters");
    return Buffer.from(text, "hex");
  } finally {
    await handle.close();
  }
}

export async function provisionAuthenticationKey(path: string): Promise<{ digest: string }> {
  if (!isAbsolute(path)) throw new Error("Authentication key path must be absolute");
  await assertProtectedSecretDirectory(dirname(path));
  const key = randomBytes(32);
  const handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try {
    await handle.writeFile(key);
    await handle.sync();
  } catch (error) {
    await handle.close();
    await unlink(path).catch(() => undefined);
    throw error;
  }
  await handle.close();
  await syncProtectedDirectory(dirname(path));
  return { digest: sha256(key) };
}

export async function retireRevokedAuthenticationKey(
  path: string,
  expectedDigest: string,
  edgeId: string,
  keyId: string,
  store: BrokerStore
): Promise<void> {
  await retireRevokedSecretKey(path, expectedDigest, "edge_key", keyIdentity(edgeId, keyId), store, "Authentication key");
}

export async function loadApprovalIssuerKey(
  path: string,
  issuerId: string,
  keyId: string,
  notBeforeMs: number,
  expiresAtMs: number,
  allowUnattended: boolean
): Promise<ApprovalIssuerKey> {
  return {
    issuerId,
    keyId,
    key: await loadAuthenticationKey(path),
    notBeforeMs,
    expiresAtMs,
    allowUnattended
  };
}

export async function retireRevokedApprovalIssuerKey(
  path: string,
  expectedDigest: string,
  issuerId: string,
  keyId: string,
  store: BrokerStore
): Promise<void> {
  await retireRevokedSecretKey(path, expectedDigest, "approval_key", approvalKeyIdentity(issuerId, keyId), store, "Approval issuer key");
}

async function retireRevokedSecretKey(
  path: string,
  expectedDigest: string,
  revocationKind: RevocationKind,
  subjectId: string,
  store: BrokerStore,
  label: string
): Promise<void> {
  if (!store.isRevoked(revocationKind, subjectId)) {
    throw new Error(`${label} must be revoked before retirement`);
  }
  if (!/^[a-f0-9]{64}$/u.test(expectedDigest)) throw new Error("Expected authentication key digest is malformed");
  const originalStat = await lstat(path);
  const key = await loadAuthenticationKey(path);
  let quarantinePath: string | undefined;
  try {
    if (sha256(key) !== expectedDigest) throw new Error(`${label} digest precondition failed`);

    const beforeRename = await lstat(path);
    if (!sameProtectedFileIdentity(originalStat, beforeRename)) {
      throw new Error("Authentication key target changed before retirement");
    }
    quarantinePath = `${path}.retired-${randomUUID()}`;
    await rename(path, quarantinePath);
    const quarantinedStat = await lstat(quarantinePath);
    if (!sameProtectedFileIdentity(originalStat, quarantinedStat)) {
      throw new Error("Authentication key target changed during retirement");
    }
    await unlink(quarantinePath);
    await syncProtectedDirectory(dirname(path));
  } catch (error) {
    // If a failure happens after moving the exact original file, restore it
    // with a non-overwriting hard link. An attacker-created replacement at
    // the original pathname is never replaced, and the quarantine is left for
    // explicit operator recovery when restoration cannot be proven safe.
    if (quarantinePath !== undefined) {
      const quarantined = await lstat(quarantinePath).catch(() => undefined);
      if (quarantined !== undefined && sameProtectedFileIdentity(originalStat, quarantined)) {
        try {
          await link(quarantinePath, path);
          await unlink(quarantinePath);
        } catch {
          // Preserve the exact quarantine artifact for explicit recovery.
        }
      }
    }
    throw error;
  } finally {
    key.fill(0);
  }
}

function sameProtectedFileIdentity(
  left: Awaited<ReturnType<typeof lstat>>,
  right: Awaited<ReturnType<typeof lstat>>
): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid && left.mode === right.mode &&
    left.size === right.size && left.mtimeMs === right.mtimeMs;
}

export async function assertProtectedSecretDirectory(path: string): Promise<void> {
  const directoryStat = await lstat(path);
  const currentUid = process.getuid?.();
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
    throw new Error("Authentication key directory must be a non-symlink directory");
  }
  if (currentUid === undefined || directoryStat.uid !== currentUid) {
    throw new Error("Authentication key directory must be owned by the Broker user");
  }
  if ((directoryStat.mode & 0o077) !== 0) {
    throw new Error("Authentication key directory must not be accessible by group or other users");
  }
}

export async function syncProtectedDirectory(path: string): Promise<void> {
  const directory = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}
