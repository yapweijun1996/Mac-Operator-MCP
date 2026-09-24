import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { chmod, lstat, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  createKeychainBrokerBackupKeySource,
  createKeychainAuditArchiveKeySource,
  createKeychainAuditAnchorKeySource,
  loadAuthenticationKey,
  loadApprovalIssuerKey,
  loadKeychainAuthenticationKey,
  provisionAuthenticationKey,
  provisionKeychainAuthenticationKey,
  provisionKeychainBrokerBackupKey,
  retireRevokedApprovalIssuerKey,
  retireRevokedAuthenticationKey,
  retireKeychainAuthenticationKey,
  verifyKeychainProtection
} from "./credentials.js";
import { BrokerStore } from "./persistence.js";
import { parseKeychainGenericPasswordMetadata } from "./peer-credentials.js";

const realKeychainEnabled = process.platform === "darwin" && process.env.MOPS_REAL_KEYCHAIN === "1";

test("authentication key loader accepts an owner-only 32-byte file", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-key-"));
  const path = join(directory, "edge.key");
  const expected = randomBytes(32);
  try {
    await writeFile(path, expected, { mode: 0o600 });
    assert.deepEqual(await loadAuthenticationKey(path), expected);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("authentication key provisioning is exclusive, durable, and owner-only", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-key-provision-"));
  const path = join(directory, "edge.key");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const provisioned = await provisionAuthenticationKey(path);
    const key = await loadAuthenticationKey(path);
    assert.equal(key.byteLength, 32);
    assert.equal((await lstat(path)).mode & 0o777, 0o600);
    await assert.rejects(provisionAuthenticationKey(path), /EEXIST/u);
    await assert.rejects(
      retireRevokedAuthenticationKey(path, provisioned.digest, "edge-1", "edge-key-1", store),
      /must be revoked/u
    );
    store.revoke("edge_key", "edge-1:edge-key-1", "ROTATED");
    await retireRevokedAuthenticationKey(path, provisioned.digest, "edge-1", "edge-key-1", store);
    await assert.rejects(lstat(path), /ENOENT/u);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("authentication key retirement requires the exact key digest", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-key-retire-"));
  const path = join(directory, "edge.key");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    await provisionAuthenticationKey(path);
    store.revoke("edge_key", "edge-1:edge-key-1", "ROTATED");
    await assert.rejects(
      retireRevokedAuthenticationKey(path, "0".repeat(64), "edge-1", "edge-key-1", store),
      /digest precondition failed/u
    );
    assert.equal((await loadAuthenticationKey(path)).byteLength, 32);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("authentication key loader rejects weak permissions and symlinks", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-key-deny-"));
  const path = join(directory, "edge.key");
  const link = join(directory, "edge-link.key");
  try {
    await writeFile(path, randomBytes(32), { mode: 0o600 });
    await chmod(path, 0o640);
    await assert.rejects(loadAuthenticationKey(path), /must not be accessible/u);
    await chmod(path, 0o600);
    await symlink(path, link);
    await assert.rejects(loadAuthenticationKey(link), /non-symlink/u);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("Keychain authentication source validates identity and fails closed when the item is absent", async () => {
  const account = `edge:missing:${randomUUID()}`;
  await assert.rejects(
    loadKeychainAuthenticationKey("com.mac-operator.test", account),
    /Keychain generic password is unavailable/u
  );
  await assert.rejects(
    loadKeychainAuthenticationKey("/tmp/attacker", account),
    /Keychain service or account is invalid/u
  );
  await assert.rejects(
    loadKeychainAuthenticationKey("com.mac-operator.test", "../escape"),
    /Keychain service or account is invalid/u
  );
});

test("Keychain authentication provisioning validates its explicit namespace without creating malformed items", async () => {
  await assert.rejects(
    provisionKeychainAuthenticationKey("/tmp/attacker", `edge:invalid:${randomUUID()}`, process.execPath),
    /Keychain service or account is invalid/u
  );
  await assert.rejects(
    provisionKeychainAuthenticationKey("com.mac-operator.test", `../escape`, process.execPath),
    /Keychain service or account is invalid/u
  );
});

test("Keychain backup key source binds a fixed Broker-owned item", async () => {
  const source = createKeychainBrokerBackupKeySource("com.mac-operator.test", "backup:primary", "backup-key-1");
  assert.equal(source.keyId, "backup-key-1");
  await assert.rejects(async () => source.loadKey(), /Keychain generic password is unavailable/u);
  assert.throws(
    () => createKeychainBrokerBackupKeySource("com.mac-operator.test", "backup:primary", "../escape"),
    /key ID is invalid/u
  );
  await assert.rejects(
    provisionKeychainBrokerBackupKey("/tmp/attacker", "backup:primary", process.execPath),
    /Keychain service or account is invalid/u
  );
});

test("Keychain audit anchor source binds a fixed Broker-owned item", () => {
  const source = createKeychainAuditAnchorKeySource("com.mac-operator.test", "audit:primary", "audit-key-1");
  assert.throws(() => source.loadKey(), /Keychain generic password is unavailable/u);
  assert.throws(
    () => createKeychainAuditAnchorKeySource("com.mac-operator.test", "audit:primary", "../escape"),
    /Audit anchor key ID is invalid/u
  );
});

test("Keychain audit archive source requires a separate fixed Broker-owned item", async () => {
  const source = createKeychainAuditArchiveKeySource("com.mac-operator.test", "audit-export:primary", "audit-export-key-1");
  assert.equal(source.keyId, "audit-export-key-1");
  await assert.rejects(async () => source.loadKey(), /Keychain generic password is unavailable/u);
  assert.throws(
    () => createKeychainAuditArchiveKeySource("com.mac-operator.test", "audit-export:primary", "../escape"),
    /Audit archive key ID is invalid/u
  );
});

test("Keychain protection metadata parser is strict and non-secret", () => {
  assert.deepEqual(
    parseKeychainGenericPasswordMetadata({
      identityMatches: true,
      protection: "file-based-acl",
      synchronizable: false,
      synchronizableAttributePresent: true,
      trustedApplicationMatches: true
    }),
    {
      identityMatches: true,
      protection: "file-based-acl",
      synchronizable: false,
      synchronizableAttributePresent: true,
      trustedApplicationMatches: true
    }
  );
  assert.throws(
    () => parseKeychainGenericPasswordMetadata({
      identityMatches: true,
      protection: "file-based-acl",
      synchronizable: false,
      synchronizableAttributePresent: true,
      trustedApplicationMatches: "yes"
    }),
    /metadata is malformed/u
  );
});

test("real macOS Keychain ACL binds one Broker executable and retires by digest", {
  skip: !realKeychainEnabled
}, async () => {
  const service = "com.mac-operator.evidence";
  const account = `acl:${randomUUID()}`;
  let digest: string | undefined;
  try {
    const provisioned = await provisionKeychainAuthenticationKey(service, account, process.execPath);
    digest = provisioned.digest;
    const loaded = await loadKeychainAuthenticationKey(service, account);
    try {
      assert.equal(createHash("sha256").update(loaded).digest("hex"), digest);
    } finally {
      loaded.fill(0);
    }
    assert.deepEqual(verifyKeychainProtection(service, account, process.execPath), {
      identityMatches: true,
      protection: "file-based-acl",
      synchronizable: false,
      synchronizableAttributePresent: false,
      trustedApplicationMatches: true
    });
    assert.throws(
      () => verifyKeychainProtection(service, account, "/usr/bin/security"),
      /protection is not approved|owned by the current user/u
    );
    await assert.rejects(
      retireKeychainAuthenticationKey(service, account, "0".repeat(64)),
      /digest precondition failed/u
    );
    await retireKeychainAuthenticationKey(service, account, digest);
    digest = undefined;
    await assert.rejects(loadKeychainAuthenticationKey(service, account), /unavailable/u);
  } finally {
    if (digest !== undefined) {
      await retireKeychainAuthenticationKey(service, account, digest).catch(() => undefined);
    }
  }
});

test("approval issuer key lifecycle requires durable revocation before retirement", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-approval-key-"));
  const path = join(directory, "operator.key");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const provisioned = await provisionAuthenticationKey(path);
    const loaded = await loadApprovalIssuerKey(path, "operator-1", "operator-key-1", 1, 2, false);
    assert.equal(loaded.key.byteLength, 32);
    await assert.rejects(
      retireRevokedApprovalIssuerKey(path, provisioned.digest, "operator-1", "operator-key-1", store),
      /must be revoked/u
    );
    store.revoke("approval_key", "operator-1:operator-key-1", "ROTATED");
    await retireRevokedApprovalIssuerKey(path, provisioned.digest, "operator-1", "operator-key-1", store);
    await assert.rejects(lstat(path), /ENOENT/u);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
