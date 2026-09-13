import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { chmod, lstat, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  loadAuthenticationKey,
  loadApprovalIssuerKey,
  loadKeychainAuthenticationKey,
  provisionAuthenticationKey,
  provisionKeychainAuthenticationKey,
  retireRevokedApprovalIssuerKey,
  retireRevokedAuthenticationKey
} from "./credentials.js";
import { BrokerStore } from "./persistence.js";

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
    provisionKeychainAuthenticationKey("/tmp/attacker", `edge:invalid:${randomUUID()}`),
    /Keychain service or account is invalid/u
  );
  await assert.rejects(
    provisionKeychainAuthenticationKey("com.mac-operator.test", `../escape`),
    /Keychain service or account is invalid/u
  );
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
