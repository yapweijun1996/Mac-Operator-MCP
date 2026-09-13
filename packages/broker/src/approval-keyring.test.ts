import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { chmod, lstat, mkdtemp, readFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  ApprovalIssuerKeyManager,
  loadApprovalIssuerKeyConfig,
  writeApprovalIssuerKeyConfig,
  type ApprovalIssuerKeyConfig
} from "./approval-keyring.js";
import { loadAuthenticationKey, provisionAuthenticationKey } from "./credentials.js";
import { BrokerStore } from "./persistence.js";

const NOW = 1_700_000_000_000;

test("approval issuer key config is owner-only, versioned, atomic, and reloadable", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-approval-keyring-"));
  const configPath = join(directory, "approval-keys.json");
  const keyPath = join(directory, "operator.key");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    await provisionAuthenticationKey(keyPath);
    const provisionedKey = await loadAuthenticationKey(keyPath);
    const document: ApprovalIssuerKeyConfig = {
      schemaVersion: "0.1",
      revision: 1,
      keys: [{
        issuerId: "operator-1",
        keyId: "operator-key-1",
        path: keyPath,
        notBeforeMs: NOW - 1_000,
        expiresAtMs: NOW + 60_000,
        allowUnattended: false
      }]
    };
    const digest = await writeApprovalIssuerKeyConfig(configPath, document);
    assert.equal((await lstat(configPath)).mode & 0o777, 0o600);
    const raw = await readFile(configPath, "utf8");
    assert.match(raw, /"schemaVersion":"0.1"/u);
    assert.doesNotMatch(raw, new RegExp(provisionedKey.toString("hex"), "u"));
    const loaded = await loadApprovalIssuerKeyConfig(configPath, store);
    assert.equal(loaded.payloadDigest, digest);
    assert.equal(loaded.document.revision, 1);
    assert.equal(loaded.keys[0]?.key.toString("hex"), provisionedKey.toString("hex"));

    await provisionAuthenticationKey(join(directory, "operator-next.key"));
    const rotatedKey = await loadAuthenticationKey(join(directory, "operator-next.key"));
    const nextDocument: ApprovalIssuerKeyConfig = {
      ...document,
      revision: 2,
      keys: [...document.keys, {
        issuerId: "operator-1",
        keyId: "operator-key-2",
        path: join(directory, "operator-next.key"),
        notBeforeMs: NOW + 1_000,
        expiresAtMs: NOW + 120_000,
        allowUnattended: false
      }]
    };
    const nextDigest = await writeApprovalIssuerKeyConfig(configPath, nextDocument);
    const reloaded = await loadApprovalIssuerKeyConfig(configPath, store);
    assert.notEqual(nextDigest, digest);
    assert.equal(reloaded.document.revision, 2);
    assert.equal(reloaded.keys.length, 2);
    assert.equal(reloaded.keys[1]?.key.toString("hex"), rotatedKey.toString("hex"));
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("approval issuer key config rejects symlink, duplicate, and revoked entries", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-approval-keyring-deny-"));
  const configPath = join(directory, "approval-keys.json");
  const linkPath = join(directory, "approval-keys-link.json");
  const keyPath = join(directory, "operator.key");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    await provisionAuthenticationKey(keyPath);
    const entry = {
      issuerId: "operator-1",
      keyId: "operator-key-1",
      path: keyPath,
      notBeforeMs: NOW - 1_000,
      expiresAtMs: NOW + 60_000,
      allowUnattended: false
    } as const;
    await assert.rejects(
      writeApprovalIssuerKeyConfig(configPath, { schemaVersion: "0.1", revision: 1, keys: [entry, entry] }),
      /Duplicate approval issuer key/u
    );
    await writeApprovalIssuerKeyConfig(configPath, { schemaVersion: "0.1", revision: 1, keys: [entry] });
    await symlink(configPath, linkPath);
    await assert.rejects(loadApprovalIssuerKeyConfig(linkPath, store), /non-symlink/u);
    store.revoke("approval_key", "operator-1:operator-key-1", "COMPROMISED", NOW);
    await assert.rejects(loadApprovalIssuerKeyConfig(configPath, store), /is revoked/u);
    await chmod(configPath, 0o640);
    await assert.rejects(loadApprovalIssuerKeyConfig(configPath, store), /not be accessible/u);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("approval issuer key config rejects unsafe replacement targets", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-approval-keyring-target-"));
  const configPath = join(directory, "approval-keys.json");
  const keyPath = join(directory, "operator.key");
  try {
    await provisionAuthenticationKey(keyPath);
    const document: ApprovalIssuerKeyConfig = {
      schemaVersion: "0.1", revision: 1, keys: [{
        issuerId: "operator-1", keyId: "operator-key-1", path: keyPath,
        notBeforeMs: NOW - 1_000, expiresAtMs: NOW + 60_000, allowUnattended: false
      }]
    };
    await symlink(keyPath, configPath);
    await assert.rejects(writeApprovalIssuerKeyConfig(configPath, document), /Existing approval issuer key config is not protected/u);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("approval issuer key config requires an explicit Keychain source shape", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-approval-keyring-keychain-"));
  const configPath = join(directory, "approval-keys.json");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const account = `approval:missing:${randomUUID()}`;
  try {
    const document: ApprovalIssuerKeyConfig = {
      schemaVersion: "0.1",
      revision: 1,
      keys: [{
        issuerId: "operator-1",
        keyId: "operator-key-1",
        keySource: "keychain",
        service: "com.mac-operator.test",
        account,
        notBeforeMs: NOW - 1_000,
        expiresAtMs: NOW + 60_000,
        allowUnattended: false
      }]
    };
    await writeApprovalIssuerKeyConfig(configPath, document);
    await assert.rejects(loadApprovalIssuerKeyConfig(configPath, store), /Keychain generic password is unavailable/u);
    await assert.rejects(
      writeApprovalIssuerKeyConfig(configPath, {
        ...document,
        keys: [{ ...document.keys[0]!, keySource: "keychain", path: join(directory, "forbidden.key") }]
      }),
      /Approval issuer key config entry is malformed/u
    );
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("approval issuer key manager persists monotonic activation and exact restart restore", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-approval-keyring-manager-"));
  const configPath = join(directory, "approval-keys.json");
  const firstKeyPath = join(directory, "operator.key");
  const secondKeyPath = join(directory, "operator-next.key");
  const databasePath = join(directory, "broker.sqlite");
  let store = new BrokerStore(databasePath);
  try {
    await provisionAuthenticationKey(firstKeyPath);
    const first: ApprovalIssuerKeyConfig = {
      schemaVersion: "0.1", revision: 1, keys: [{
        issuerId: "operator-1", keyId: "operator-key-1", path: firstKeyPath,
        notBeforeMs: NOW - 1_000, expiresAtMs: NOW + 60_000, allowUnattended: false
      }]
    };
    await writeApprovalIssuerKeyConfig(configPath, first);
    const manager = new ApprovalIssuerKeyManager(configPath, store, () => NOW);
    await assert.rejects(manager.restore(), /does not match persisted activation/u);
    const activated = await manager.activate();
    assert.equal(activated.document.revision, 1);
    assert.equal(store.activeApprovalKeyConfigIdentity()?.revision, 1);

    store.close();
    store = new BrokerStore(databasePath);
    const restartedManager = new ApprovalIssuerKeyManager(configPath, store, () => NOW + 1_000);
    assert.equal((await restartedManager.restore()).payloadDigest, activated.payloadDigest);

    await provisionAuthenticationKey(secondKeyPath);
    const second: ApprovalIssuerKeyConfig = {
      ...first,
      revision: 2,
      keys: [...first.keys, {
        issuerId: "operator-1", keyId: "operator-key-2", path: secondKeyPath,
        notBeforeMs: NOW + 1_000, expiresAtMs: NOW + 120_000, allowUnattended: false
      }]
    };
    await writeApprovalIssuerKeyConfig(configPath, second);
    await restartedManager.activate(1);
    assert.equal(store.activeApprovalKeyConfigIdentity()?.revision, 2);

    await writeApprovalIssuerKeyConfig(configPath, first);
    await assert.rejects(restartedManager.activate(), /revision must increase/u);
    assert.equal(store.activeApprovalKeyConfigIdentity()?.revision, 2);
    await writeApprovalIssuerKeyConfig(configPath, second);
    await restartedManager.restore();
    const activationAudits = store.auditRows().filter((row) => row.tool === "internal_approval_key_config_activate");
    assert.equal(activationAudits.length, 4);
    assert.equal(activationAudits.filter((row) => row.event_type === "intent").length, 2);
    assert.equal(activationAudits.filter((row) => row.event_type === "completion").length, 2);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
