import assert from "node:assert/strict";
import { chmod, lstat, mkdtemp, readFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  AuthorityControlKeyManager,
  loadAuthorityControlKeyConfig,
  writeAuthorityControlKeyConfig,
  type AuthorityControlKeyConfig
} from "./authority-control-keyring.js";
import { AuthorityControlIpcServer } from "./authority-control-ipc.js";
import { loadAuthenticationKey, provisionAuthenticationKey } from "./credentials.js";
import { createAuthorityControlUninstallActionsFromKeyManager } from "./macos-uninstall-plan.js";
import { BrokerStore } from "./persistence.js";

const NOW = 1_700_000_000_000;

function document(keyPath: string, keyDigest: string, revision = 1): AuthorityControlKeyConfig {
  return {
    schemaVersion: "0.1",
    revision,
    keys: [{
      keyId: `authority-key-${revision}`,
      keySource: "file",
      path: keyPath,
      keyDigest,
      notBeforeMs: NOW - 1_000,
      expiresAtMs: NOW + 60_000
    }]
  };
}

test("authority control key config is protected, digest-bound, and restart-restorable", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-authority-keyring-"));
  const configPath = join(directory, "authority-keys.json");
  const firstKeyPath = join(directory, "authority.key");
  const secondKeyPath = join(directory, "authority-next.key");
  const databasePath = join(directory, "broker.sqlite");
  let store = new BrokerStore(databasePath);
  try {
    const firstDigest = (await provisionAuthenticationKey(firstKeyPath)).digest;
    const firstKey = await loadAuthenticationKey(firstKeyPath);
    const first = document(firstKeyPath, firstDigest);
    const digest = await writeAuthorityControlKeyConfig(configPath, first);
    assert.equal((await lstat(configPath)).mode & 0o777, 0o600);
    assert.doesNotMatch(await readFile(configPath, "utf8"), new RegExp(firstKey.toString("hex"), "u"));
    const loaded = await loadAuthorityControlKeyConfig(configPath, store);
    assert.equal(loaded.payloadDigest, digest);
    assert.equal(loaded.key.key.toString("hex"), firstKey.toString("hex"));

    const manager = new AuthorityControlKeyManager(configPath, store, () => NOW);
    await assert.rejects(manager.restore(), /does not match persisted activation/u);
    const activated = await manager.activate();
    assert.equal(activated.document.revision, 1);
    assert.equal(store.activeAuthorityKeyConfigIdentity()?.revision, 1);
    assert.equal(manager.current().key.key.toString("hex"), firstKey.toString("hex"));

    store.close();
    store = new BrokerStore(databasePath);
    const restarted = new AuthorityControlKeyManager(configPath, store, () => NOW + 1_000);
    assert.equal((await restarted.restore()).payloadDigest, activated.payloadDigest);

    const secondDigest = (await provisionAuthenticationKey(secondKeyPath)).digest;
    await writeAuthorityControlKeyConfig(configPath, document(secondKeyPath, secondDigest, 2));
    await restarted.activate(1);
    assert.equal(restarted.current().document.revision, 2);
    await writeAuthorityControlKeyConfig(configPath, first);
    await assert.rejects(restarted.activate(), /revision must increase/u);
    assert.equal(store.activeAuthorityKeyConfigIdentity()?.revision, 2);
    const activationAudits = store.auditRows().filter((row) => row.tool === "internal_authority_key_config_activate");
    assert.equal(activationAudits.filter((row) => row.event_type === "intent").length, 2);
    assert.equal(activationAudits.filter((row) => row.event_type === "completion").length, 2);
    restarted.dispose();
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("authority control key config rejects unsafe, revoked, and ambiguous sources", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-authority-keyring-deny-"));
  const configPath = join(directory, "authority-keys.json");
  const linkPath = join(directory, "authority-keys-link.json");
  const keyPath = join(directory, "authority.key");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const digest = (await provisionAuthenticationKey(keyPath)).digest;
    const valid = document(keyPath, digest);
    await writeAuthorityControlKeyConfig(configPath, valid);
    await symlink(configPath, linkPath);
    await assert.rejects(loadAuthorityControlKeyConfig(linkPath, store), /non-symlink/u);
    await assert.rejects(
      writeAuthorityControlKeyConfig(configPath, {
        ...valid,
        keys: [valid.keys[0]!, valid.keys[0]!]
      } as unknown as AuthorityControlKeyConfig),
      /malformed/u
    );
    store.revoke("authority_key", "authority-key-1", "COMPROMISED", NOW);
    await assert.rejects(loadAuthorityControlKeyConfig(configPath, store), /is revoked/u);
    await chmod(configPath, 0o640);
    await assert.rejects(loadAuthorityControlKeyConfig(configPath, store), /not be accessible/u);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("activated authority key manager assembles the real uninstall IPC client", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-authority-assembly-"));
  const configPath = join(directory, "authority-keys.json");
  const keyPath = join(directory, "authority.key");
  const socketPath = join(directory, "authority.sock");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = await provisionAuthenticationKey(keyPath);
  const authenticationKey = await loadAuthenticationKey(keyPath);
  const manager = new AuthorityControlKeyManager(configPath, store, () => NOW);
  const server = new AuthorityControlIpcServer({
    socketPath,
    store,
    authenticationKey,
    peerCredentialVerifier: { verify() { return undefined; } },
    now: () => NOW
  });
  try {
    await writeAuthorityControlKeyConfig(configPath, document(keyPath, key.digest));
    await manager.activate();
    await server.listen();
    const actions = createAuthorityControlUninstallActionsFromKeyManager(
      manager,
      { socketPath, now: () => NOW },
      "edge-1"
    );
    await actions.disableGlobal();
    await actions.revokeEdge("edge-1");
    assert.deepEqual(await actions.authorityReadback(), { globalDisabled: true, edgeRevoked: true });
  } finally {
    await server.close().catch(() => undefined);
    manager.dispose();
    authenticationKey.fill(0);
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
