import assert from "node:assert/strict";
import { chmod, lstat, mkdtemp, readFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  PrivilegedHelperKeyManager,
  loadPrivilegedHelperKeyConfig,
  writePrivilegedHelperKeyConfig,
  type PrivilegedHelperKeyConfig
} from "./privileged-helper-keyring.js";
import { FailClosedPrivilegedHelper, InMemoryPrivilegedHelperReplayGuard, readPrivilegedHelperStatus } from "./privileged-helper.js";
import { loadAuthenticationKey, provisionAuthenticationKey } from "./credentials.js";
import { BrokerStore } from "./persistence.js";

const NOW = 1_700_000_000_000;

function document(keyPath: string, keyDigest: string, revision = 1): PrivilegedHelperKeyConfig {
  return {
    schemaVersion: "0.1",
    revision,
    keys: [{
      keyId: `helper-key-${revision}`,
      keySource: "file",
      path: keyPath,
      keyDigest,
      notBeforeMs: NOW - 1_000,
      expiresAtMs: NOW + 60_000
    }]
  };
}

test("privileged helper key config is protected, digest-bound, and restart-restorable", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-helper-keyring-"));
  const configPath = join(directory, "helper-keys.json");
  const firstKeyPath = join(directory, "helper.key");
  const secondKeyPath = join(directory, "helper-next.key");
  const databasePath = join(directory, "broker.sqlite");
  let store = new BrokerStore(databasePath);
  let manager: PrivilegedHelperKeyManager | undefined;
  try {
    const firstDigest = (await provisionAuthenticationKey(firstKeyPath)).digest;
    const firstKey = await loadAuthenticationKey(firstKeyPath);
    const first = document(firstKeyPath, firstDigest);
    const digest = await writePrivilegedHelperKeyConfig(configPath, first);
    assert.equal((await lstat(configPath)).mode & 0o777, 0o600);
    assert.doesNotMatch(await readFile(configPath, "utf8"), new RegExp(firstKey.toString("hex"), "u"));
    const loaded = await loadPrivilegedHelperKeyConfig(configPath, store);
    assert.equal(loaded.payloadDigest, digest);
    assert.equal(loaded.key.key.toString("hex"), firstKey.toString("hex"));

    manager = new PrivilegedHelperKeyManager(configPath, store, () => NOW);
    await assert.rejects(manager.restore(), /does not match persisted activation/u);
    const activated = await manager.activate();
    assert.equal(activated.document.revision, 1);
    assert.equal(store.activeHelperKeyConfigIdentity()?.revision, 1);
    assert.equal(manager.assertUsable().toString("hex"), firstKey.toString("hex"));
    const factory = manager.createCommandFactory({
      store,
      authorizeCommand: () => undefined
    });
    const server = manager.createServer({
      socketPath: join(directory, "helper.sock"),
      replayGuard: { admit: () => undefined },
      adapter: new FailClosedPrivilegedHelper(),
      authorizeCommand: () => undefined,
      peerCredentialVerifier: { verify() { return undefined; } }
    });
    await server.close();
    factory.dispose();

    store.close();
    store = new BrokerStore(databasePath);
    manager.dispose();
    let helperNow = NOW + 1_000;
    manager = new PrivilegedHelperKeyManager(configPath, store, () => helperNow);
    assert.equal((await manager.restore()).payloadDigest, activated.payloadDigest);
    const secondDigest = (await provisionAuthenticationKey(secondKeyPath)).digest;
    await writePrivilegedHelperKeyConfig(configPath, document(secondKeyPath, secondDigest, 2));
    await manager.activate(1);
    assert.equal(manager.current().document.revision, 2);
    const expiringFactory = manager.createCommandFactory({ store, authorizeCommand: () => undefined });
    helperNow = NOW + 60_001;
    assert.throws(
      () => expiringFactory.issue({ requestId: "request:test", principalId: "principal-1", sessionId: "session-1", jobId: "job:test" }),
      (error: unknown) => error instanceof Error && "errorClass" in error && (error as { errorClass: string }).errorClass === "AUTH_EXPIRED"
    );
    expiringFactory.dispose();
    helperNow = NOW + 1_000;
    const revokedFactory = manager.createCommandFactory({ store, authorizeCommand: () => undefined });
    store.revoke("helper_key", "helper-key-2", "COMPROMISED", NOW);
    assert.throws(
      () => revokedFactory.issue({ requestId: "request:test", principalId: "principal-1", sessionId: "session-1", jobId: "job:test" }),
      (error: unknown) => error instanceof Error && "errorClass" in error && (error as { errorClass: string }).errorClass === "REVOKED"
    );
    revokedFactory.dispose();
    await writePrivilegedHelperKeyConfig(configPath, first);
    await assert.rejects(manager.activate(), /revision must increase/u);
    const audits = store.auditRows().filter((row) => row.tool === "internal_helper_key_config_activate");
    assert.equal(audits.filter((row) => row.event_type === "intent").length, 2);
    assert.equal(audits.filter((row) => row.event_type === "completion").length, 2);
  } finally {
    manager?.dispose();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("privileged helper key config rejects symlink, unsafe mode, and revocation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-helper-keyring-deny-"));
  const configPath = join(directory, "helper-keys.json");
  const linkPath = join(directory, "helper-keys-link.json");
  const keyPath = join(directory, "helper.key");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const digest = (await provisionAuthenticationKey(keyPath)).digest;
    const valid = document(keyPath, digest);
    await writePrivilegedHelperKeyConfig(configPath, valid);
    await symlink(configPath, linkPath);
    await assert.rejects(loadPrivilegedHelperKeyConfig(linkPath, store), /non-symlink/u);
    store.revoke("helper_key", "helper-key-1", "COMPROMISED", NOW);
    await assert.rejects(loadPrivilegedHelperKeyConfig(configPath, store), /is revoked/u);
    await chmod(configPath, 0o640);
    await assert.rejects(loadPrivilegedHelperKeyConfig(configPath, store), /not be accessible/u);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("constructed helper server fences status reads after key revocation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-helper-keyring-status-"));
  const configPath = join(directory, "helper-keys.json");
  const keyPath = join(directory, "helper.key");
  const socketPath = join(directory, "helper.sock");
  const brokerSocketPath = join(directory, "broker.sock");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  let manager: PrivilegedHelperKeyManager | undefined;
  try {
    const provisioned = await provisionAuthenticationKey(keyPath);
    const key = await loadAuthenticationKey(keyPath);
    await writePrivilegedHelperKeyConfig(configPath, document(keyPath, provisioned.digest));
    manager = new PrivilegedHelperKeyManager(configPath, store, () => NOW);
    await manager.activate();
    const server = manager.createServer({
      socketPath,
      replayGuard: new InMemoryPrivilegedHelperReplayGuard(),
      adapter: new FailClosedPrivilegedHelper(),
      authorizeCommand: () => undefined,
      authorizeStatus: () => undefined,
      readStatus: () => ({
        component: "mac-operator-privileged-helper" as const,
        state: "running" as const,
        runtimeState: "running" as const,
        nativeTransportRequired: true as const,
        adapterAvailable: false as const,
        helperSocketPath: socketPath,
        brokerSocketPath,
        helperAuthoritySocketPath: `${directory}/helper-authority.sock`,
        brokerPeerUid: 501,
        brokerPeerGid: 20,
        sourceRevision: "a".repeat(40),
        contractVersion: "0.1",
        policyVersion: "policy-0.1",
        enabledCapabilities: [] as const
      }),
      peerCredentialVerifier: { verify: () => undefined },
      now: () => NOW
    });
    try {
      await server.listen();
      const status = await readPrivilegedHelperStatus({ socketPath, authenticationKey: key, now: () => NOW });
      assert.equal(status.runtimeState, "running");
      store.revoke("helper_key", "helper-key-1", "COMPROMISED", NOW);
      await assert.rejects(
        readPrivilegedHelperStatus({ socketPath, authenticationKey: key, now: () => NOW }),
        (error: unknown) => error instanceof Error && "errorClass" in error && (error as { errorClass: string }).errorClass === "REVOKED"
      );
    } finally {
      await server.close();
    }
    key.fill(0);
  } finally {
    manager?.dispose();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
