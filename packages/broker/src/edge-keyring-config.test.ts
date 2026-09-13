import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { chmod, lstat, mkdtemp, readFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  loadEdgeAuthenticationKeyConfig,
  writeEdgeAuthenticationKeyConfig,
  type EdgeAuthenticationKeyConfig
} from "./edge-keyring-config.js";
import { loadAuthenticationKey, provisionAuthenticationKey } from "./credentials.js";
import { BrokerStore } from "./persistence.js";

const NOW = 1_700_000_000_000;

test("Edge key config binds explicit file sources and supports overlapping rotation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-edge-keyring-"));
  const configPath = join(directory, "edge-keys.json");
  const oldPath = join(directory, "edge-old.key");
  const nextPath = join(directory, "edge-next.key");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    await provisionAuthenticationKey(oldPath);
    await provisionAuthenticationKey(nextPath);
    const oldKey = await loadAuthenticationKey(oldPath);
    const nextKey = await loadAuthenticationKey(nextPath);
    const first: EdgeAuthenticationKeyConfig = {
      schemaVersion: "0.1",
      revision: 1,
      keys: [{
        edgeId: "edge-1",
        keyId: "edge-key-old",
        keySource: "file",
        path: oldPath,
        notBeforeMs: NOW - 60_000,
        expiresAtMs: NOW + 60_000
      }]
    };
    const digest = await writeEdgeAuthenticationKeyConfig(configPath, first);
    assert.equal((await lstat(configPath)).mode & 0o777, 0o600);
    const raw = await readFile(configPath, "utf8");
    assert.doesNotMatch(raw, new RegExp(oldKey.toString("hex"), "u"));
    const loaded = await loadEdgeAuthenticationKeyConfig(configPath, store);
    assert.equal(loaded.payloadDigest, digest);
    assert.equal(loaded.keyring.keyByIdentity("edge-1", "edge-key-old")?.toString("hex"), oldKey.toString("hex"));

    const rotated: EdgeAuthenticationKeyConfig = {
      ...first,
      revision: 2,
      keys: [
        ...first.keys,
        {
          edgeId: "edge-1",
          keyId: "edge-key-next",
          keySource: "file",
          path: nextPath,
          notBeforeMs: NOW,
          expiresAtMs: NOW + 120_000
        }
      ]
    };
    const rotatedDigest = await writeEdgeAuthenticationKeyConfig(configPath, rotated);
    const reloaded = await loadEdgeAuthenticationKeyConfig(configPath, store);
    assert.notEqual(rotatedDigest, digest);
    assert.equal(reloaded.document.revision, 2);
    assert.equal(reloaded.keys.length, 2);
    assert.equal(reloaded.keyring.keyByIdentity("edge-1", "edge-key-next")?.toString("hex"), nextKey.toString("hex"));
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Edge key config rejects revoked, symlinked, and unsafe entries", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-edge-keyring-deny-"));
  const configPath = join(directory, "edge-keys.json");
  const linkPath = join(directory, "edge-keys-link.json");
  const keyPath = join(directory, "edge.key");
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  try {
    await provisionAuthenticationKey(keyPath);
    const entry = {
      edgeId: "edge-1",
      keyId: "edge-key-1",
      keySource: "file" as const,
      path: keyPath,
      notBeforeMs: NOW - 1_000,
      expiresAtMs: NOW + 60_000
    };
    await writeEdgeAuthenticationKeyConfig(configPath, { schemaVersion: "0.1", revision: 1, keys: [entry] });
    await symlink(configPath, linkPath);
    await assert.rejects(loadEdgeAuthenticationKeyConfig(linkPath, store), /non-symlink/u);
    store.revoke("edge_key", "edge-1:edge-key-1", "COMPROMISED", NOW);
    await assert.rejects(loadEdgeAuthenticationKeyConfig(configPath, store), /is revoked/u);
    await chmod(configPath, 0o640);
    await assert.rejects(loadEdgeAuthenticationKeyConfig(configPath, store), /not be accessible/u);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Edge key config requires an explicit source and rejects Keychain/file mixing", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-edge-keyring-keychain-"));
  const configPath = join(directory, "edge-keys.json");
  const account = `edge:missing:${randomUUID()}`;
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const document: EdgeAuthenticationKeyConfig = {
      schemaVersion: "0.1",
      revision: 1,
      keys: [{
        edgeId: "edge-1",
        keyId: "edge-key-1",
        keySource: "keychain",
        service: "com.mac-operator.test",
        account,
        notBeforeMs: NOW - 1_000,
        expiresAtMs: NOW + 60_000
      }]
    };
    await writeEdgeAuthenticationKeyConfig(configPath, document);
    await assert.rejects(loadEdgeAuthenticationKeyConfig(configPath, store), /Keychain generic password is unavailable/u);
    await assert.rejects(
      writeEdgeAuthenticationKeyConfig(configPath, {
        ...document,
        keys: [{ ...document.keys[0]!, keySource: "keychain", path: join(directory, "forbidden.key") }]
      }),
      /Edge authentication key config entry is malformed/u
    );
    await assert.rejects(
      writeEdgeAuthenticationKeyConfig(configPath, {
        ...document,
        keys: [{ ...document.keys[0]!, keySource: undefined as never }]
      }),
      /Edge authentication key config entry is malformed/u
    );
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
