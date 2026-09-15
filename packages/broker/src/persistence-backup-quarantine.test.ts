import assert from "node:assert/strict";
import { mkdtemp, readdir, rename, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerStore } from "./persistence.js";

test("Broker backup pruning completes a stale deletion quarantine", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-backup-quarantine-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const manifest = await store.backupTo(directory, {
      keySource: { keyId: "backup-test-1", loadKey: () => Buffer.from("0123456789abcdef0123456789abcdef", "ascii") },
      nowMs: 1_700_000_000_000,
      retainCount: 2
    });
    const quarantine = `${manifest.path}.unlink-${Date.now() - 2 * 60 * 60 * 1_000}-${"a".repeat(24)}`;
    await rename(manifest.path, quarantine);

    const result = await store.pruneBackups(directory, 2);

    assert.equal(result.removed.includes(quarantine), true);
    await assert.rejects(stat(quarantine), { code: "ENOENT" });
    assert.equal((await readdir(directory)).some((name) => name.includes(".unlink-")), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Broker backup pruning leaves a recent deletion quarantine untouched", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-backup-quarantine-recent-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const manifest = await store.backupTo(directory, {
      keySource: { keyId: "backup-test-1", loadKey: () => Buffer.from("0123456789abcdef0123456789abcdef", "ascii") },
      nowMs: 1_700_000_000_001,
      retainCount: 2
    });
    const quarantine = `${manifest.path}.unlink-${Date.now()}-${"b".repeat(24)}`;
    await rename(manifest.path, quarantine);

    const result = await store.pruneBackups(directory, 2);

    assert.equal(result.removed.includes(quarantine), false);
    assert.equal((await stat(quarantine)).isFile(), true);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Broker backup pruning rejects an invalid quarantine timestamp", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-backup-quarantine-invalid-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const manifest = await store.backupTo(directory, {
      keySource: { keyId: "backup-test-1", loadKey: () => Buffer.from("0123456789abcdef0123456789abcdef", "ascii") },
      nowMs: 1_700_000_000_002,
      retainCount: 2
    });
    const quarantine = `${manifest.path}.unlink-${"9".repeat(16)}-${"c".repeat(24)}`;
    await rename(manifest.path, quarantine);

    await assert.rejects(store.pruneBackups(directory, 2), /quarantine timestamp is invalid/u);
    assert.equal((await stat(quarantine)).isFile(), true);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
