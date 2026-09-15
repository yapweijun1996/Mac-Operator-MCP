import assert from "node:assert/strict";
import { mkdtemp, readdir, rename, rm, stat, utimes } from "node:fs/promises";
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
    const quarantine = `${manifest.path}.unlink-${"a".repeat(24)}`;
    await rename(manifest.path, quarantine);
    const stale = new Date(Date.now() - 2 * 60 * 60 * 1_000);
    await utimes(quarantine, stale, stale);

    const result = await store.pruneBackups(directory, 2);

    assert.equal(result.removed.includes(quarantine), true);
    await assert.rejects(stat(quarantine), { code: "ENOENT" });
    assert.equal((await readdir(directory)).some((name) => name.includes(".unlink-")), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
