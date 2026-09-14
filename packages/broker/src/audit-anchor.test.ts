import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AuditAnchorManager } from "./audit-anchor.js";

const key = Buffer.from("audit-anchor-test-key-0123456789abcdef", "ascii");
const firstHash = "a".repeat(64);
const secondHash = "b".repeat(64);

test("AuditAnchorManager publishes and verifies a keyed monotonic tail", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-anchor-"));
  const path = join(directory, "audit.anchor");
  const manager = new AuditAnchorManager({
    path,
    keySource: { keyId: "audit-key-1", loadKey: () => key }
  });
  try {
    manager.verify(undefined);
    manager.publish(1, firstHash);
    manager.publish(2, secondHash);
    manager.publish(1, firstHash);
    manager.verify({ sequence: 2, eventHash: secondHash });
    assert.match((await readFile(path, "utf8")), /audit-key-1/u);
  } finally {
    manager.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("AuditAnchorManager rejects a forged sidecar even when the SQLite tail is unchanged", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-anchor-tamper-"));
  const path = join(directory, "audit.anchor");
  const manager = new AuditAnchorManager({
    path,
    keySource: { keyId: "audit-key-1", loadKey: () => key }
  });
  try {
    manager.publish(1, firstHash);
    const forged = JSON.parse(await readFile(path, "utf8")) as { mac: string };
    forged.mac = "0".repeat(64);
    await writeFile(path, `${JSON.stringify(forged)}\n`, { mode: 0o600 });
    await chmod(path, 0o600);
    assert.throws(
      () => manager.verify({ sequence: 1, eventHash: firstHash }),
      /does not match/u
    );
  } finally {
    manager.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("AuditAnchorManager refuses a missing anchor for non-empty audit state", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-anchor-missing-"));
  const manager = new AuditAnchorManager({
    path: join(directory, "audit.anchor"),
    keySource: { keyId: "audit-key-1", loadKey: () => key }
  });
  try {
    assert.throws(
      () => manager.verify({ sequence: 1, eventHash: firstHash }),
      /anchor is missing/u
    );
  } finally {
    manager.close();
    await rm(directory, { recursive: true, force: true });
  }
});
