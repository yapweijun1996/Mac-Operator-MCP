import assert from "node:assert/strict";
import { chmod, lstat, mkdtemp, readFile, realpath, rm, stat, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AuditAnchorManager, recoverAuditAnchorLock } from "./audit-anchor.js";

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

test("AuditAnchorManager rejects unknown sidecar authority fields", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-anchor-shape-"));
  const path = join(directory, "audit.anchor");
  const manager = new AuditAnchorManager({
    path,
    keySource: { keyId: "audit-key-1", loadKey: () => key }
  });
  try {
    manager.publish(1, firstHash);
    const forged = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
    forged.extra = "authority";
    await writeFile(path, `${JSON.stringify(forged)}\n`, { mode: 0o600 });
    await chmod(path, 0o600);
    assert.throws(
      () => manager.verify({ sequence: 1, eventHash: firstHash }),
      /anchor is malformed/u
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

test("AuditAnchorManager fails closed when another process holds the sidecar lock", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-anchor-lock-"));
  const path = join(directory, "audit.anchor");
  const manager = new AuditAnchorManager({
    path,
    keySource: { keyId: "audit-key-1", loadKey: () => key }
  });
  const lockPath = `${path}.lock`;
  try {
    await writeFile(lockPath, "foreign-owner\n", { mode: 0o600 });
    assert.throws(
      () => manager.publish(1, firstHash),
      /lock is held/u
    );
    await unlink(lockPath);
    manager.publish(1, firstHash);
    manager.verify({ sequence: 1, eventHash: firstHash });
  } finally {
    manager.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("stopped-service audit anchor recovery removes only the exact lock identity", {
  skip: process.platform !== "darwin"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-anchor-recovery-"));
  const path = join(await realpath(directory), "audit.anchor");
  const lockPath = `${path}.lock`;
  let stoppedReadbackCalls = 0;
  try {
    await writeFile(lockPath, "stopped-service-recovery\n", { mode: 0o600 });
    const identity = await stat(lockPath);
    const recovered = recoverAuditAnchorLock({
      path,
      expectedLockDevice: identity.dev,
      expectedLockInode: identity.ino,
      assertServiceStopped: () => { stoppedReadbackCalls += 1; }
    });
    assert.deepEqual(recovered, {
      path,
      lockPath,
      removed: true,
      device: identity.dev,
      inode: identity.ino
    });
    assert.equal(stoppedReadbackCalls, 1);
    await assertRejectsMissing(lockPath);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("stopped-service audit anchor recovery refuses a replacement lock", {
  skip: process.platform !== "darwin"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-anchor-recovery-swap-"));
  const path = join(await realpath(directory), "audit.anchor");
  const lockPath = `${path}.lock`;
  try {
    await writeFile(lockPath, "first\n", { mode: 0o600 });
    const first = await stat(lockPath);
    await unlink(lockPath);
    await writeFile(lockPath, "replacement\n", { mode: 0o600 });
    await assert.rejects(
      async () => recoverAuditAnchorLock({
        path,
        expectedLockDevice: first.dev,
        expectedLockInode: first.ino,
        assertServiceStopped: () => undefined
      }),
      /identity precondition/u
    );
    assert.equal((await lstat(lockPath)).isFile(), true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("stopped-service audit anchor recovery requires the host stop gate", {
  skip: process.platform !== "darwin"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-anchor-recovery-gate-"));
  const path = join(await realpath(directory), "audit.anchor");
  const lockPath = `${path}.lock`;
  try {
    await writeFile(lockPath, "running-service\n", { mode: 0o600 });
    const identity = await stat(lockPath);
    assert.throws(
      () => recoverAuditAnchorLock({
        path,
        expectedLockDevice: identity.dev,
        expectedLockInode: identity.ino,
        assertServiceStopped: () => { throw new Error("service is still running"); }
      }),
      /service is still running/u
    );
    assert.equal((await lstat(lockPath)).isFile(), true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

async function assertRejectsMissing(path: string): Promise<void> {
  await assert.rejects(() => lstat(path), (error: unknown) => (error as NodeJS.ErrnoException).code === "ENOENT");
}
