import assert from "node:assert/strict";
import { chmod, lstat, mkdtemp, realpath, readFile, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerServiceInstanceLock, ServiceInstanceLockError } from "./service-instance-lock.js";

const identity = { pid: 12_345, startTimeMicros: 678_901 };

test("service instance lock admits one owner and rejects an active duplicate", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-instance-lock-"));
  const path = join(await realpath(directory), "broker.instance.lock");
  let lock: BrokerServiceInstanceLock | undefined;
  try {
    lock = await BrokerServiceInstanceLock.acquire(path, { identity, probe: () => "active" });
    const document = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
    assert.deepEqual(document, { schemaVersion: "0.1", pid: identity.pid, startTimeMicros: identity.startTimeMicros });
    await assert.rejects(
      BrokerServiceInstanceLock.acquire(path, { identity: { pid: 22_222, startTimeMicros: 888_999 }, probe: () => "active" }),
      (error: unknown) => error instanceof ServiceInstanceLockError && error.code === "ALREADY_ACTIVE"
    );
  } finally {
    await lock?.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("service instance lock reclaims only a proven stale owner", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-instance-lock-stale-"));
  const path = join(await realpath(directory), "broker.instance.lock");
  const stale = { pid: 33_333, startTimeMicros: 111_222 };
  let lock: BrokerServiceInstanceLock | undefined;
  try {
    await writeFile(path, `${JSON.stringify({ schemaVersion: "0.1", ...stale })}\n`, { mode: 0o600 });
    lock = await BrokerServiceInstanceLock.acquire(path, {
      identity,
      probe: (observed) => observed.pid === stale.pid ? "stale" : "active"
    });
    assert.equal((await lstat(path)).isFile(), true);
    assert.deepEqual(JSON.parse(await readFile(path, "utf8")), { schemaVersion: "0.1", ...identity });
  } finally {
    await lock?.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("service instance lock fails closed on observer uncertainty and unsafe targets", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-instance-lock-unsafe-"));
  const canonicalDirectory = await realpath(directory);
  const path = join(canonicalDirectory, "broker.instance.lock");
  const target = join(canonicalDirectory, "target");
  try {
    await writeFile(path, `${JSON.stringify({ schemaVersion: "0.1", ...identity })}\n`, { mode: 0o600 });
    await assert.rejects(
      BrokerServiceInstanceLock.acquire(path, { identity, probe: () => "unknown" }),
      (error: unknown) => error instanceof ServiceInstanceLockError && error.code === "OWNER_UNVERIFIED"
    );
    await unlink(path);
    await writeFile(target, "not a lock\n", { mode: 0o600 });
    await symlink(target, path);
    await assert.rejects(
      BrokerServiceInstanceLock.acquire(path, { identity, probe: () => "stale" }),
      (error: unknown) => error instanceof ServiceInstanceLockError && error.code === "LOCK_INVALID"
    );
  } finally {
    await chmod(directory, 0o700);
    await rm(directory, { recursive: true, force: true });
  }
});

test("service instance lock refuses to remove a replacement lock on close", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-instance-lock-replacement-"));
  const path = join(await realpath(directory), "broker.instance.lock");
  let lock: BrokerServiceInstanceLock | undefined;
  try {
    lock = await BrokerServiceInstanceLock.acquire(path, { identity, probe: () => "active" });
    await unlink(path);
    await writeFile(path, `${JSON.stringify({ schemaVersion: "0.1", pid: 44_444, startTimeMicros: 555_666 })}\n`, { mode: 0o600 });
    await assert.rejects(lock.close(), (error: unknown) => error instanceof ServiceInstanceLockError && error.code === "LOCK_CHANGED");
    assert.equal((await lstat(path)).isFile(), true);
    lock = undefined;
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
