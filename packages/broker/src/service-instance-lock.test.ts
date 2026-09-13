import assert from "node:assert/strict";
import { chmod, lstat, mkdtemp, realpath, readFile, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
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

test("service instance lock rejects a real non-cooperating owner and reclaims only after exit", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("native PID/start-time observation is a macOS boundary");
    return;
  }
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-instance-lock-process-"));
  const path = join(await realpath(directory), "broker.instance.lock");
  const modulePath = fileURLToPath(new URL("./service-instance-lock.js", import.meta.url));
  const childScript = `import { BrokerServiceInstanceLock } from ${JSON.stringify(modulePath)};\nconst lock = await BrokerServiceInstanceLock.acquire(process.argv[1]);\nprocess.stdout.write("ready\\n");\nsetInterval(() => {}, 1_000);`;
  const child = spawn(process.execPath, ["--input-type=module", "-e", childScript, path], {
    cwd: dirname(modulePath),
    stdio: ["ignore", "pipe", "pipe"]
  });
  child.stdout.setEncoding("utf8");
  let childOutput = "";
  let childError = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => { childError += chunk; });
  const waitForChildExit = (): Promise<void> => new Promise((resolve, reject) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve();
      return;
    }
    const timer = setTimeout(() => reject(new Error("lock owner did not exit")), 5_000);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
  });
  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`lock owner did not start: ${childError}`)), 5_000);
      child.stdout.on("data", (chunk: string) => {
        childOutput += chunk;
        if (childOutput.includes("ready\n")) {
          clearTimeout(timer);
          resolve();
        }
      });
      child.once("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.once("exit", (code, signal) => {
        if (!childOutput.includes("ready\n")) {
          clearTimeout(timer);
          reject(new Error(`lock owner exited before readiness: ${code ?? signal}: ${childError}`));
        }
      });
    });
    await assert.rejects(
      BrokerServiceInstanceLock.acquire(path),
      (error: unknown) => error instanceof ServiceInstanceLockError && error.code === "ALREADY_ACTIVE"
    );
    child.kill("SIGTERM");
    await waitForChildExit();
    const reclaimed = await BrokerServiceInstanceLock.acquire(path);
    await reclaimed.close();
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    await waitForChildExit().catch(() => undefined);
    await rm(directory, { recursive: true, force: true });
  }
});
