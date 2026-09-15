import assert from "node:assert/strict";
import { renameSync, writeFileSync } from "node:fs";
import { chmod, mkdtemp, open, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { captureProcessPathIdentity, detectProcessIdentityReplacement, ProcessSupervisor } from "./process-supervisor.js";

const CWD = process.cwd();

test("process supervisor rejects invalid per-executable capacity", () => {
  assert.throws(() => new ProcessSupervisor({ maxConcurrentPerExecutable: 0 }), /limits are outside/u);
  assert.throws(() => new ProcessSupervisor({ maxConcurrentPerExecutable: 65 }), /limits are outside/u);
});

test("process supervisor rejects non-data request shapes before spawning", async () => {
  const supervisor = new ProcessSupervisor({ allowedEnvironmentKeys: ["SAFE_PROFILE"] });
  const base = {
    executable: "/usr/bin/printf",
    args: ["ok"],
    cwd: CWD,
    environment: { SAFE_PROFILE: "test" },
    timeoutMs: 1_000,
    outputCapBytes: 100
  };
  await assert.rejects(supervisor.run(Object.create(base)), /limits or paths are invalid/u);
  const accessor = { ...base } as Record<string, unknown>;
  Object.defineProperty(accessor, "executable", { enumerable: true, get: () => "/usr/bin/printf" });
  await assert.rejects(supervisor.run(accessor as never), /limits or paths are invalid/u);
  const symbolic = { ...base } as Record<string, unknown>;
  Object.defineProperty(symbolic, Symbol("hidden"), { value: "authority" });
  await assert.rejects(supervisor.run(symbolic as never), /limits or paths are invalid/u);
  await assert.rejects(supervisor.run({ ...base, extra: true } as never), /limits or paths are invalid/u);
  const sparseArgs = new Array<string>(1);
  await assert.rejects(supervisor.run({ ...base, args: sparseArgs } as never), /limits or paths are invalid/u);
  await assert.rejects(
    supervisor.run({ ...base, environment: Object.create({ SAFE_PROFILE: "inherited" }) } as never),
    /environment is malformed/u
  );
  await assert.rejects(supervisor.run({ ...base, shouldCancel: true } as never), /callbacks are malformed/u);
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor snapshots caller request before asynchronous target checks", async () => {
  const supervisor = new ProcessSupervisor({ allowedEnvironmentKeys: ["SAFE_PROFILE"] });
  const request = {
    executable: "/usr/bin/printf",
    args: ["before"],
    cwd: CWD,
    environment: { SAFE_PROFILE: "before" },
    timeoutMs: 1_000,
    outputCapBytes: 100
  };
  const execution = supervisor.run(request);
  request.executable = "/usr/bin/false";
  request.args[0] = "mutated";
  request.cwd = "/";
  request.environment = { SAFE_PROFILE: "mutated" };
  const result = await execution;
  assert.equal(result.state, "completed");
  assert.equal(result.stdout, "before");
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor rejects descendant PID identity replacement", () => {
  const tracked = [{ pid: 42, startTimeMicros: 100 }];
  assert.equal(detectProcessIdentityReplacement(tracked, [{ pid: 42, startTimeMicros: 100 }]), false);
  assert.equal(detectProcessIdentityReplacement(tracked, [{ pid: 42, startTimeMicros: 101 }]), true);
  assert.equal(detectProcessIdentityReplacement(tracked, [{ pid: 43, startTimeMicros: 101 }]), false);
});

test("process supervisor uses an explicit environment and bounded output", async () => {
  const supervisor = new ProcessSupervisor({ allowedEnvironmentKeys: ["SAFE_PROFILE"] });
  const result = await supervisor.run({
    executable: "/usr/bin/python3",
    args: ["-c", "import os; print(os.getenv('MOP_CONTROLLER_SECRET', 'unset'))"],
    cwd: CWD,
    environment: { SAFE_PROFILE: "test" },
    timeoutMs: 10_000,
    outputCapBytes: 1_024
  });
  assert.equal(result.state, "completed");
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(result.stdout.trim(), "unset");
  assert.equal(result.stderr, "");
  assert.equal(result.terminationObserved, true);
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor delivers bounded stdin without exposing it in argv", async () => {
  const supervisor = new ProcessSupervisor();
  const result = await supervisor.run({
    executable: "/usr/bin/python3",
    args: ["-c", "import sys; print(sys.stdin.read(), end='')"],
    stdin: "opaque-input",
    cwd: CWD,
    timeoutMs: 2_000,
    outputCapBytes: 1_024
  });
  assert.equal(result.state, "completed");
  assert.equal(result.stdout, "opaque-input");
  assert.equal(supervisor.activeCount(), 0);
  await assert.rejects(supervisor.run({
    executable: "/usr/bin/printf",
    args: ["ok"],
    stdin: "x".repeat(65_537),
    cwd: CWD,
    timeoutMs: 1_000,
    outputCapBytes: 100
  }), /stdin exceeds/u);
});

test("process supervisor captures output from a child that exits during startup checks", async () => {
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  try {
    for (let index = 0; index < 8; index += 1) {
      const result = await supervisor.run({
        executable: "/usr/bin/printf",
        args: ["startup-race"],
        cwd: CWD,
        timeoutMs: 1_000,
        outputCapBytes: 100
      });
      assert.equal(result.state, "completed");
      assert.equal(result.stdout, "startup-race");
    }
    assert.equal(supervisor.activeCount(), 0);
  } finally {
    await supervisor.close();
  }
});

test("process supervisor requires a final native descendant readback for strict task exits", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Strict task exit proof uses the macOS native process observer");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  const result = await supervisor.run({
    executable: "/usr/bin/python3",
    args: ["-c", "import time; print('strict-exit', flush=True); time.sleep(0.5)"],
    cwd: CWD,
    timeoutMs: 1_000,
    outputCapBytes: 100,
    requireCleanExitProof: true
  });
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(result.terminationObserved, true);
  assert.equal(result.stdout, "strict-exit\n");
  assert.equal(supervisor.activeCount(), 0);
});

test("strict task exit proof keeps a late descendant unresolved", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Strict task exit proof uses the macOS native process observer");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 25, terminationGraceMs: 50 });
  const result = await supervisor.run({
    executable: "/usr/bin/python3",
    args: ["-c", "import os,time; child=os.fork(); time.sleep(0.15) if child == 0 else os._exit(0)"],
    cwd: CWD,
    timeoutMs: 2_000,
    outputCapBytes: 100,
    requireCleanExitProof: true
  });
  assert.equal(result.resultClass, "UNKNOWN_OUTCOME");
  assert.equal(result.terminationObserved, false);
  await supervisor.close();
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor does not leak a parent file-descriptor canary", async (t) => {
  if (process.platform === "win32") {
    t.skip("The Broker target platform uses POSIX descriptor semantics");
    return;
  }
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-process-fd-"));
  const canaryPath = join(directory, "controller-secret-canary");
  await writeFile(canaryPath, "synthetic-canary\n", { mode: 0o600 });
  const canary = await open(canaryPath, "r");
  try {
    const canaryStat = await canary.stat();
    const supervisor = new ProcessSupervisor();
    const result = await supervisor.run({
      executable: "/usr/bin/python3",
      args: [
        "-c",
        "import os,sys; fd='/dev/fd/'+sys.argv[1]; print('leaked' if os.path.exists(fd) and (lambda s: s.st_dev == int(sys.argv[2]) and s.st_ino == int(sys.argv[3]))(os.stat(fd)) else 'not-leaked')",
        String(canary.fd),
        String(canaryStat.dev),
        String(canaryStat.ino)
      ],
      cwd: CWD,
      timeoutMs: 2_000,
      outputCapBytes: 1_024
    });
    assert.equal(result.state, "completed");
    assert.equal(result.stdout.trim(), "not-leaked");
  } finally {
    await canary.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("process supervisor rejects secret-shaped or non-allowlisted environment keys", async () => {
  const supervisor = new ProcessSupervisor({ allowedEnvironmentKeys: ["SAFE_PROFILE"] });
  await assert.rejects(
    supervisor.run({
      executable: "/usr/bin/printf",
      args: ["ok"],
      cwd: CWD,
      environment: { SAFE_PROFILE: "test", MOP_CONTROLLER_SECRET: "must-not-cross" },
      timeoutMs: 1_000,
      outputCapBytes: 100
    }),
    /environment key is not safe/u
  );
  await assert.rejects(
    supervisor.run({
      executable: "/usr/bin/printf",
      args: ["ok"],
      cwd: CWD,
      environment: { NODE_OPTIONS: "--require=/tmp/untrusted.js" },
      timeoutMs: 1_000,
      outputCapBytes: 100
    }),
    /environment key is not safe/u
  );
  await assert.rejects(
    supervisor.run({
      executable: "/usr/bin/printf",
      args: ["ok"],
      cwd: CWD,
      environment: { OTHER_PROFILE: "not-allowlisted" },
      timeoutMs: 1_000,
      outputCapBytes: 100
    }),
    /not profile-allowlisted/u
  );
  await assert.rejects(
    supervisor.run({
      executable: "/usr/bin/printf",
      args: ["ok"],
      cwd: CWD,
      environment: { SAFE_PROFILE: 42 as unknown as string },
      timeoutMs: 1_000,
      outputCapBytes: 100
    }),
    /environment value is invalid/u
  );
  const oversizedEnvironment = Object.fromEntries(
    Array.from({ length: 65 }, (_, index) => [`SAFE_${index}`, "x"])
  );
  const largeEnvironmentSupervisor = new ProcessSupervisor({ allowedEnvironmentKeys: Object.keys(oversizedEnvironment) });
  await assert.rejects(
    largeEnvironmentSupervisor.run({
      executable: "/usr/bin/printf",
      args: ["ok"],
      cwd: CWD,
      environment: oversizedEnvironment,
      timeoutMs: 1_000,
      outputCapBytes: 100
    }),
    /environment exceeds the supported size/u
  );
  await assert.rejects(
    supervisor.run({
      executable: "/usr/bin/printf",
      args: ["--token", "value"],
      cwd: CWD,
      timeoutMs: 1_000,
      outputCapBytes: 100
    }),
    /protected secret option/u
  );
  await assert.rejects(
    supervisor.run({
      executable: "/usr/bin/printf",
      args: ["ok"],
      cwd: CWD,
      environment: { SAFE_PROFILE: "Bearer opaque-token-value-123456" },
      timeoutMs: 1_000,
      outputCapBytes: 100
    }),
    /environment value matched a protected secret signature/u
  );
});

test("process supervisor rejects symlink executables and non-canonical cwd", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-process-path-"));
  const executableLink = join(directory, "printf-link");
  try {
    await symlink("/usr/bin/printf", executableLink);
    const supervisor = new ProcessSupervisor();
    await assert.rejects(
      supervisor.run({
        executable: executableLink,
        args: ["no"],
        cwd: CWD,
        timeoutMs: 1_000,
        outputCapBytes: 100
      }),
      /Executable symlinks are not allowed/u
    );
    await assert.rejects(
      supervisor.run({
        executable: "/usr/bin/printf",
        args: ["no"],
        cwd: `${CWD}/..`,
        timeoutMs: 1_000,
        outputCapBytes: 100
      }),
      /invalid/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("process supervisor rejects group- or other-writable executables", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-process-permissions-"));
  const executable = join(await realpath(directory), "runner");
  try {
    await writeFile(executable, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    await chmod(executable, 0o720);
    const supervisor = new ProcessSupervisor();
    await assert.rejects(
      supervisor.run({
        executable,
        args: [],
        cwd: CWD,
        timeoutMs: 1_000,
        outputCapBytes: 100
      }),
      /permissions are not owner-only/u
    );
    assert.equal(supervisor.activeCount(), 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("process supervisor can require root-owned executables for fixed adapters", async () => {
  const supervisor = new ProcessSupervisor({ requireRootOwnedExecutable: true });
  const trusted = await supervisor.run({
    executable: "/usr/bin/printf",
    args: ["root-owned"],
    cwd: CWD,
    timeoutMs: 1_000,
    outputCapBytes: 100
  });
  assert.equal(trusted.state, "completed");
  assert.equal(trusted.stdout, "root-owned");

  const uid = process.getuid?.();
  if (uid === 0) return;
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-process-owner-"));
  const executable = join(await realpath(directory), "runner");
  try {
    await writeFile(executable, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    await assert.rejects(
      supervisor.run({
        executable,
        args: [],
        cwd: CWD,
        timeoutMs: 1_000,
        outputCapBytes: 100
      }),
      /not root-owned/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("process supervisor rejects executable target swaps after startup authorization", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("The startup identity callback uses the macOS native process observer");
    return;
  }
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-process-swap-"));
  const canonicalDirectory = await realpath(directory);
  const executable = join(canonicalDirectory, "runner");
  const movedExecutable = join(canonicalDirectory, "runner-authorized");
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  try {
    await writeFile(executable, "#!/bin/sh\nsleep 1\n", { mode: 0o700 });
    await assert.rejects(
      supervisor.run({
        executable,
        args: [],
        cwd: canonicalDirectory,
        timeoutMs: 2_000,
        outputCapBytes: 100,
        onStarted: () => {
          renameSync(executable, movedExecutable);
          writeFileSync(executable, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
        }
      }),
      /Executable changed after authorization/u
    );
    assert.equal(supervisor.activeCount(), 0);
  } finally {
    await supervisor.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("process supervisor rejects in-place executable mutations after startup authorization", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("The startup identity callback uses the macOS native process observer");
    return;
  }
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-process-content-swap-"));
  const canonicalDirectory = await realpath(directory);
  const executable = join(canonicalDirectory, "runner");
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  try {
    await writeFile(executable, "#!/bin/sh\nsleep 1\n", { mode: 0o700 });
    await assert.rejects(
      supervisor.run({
        executable,
        args: [],
        cwd: canonicalDirectory,
        timeoutMs: 2_000,
        outputCapBytes: 100,
        onStarted: () => {
          // Preserve the path and inode while changing its content and stat metadata.
          writeFileSync(executable, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
        }
      }),
      /Executable changed after authorization/u
    );
    assert.equal(supervisor.activeCount(), 0);
  } finally {
    await supervisor.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("process supervisor captures a cryptographic executable content identity", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-process-content-digest-"));
  const executable = join(await realpath(directory), "runner");
  try {
    await writeFile(executable, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    const first = await captureProcessPathIdentity(executable, "executable");
    await writeFile(executable, "#!/bin/sh\nexit 1\n", { mode: 0o700 });
    const second = await captureProcessPathIdentity(executable, "executable");
    assert.match(first.contentSha256 ?? "", /^[a-f0-9]{64}$/u);
    assert.match(second.contentSha256 ?? "", /^[a-f0-9]{64}$/u);
    assert.notEqual(first.contentSha256, second.contentSha256);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("process supervisor terminates the process group on timeout and output overflow", async () => {
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  const timedOut = await supervisor.run({
    executable: "/bin/sleep",
    args: ["5"],
    cwd: CWD,
    timeoutMs: 30,
    outputCapBytes: 100
  });
  assert.equal(timedOut.state, "timed_out");
  assert.equal(timedOut.resultClass, "TIMEOUT");
  assert.equal(timedOut.terminationObserved, true);

  const outputLimited = await supervisor.run({
    executable: "/usr/bin/python3",
    args: ["-c", "print('x' * 10_000)"],
    cwd: CWD,
    timeoutMs: 2_000,
    outputCapBytes: 128
  });
  assert.equal(outputLimited.state, "failed");
  assert.equal(outputLimited.resultClass, "OUTPUT_LIMIT");
  assert.equal(outputLimited.truncated, true);
  assert.ok(Buffer.byteLength(outputLimited.stdout) <= 128);
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor attributes an unexpected signal exit as execution failure", async () => {
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  const result = await supervisor.run({
    executable: "/usr/bin/python3",
    args: ["-c", "import os; os.kill(os.getpid(), 9)"],
    cwd: CWD,
    timeoutMs: 2_000,
    outputCapBytes: 100
  });
  assert.equal(result.state, "failed");
  assert.equal(result.resultClass, "EXECUTION_FAILED");
  assert.equal(result.exitCode, null);
  assert.equal(result.signal, "SIGKILL");
  assert.equal(result.terminationObserved, true);
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor terminates a tracked detached descendant", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Detached descendant identity tracking is a macOS native boundary");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  const startedAt = Date.now();
  const result = await supervisor.run({
    executable: "/usr/bin/python3",
    args: [
      "-c",
      "import os,time; pid=os.fork();\nif pid==0:\n os.setsid(); print(os.getpid(), flush=True); time.sleep(5)\nelse:\n time.sleep(1)"
    ],
    cwd: CWD,
    timeoutMs: 200,
    outputCapBytes: 1_024
  });
  assert.equal(result.state, "timed_out");
  assert.equal(result.resultClass, "TIMEOUT");
  assert.equal(result.terminationObserved, true);
  const descendantPid = Number.parseInt(result.stdout, 10);
  assert.ok(Number.isSafeInteger(descendantPid) && descendantPid > 0);
  assert.ok(Date.now() - startedAt < 2_000, "detached descendant must not hold the supervisor for its full lifetime");
  await assertProcessGone(descendantPid);
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor cancellation kills descendants and releases capacity", async () => {
  const supervisor = new ProcessSupervisor({ maxConcurrent: 1, pollIntervalMs: 5, terminationGraceMs: 50 });
  let cancelled = false;
  const running = supervisor.run({
    executable: "/bin/bash",
    args: ["-c", "/bin/sleep 10 & printf '%s' \"$!\"; wait"],
    cwd: CWD,
    timeoutMs: 5_000,
    outputCapBytes: 1_024,
    shouldCancel: () => cancelled
  });
  await new Promise((resolve) => setTimeout(resolve, 30));
  cancelled = true;
  const result = await running;
  assert.equal(result.state, "cancelled");
  assert.equal(result.resultClass, "CANCELLED");
  assert.equal(result.terminationObserved, true);
  const descendantPid = Number.parseInt(result.stdout, 10);
  assert.ok(Number.isSafeInteger(descendantPid) && descendantPid > 0);
  await assertProcessGone(descendantPid);
  assert.equal(supervisor.activeCount(), 0);

  const second = await supervisor.run({
    executable: "/usr/bin/printf",
    args: ["capacity-released"],
    cwd: CWD,
    timeoutMs: 15_000,
    outputCapBytes: 100
  });
  assert.equal(second.stdout, "capacity-released");
});

test("process supervisor close drains owned processes and rejects new work", async () => {
  const supervisor = new ProcessSupervisor({ maxConcurrent: 1, pollIntervalMs: 5, terminationGraceMs: 50 });
  const running = supervisor.run({
    executable: "/bin/sleep",
    args: ["10"],
    cwd: CWD,
    timeoutMs: 5_000,
    outputCapBytes: 100
  });
  await waitForActiveProcess(supervisor, 1, 2_000);
  const closePromise = supervisor.close();
  await assert.rejects(
    supervisor.run({
      executable: "/usr/bin/printf",
      args: ["closed"],
      cwd: CWD,
      timeoutMs: 1_000,
      outputCapBytes: 100
    }),
    /authority is closed/u
  );
  const result = await running;
  await closePromise;
  assert.equal(result.state, "cancelled");
  assert.equal(result.resultClass, "CANCELLED");
  assert.equal(result.terminationObserved, true);
  assert.equal(supervisor.activeCount(), 0);
  assert.strictEqual(supervisor.close(), closePromise);
});

test("process supervisor close waits for a startup that is proving ownership", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Startup ownership persistence uses the macOS native process observer");
    return;
  }
  const supervisor = new ProcessSupervisor({ maxConcurrent: 1, pollIntervalMs: 5, terminationGraceMs: 50 });
  let closePromise: Promise<void> | undefined;
  let closeResolved = false;
  const starting = supervisor.run({
    executable: "/bin/sleep",
    args: ["10"],
    cwd: CWD,
    timeoutMs: 5_000,
    outputCapBytes: 100,
    onStarted: () => {
      closePromise = supervisor.close();
      void closePromise.then(() => { closeResolved = true; });
    }
  });
  await assert.rejects(starting, (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED");
  assert.ok(closePromise);
  await closePromise;
  assert.equal(closeResolved, true);
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor does not retain a synchronously aborted ownership run", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Synchronous ownership sampling uses the macOS native process observer");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  const running = supervisor.run({
    executable: "/bin/sleep",
    args: ["5"],
    cwd: CWD,
    timeoutMs: 2_000,
    outputCapBytes: 100,
    onOwnershipChanged: () => { throw new Error("ownership persistence failed"); }
  });
  const result = await running;
  assert.equal(result.resultClass, "UNKNOWN_OUTCOME");
  assert.equal(supervisor.activeCount(), 0);
  const closePromise = supervisor.close();
  await closePromise;
  assert.strictEqual(supervisor.close(), closePromise);
});

test("process supervisor drains a child when startup ownership persistence fails", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Startup ownership persistence uses the macOS native process observer");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  let snapshot: import("./process-supervisor.js").ProcessOwnershipSnapshot | undefined;
  await assert.rejects(
    supervisor.run({
      executable: "/bin/sleep",
      args: ["10"],
      cwd: CWD,
      timeoutMs: 2_000,
      outputCapBytes: 100,
      onStarted: async (value) => {
        snapshot = value;
        await new Promise((resolve) => setTimeout(resolve, 5));
        throw new Error("startup ownership persistence failed");
      }
    }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
  );
  assert.ok(snapshot);
  await assertProcessGone(snapshot!.identity.pid);
  assert.equal(supervisor.activeCount(), 0);
  await supervisor.close();
});

test("process supervisor aborts a child when authority closes during startup", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Startup authority binding uses the macOS native process observer");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  let snapshot: import("./process-supervisor.js").ProcessOwnershipSnapshot | undefined;
  let closePromise: Promise<void> | undefined;
  await assert.rejects(
    supervisor.run({
      executable: "/bin/sleep",
      args: ["10"],
      cwd: CWD,
      timeoutMs: 2_000,
      outputCapBytes: 100,
      onStarted: (value) => {
        snapshot = value;
        closePromise = supervisor.close();
      }
    }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
  );
  assert.ok(snapshot);
  await assertProcessGone(snapshot!.identity.pid);
  await closePromise;
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor captures and recovers an exact persisted root identity", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Persisted root identity recovery is a macOS native boundary");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  let snapshot: import("./process-supervisor.js").ProcessOwnershipSnapshot | undefined;
  let resolveSnapshot!: () => void;
  const snapshotReady = new Promise<void>((resolve) => { resolveSnapshot = resolve; });
  const running = supervisor.run({
    executable: "/bin/sleep",
    args: ["10"],
    cwd: CWD,
    timeoutMs: 5_000,
    outputCapBytes: 100,
    onStarted: (value) => { snapshot = value; resolveSnapshot(); }
  });
  await Promise.race([
    snapshotReady,
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error("root ownership snapshot timeout")), 2_000))
  ]);
  assert.ok(snapshot);
  const recovered = await supervisor.recoverOwnedProcess(snapshot!.identity, 1_000);
  assert.equal(recovered.outcome, "drained");
  assert.equal(recovered.terminationObserved, true);
  await running;
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor refuses a swapped persisted root identity", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Persisted root identity recovery is a macOS native boundary");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  let snapshot: import("./process-supervisor.js").ProcessOwnershipSnapshot | undefined;
  let resolveSnapshot!: () => void;
  const snapshotReady = new Promise<void>((resolve) => { resolveSnapshot = resolve; });
  const running = supervisor.run({
    executable: "/bin/sleep",
    args: ["10"],
    cwd: CWD,
    timeoutMs: 5_000,
    outputCapBytes: 100,
    onStarted: (value) => { snapshot = value; resolveSnapshot(); }
  });
  await Promise.race([
    snapshotReady,
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error("root ownership snapshot timeout")), 2_000))
  ]);
  assert.ok(snapshot);
  const swapped = await supervisor.recoverOwnedProcess({ ...snapshot!.identity, startTimeMicros: snapshot!.identity.startTimeMicros + 1 }, 250);
  assert.equal(swapped.outcome, "identity_mismatch");
  assert.equal(swapped.terminationObserved, false);
  await supervisor.close();
  await assert.rejects(
    running,
    (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
  );
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor rejects non-data persisted ownership snapshots", async () => {
  const supervisor = new ProcessSupervisor();
  const identity = { pid: 1, processGroupId: 1, startTimeMicros: 1 };
  const accessor: Record<string, unknown> = {};
  Object.defineProperty(accessor, "pid", { enumerable: true, get: () => 1 });
  await assert.rejects(
    supervisor.recoverOwnedProcess(accessor as never, 250),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
  await assert.rejects(
    supervisor.recoverOwnedProcess({ identity, descendants: [], extra: true } as never, 250),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
  await assert.rejects(
    supervisor.recoverOwnedProcess({ identity: { ...identity, extra: true }, descendants: [] } as never, 250),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
});

test("process supervisor keeps an empty snapshot unresolved after root exit", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Persisted process recovery is a macOS native boundary");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  let snapshot: import("./process-supervisor.js").ProcessOwnershipSnapshot | undefined;
  let resolveSnapshot!: () => void;
  const snapshotReady = new Promise<void>((resolve) => { resolveSnapshot = resolve; });
  const running = supervisor.run({
    executable: "/bin/sleep",
    args: ["10"],
    cwd: CWD,
    timeoutMs: 5_000,
    outputCapBytes: 100,
    onStarted: (value) => { snapshot = value; resolveSnapshot(); }
  });
  try {
    await Promise.race([
      snapshotReady,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("root ownership snapshot timeout")), 2_000))
    ]);
    assert.ok(snapshot);
    assert.deepEqual(snapshot!.descendants, []);
    process.kill(snapshot!.identity.pid, "SIGKILL");
    await running;
    const recovered = await supervisor.recoverOwnedProcess(snapshot!, 250);
    assert.equal(recovered.outcome, "unknown");
    assert.equal(recovered.terminationObserved, false);
  } finally {
    await running;
    await supervisor.close();
  }
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor proves absence for a validated no-fork snapshot", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("No-fork absence proof uses the macOS native process observer");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  let snapshot: import("./process-supervisor.js").ProcessOwnershipSnapshot | undefined;
  let resolveSnapshot!: () => void;
  const snapshotReady = new Promise<void>((resolve) => { resolveSnapshot = resolve; });
  const running = supervisor.run({
    executable: "/bin/sleep",
    args: ["10"],
    cwd: CWD,
    timeoutMs: 5_000,
    outputCapBytes: 100,
    onStarted: (value) => { snapshot = value; resolveSnapshot(); }
  });
  try {
    await Promise.race([
      snapshotReady,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("root ownership snapshot timeout")), 2_000))
    ]);
    assert.ok(snapshot);
    assert.deepEqual(snapshot!.descendants, []);
    process.kill(snapshot!.identity.pid, "SIGKILL");
    await running;
    const recovered = await supervisor.recoverOwnedProcess({
      ...snapshot!,
      ownershipProof: "sandbox-exec-no-fork-v1"
    }, 250);
    assert.equal(recovered.outcome, "absent");
    assert.equal(recovered.terminationObserved, true);
  } finally {
    await running;
    await supervisor.close();
  }
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor recovers a persisted detached descendant after root exit", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Persisted descendant recovery is a macOS native boundary");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 25, terminationGraceMs: 50 });
  let snapshot: import("./process-supervisor.js").ProcessOwnershipSnapshot | undefined;
  let resolveDescendant!: () => void;
  const descendantReady = new Promise<void>((resolve) => { resolveDescendant = resolve; });
  const running = supervisor.run({
    executable: "/usr/bin/python3",
    args: ["-c", "import os,time; child=os.fork(); (os.setsid(), time.sleep(30)) if child == 0 else time.sleep(30)"],
    cwd: CWD,
    timeoutMs: 35_000,
    outputCapBytes: 100,
    onStarted: (value) => { snapshot = value; },
    onOwnershipChanged: (value) => {
      snapshot = value;
      if (value.descendants.length > 0) resolveDescendant();
    }
  });
  try {
    await Promise.race([
      descendantReady,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("descendant snapshot timeout")), 5_000))
    ]);
    assert.ok(snapshot);
    assert.ok(snapshot!.descendants.length > 0);
    process.kill(snapshot!.identity.pid, "SIGKILL");
    const recovered = await supervisor.recoverOwnedProcess(snapshot!, 5_000);
    assert.equal(recovered.outcome, "drained");
    assert.equal(recovered.terminationObserved, true);
  } finally {
    await running;
    await supervisor.close();
  }
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor keeps a dead root unresolved after persisted descendants disappear", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Persisted descendant absence is a macOS native boundary");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 25, terminationGraceMs: 50 });
  let snapshot: import("./process-supervisor.js").ProcessOwnershipSnapshot | undefined;
  let resolveDescendant!: () => void;
  const descendantReady = new Promise<void>((resolve) => { resolveDescendant = resolve; });
  const running = supervisor.run({
    executable: "/usr/bin/python3",
    args: ["-c", "import os,time; child=os.fork(); (time.sleep(0.05), os._exit(0)) if child == 0 else (os.waitpid(child, 0), time.sleep(30))"],
    cwd: CWD,
    timeoutMs: 35_000,
    outputCapBytes: 100,
    onStarted: (value) => { snapshot = value; },
    onOwnershipChanged: (value) => {
      snapshot = value;
      if (value.descendants.length > 0) resolveDescendant();
    }
  });
  try {
    await Promise.race([
      descendantReady,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("descendant snapshot timeout")), 5_000))
    ]);
    assert.ok(snapshot);
    assert.ok(snapshot!.descendants.length > 0);
    // Let the observed child exit while the persisted root remains alive.
    await new Promise((resolve) => setTimeout(resolve, 250));
    process.kill(snapshot!.identity.pid, "SIGKILL");
    await running;
    const recovered = await supervisor.recoverOwnedProcess(snapshot!, 250);
    assert.equal(recovered.outcome, "unknown");
    assert.equal(recovered.terminationObserved, false);
  } finally {
    await running;
    await supervisor.close();
  }
  assert.equal(supervisor.activeCount(), 0);
});

async function assertProcessGone(pid: number): Promise<void> {
  const deadline = Date.now() + 1_000;
  while (Date.now() < deadline) {
    try {
      process.kill(pid, 0);
    } catch {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.throws(() => process.kill(pid, 0));
}

async function waitForActiveProcess(supervisor: ProcessSupervisor, expected: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (supervisor.activeCount() >= expected) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("Process supervisor did not admit the expected active run");
}

test("process supervisor enforces concurrent process capacity", async () => {
  const supervisor = new ProcessSupervisor({ maxConcurrent: 1, pollIntervalMs: 5, terminationGraceMs: 50 });
  let cancelled = false;
  const first = supervisor.run({
    executable: "/bin/sleep",
    args: ["2"],
    cwd: CWD,
    timeoutMs: 5_000,
    outputCapBytes: 100,
    shouldCancel: () => cancelled
  });
  await new Promise((resolve) => setTimeout(resolve, 20));
  await assert.rejects(
    supervisor.run({
      executable: "/usr/bin/printf",
      args: ["blocked"],
      cwd: CWD,
      timeoutMs: 1_000,
      outputCapBytes: 100
    }),
    /capacity is exhausted/u
  );
  cancelled = true;
  const result = await first;
  assert.equal(result.state, "cancelled");
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor isolates per-executable capacity from the global pool", async () => {
  const supervisor = new ProcessSupervisor({ maxConcurrent: 2, maxConcurrentPerExecutable: 1, pollIntervalMs: 5, terminationGraceMs: 50 });
  let cancelled = false;
  const first = supervisor.run({
    executable: "/bin/sleep",
    args: ["2"],
    cwd: CWD,
    timeoutMs: 5_000,
    outputCapBytes: 100,
    shouldCancel: () => cancelled
  });
  try {
    await waitForActiveProcess(supervisor, 1, 5_000);
    await assert.rejects(
      supervisor.run({
        executable: "/bin/sleep",
        args: ["1"],
        cwd: CWD,
        timeoutMs: 5_000,
        outputCapBytes: 100
      }),
      /capacity is exhausted/u
    );
    const other = await supervisor.run({
      executable: "/usr/bin/printf",
      args: ["other"],
      cwd: CWD,
      timeoutMs: 5_000,
      outputCapBytes: 100
    });
    assert.equal(other.state, "completed");
    assert.equal(other.stdout, "other");
  } finally {
    cancelled = true;
    await first;
    await supervisor.close();
  }
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor counts concurrent starts for one executable", async () => {
  const supervisor = new ProcessSupervisor({ maxConcurrent: 4, maxConcurrentPerExecutable: 4, pollIntervalMs: 5, terminationGraceMs: 50 });
  let cancelled = false;
  const runs = Array.from({ length: 4 }, () => supervisor.run({
    executable: "/bin/sleep",
    args: ["2"],
    cwd: CWD,
    timeoutMs: 5_000,
    outputCapBytes: 100,
    shouldCancel: () => cancelled
  }));
  try {
    await waitForActiveProcess(supervisor, 4, 1_000);
    await assert.rejects(
      supervisor.run({
        executable: "/bin/sleep",
        args: ["1"],
        cwd: CWD,
        timeoutMs: 1_000,
        outputCapBytes: 100
      }),
      /capacity is exhausted/u
    );
  } finally {
    cancelled = true;
    await Promise.all(runs);
    await supervisor.close();
  }
  assert.equal(supervisor.activeCount(), 0);
});
