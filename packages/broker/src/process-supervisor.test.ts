import assert from "node:assert/strict";
import { mkdtemp, open, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ProcessSupervisor } from "./process-supervisor.js";

const CWD = process.cwd();

test("process supervisor uses an explicit environment and bounded output", async () => {
  const supervisor = new ProcessSupervisor({ allowedEnvironmentKeys: ["SAFE_PROFILE"] });
  const result = await supervisor.run({
    executable: "/usr/bin/python3",
    args: ["-c", "import os; print(os.getenv('MOP_CONTROLLER_SECRET', 'unset'))"],
    cwd: CWD,
    environment: { SAFE_PROFILE: "test" },
    timeoutMs: 2_000,
    outputCapBytes: 1_024
  });
  assert.equal(result.state, "completed");
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(result.stdout.trim(), "unset");
  assert.equal(result.stderr, "");
  assert.equal(result.terminationObserved, true);
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
    timeoutMs: 1_000,
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
  await new Promise((resolve) => setTimeout(resolve, 20));
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

test("process supervisor captures and recovers an exact persisted root identity", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Persisted root identity recovery is a macOS native boundary");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  let snapshot: import("./process-supervisor.js").ProcessOwnershipSnapshot | undefined;
  const running = supervisor.run({
    executable: "/bin/sleep",
    args: ["10"],
    cwd: CWD,
    timeoutMs: 5_000,
    outputCapBytes: 100,
    onStarted: (value) => { snapshot = value; }
  });
  await new Promise((resolve) => setTimeout(resolve, 20));
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
  const running = supervisor.run({
    executable: "/bin/sleep",
    args: ["10"],
    cwd: CWD,
    timeoutMs: 5_000,
    outputCapBytes: 100,
    onStarted: (value) => { snapshot = value; }
  });
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.ok(snapshot);
  const swapped = await supervisor.recoverOwnedProcess({ ...snapshot!.identity, startTimeMicros: snapshot!.identity.startTimeMicros + 1 }, 250);
  assert.equal(swapped.outcome, "identity_mismatch");
  assert.equal(swapped.terminationObserved, false);
  await supervisor.close();
  await running;
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor keeps an empty snapshot unresolved after root exit", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Persisted process recovery is a macOS native boundary");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  let snapshot: import("./process-supervisor.js").ProcessOwnershipSnapshot | undefined;
  const running = supervisor.run({
    executable: "/bin/sleep",
    args: ["10"],
    cwd: CWD,
    timeoutMs: 5_000,
    outputCapBytes: 100,
    onStarted: (value) => { snapshot = value; }
  });
  try {
    await new Promise((resolve) => setTimeout(resolve, 20));
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

test("process supervisor recovers a persisted detached descendant after root exit", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Persisted descendant recovery is a macOS native boundary");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 100, terminationGraceMs: 50 });
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
    const recovered = await supervisor.recoverOwnedProcess(snapshot!, 2_000);
    assert.equal(recovered.outcome, "drained");
    assert.equal(recovered.terminationObserved, true);
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
