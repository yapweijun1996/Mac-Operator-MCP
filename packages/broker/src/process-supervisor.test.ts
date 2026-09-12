import assert from "node:assert/strict";
import { mkdtemp, rm, symlink } from "node:fs/promises";
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
