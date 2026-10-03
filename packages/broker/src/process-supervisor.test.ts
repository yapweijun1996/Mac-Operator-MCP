import assert from "node:assert/strict";
import { renameSync, writeFileSync } from "node:fs";
import { chmod, mkdtemp, open, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { assertProcessPathIdentityStable, captureProcessPathIdentity, detectProcessIdentityReplacement, observeProcessRootState, ProcessSupervisor, type ProcessStdinSink } from "./process-supervisor.js";

const CWD = process.cwd();
// Host scheduling is a fixture prerequisite, separate from the timeout/failure
// under test. Capacity fixtures stay alive until the test explicitly cancels.
const FIXTURE_STARTUP_TIMEOUT_MS = 15_000;

async function waitForFixtureReady(ready: () => boolean, description: string): Promise<void> {
  const deadline = Date.now() + FIXTURE_STARTUP_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (ready()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error(`Process fixture did not become ready: ${description}`);
}

test("process supervisor rejects invalid per-executable capacity", () => {
  assert.throws(() => new ProcessSupervisor({ maxConcurrentPerExecutable: 0 }), /limits are outside/u);
  assert.throws(() => new ProcessSupervisor({ maxConcurrentPerExecutable: 65 }), /limits are outside/u);
  assert.throws(() => new ProcessSupervisor({ requireDescriptorExecution: "yes" as never }), /limits are outside/u);
  assert.throws(() => new ProcessSupervisor({ requireSystemPublishedExecutable: "yes" as never }), /limits are outside/u);
  assert.throws(() => new ProcessSupervisor({ requireDescriptorExecution: true, requireSystemPublishedExecutable: true }), /limits are outside/u);
  assert.throws(() => new ProcessSupervisor({
    descriptorSpawnAdapter: {
      mechanism: "darwin-descriptor-exec-v1",
      spawn: (() => { throw new Error("unused"); }) as never
    }
  }), /limits are outside/u);
});

test("process supervisor denies descriptor-required admission before spawning", async () => {
  const supervisor = new ProcessSupervisor({ requireDescriptorExecution: true });
  let started = false;
  await assert.rejects(
    supervisor.run({
      executable: "/usr/bin/true",
      args: [],
      cwd: CWD,
      timeoutMs: 1_000,
      outputCapBytes: 100,
      onStarted: () => { started = true; }
    }),
    (error: unknown) => error instanceof BrokerError &&
      error.errorClass === "POLICY_DENIED" &&
      error.message === "Kernel descriptor executable launch is unavailable"
  );
  assert.equal(started, false);
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor never falls back to pathname spawn after descriptor capability admission", async () => {
  let spawnCalls = 0;
  const supervisor = new ProcessSupervisor({
    requireDescriptorExecution: true,
    descriptorSpawnAdapter: {
      mechanism: "darwin-descriptor-exec-v1",
      spawn: () => {
        spawnCalls += 1;
        throw new Error("descriptor launcher should not be reached on an unavailable host");
      }
    }
  });
  await assert.rejects(
    supervisor.run({
      executable: "/usr/bin/true",
      args: [],
      cwd: CWD,
      timeoutMs: 1_000,
      outputCapBytes: 100
    }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.equal(spawnCalls, 0);
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
  const customPrototypeArgs = ["ok"] as string[];
  Object.setPrototypeOf(customPrototypeArgs, { reduce: () => 0 });
  await assert.rejects(supervisor.run({ ...base, args: customPrototypeArgs } as never), /limits or paths are invalid/u);
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

test("root observation resolves an exit between liveness and identity reads", () => {
  const identity = { pid: 42, processGroupId: 42, startTimeMicros: 100 };
  let checks = 0;
  const state = observeProcessRootState({
    isProcessIdentityAlive: (pid, startTimeMicros) => {
      assert.equal(pid, identity.pid);
      assert.equal(startTimeMicros, identity.startTimeMicros);
      checks += 1;
      return checks === 1;
    },
    getProcessIdentity: () => { throw new Error("process exited before identity read"); }
  }, identity, (pid) => { assert.equal(pid, identity.pid); return true; });
  assert.equal(state, "dead");
  assert.equal(checks, 2, "exit-race recovery performs one bounded exact-identity recheck");
});

test("root observation preserves uncertainty when the identity read fails for a live process", () => {
  const identity = { pid: 42, processGroupId: 42, startTimeMicros: 100 };
  for (const recheck of [true, undefined, "unavailable"] as const) {
    let checks = 0;
    assert.equal(observeProcessRootState({
      isProcessIdentityAlive: () => { checks += 1; return checks === 1 ? true : recheck; },
      getProcessIdentity: () => { throw new Error("observer unavailable"); }
    }, identity), "unknown");
    assert.equal(checks, 2);
  }
  let checks = 0;
  assert.equal(observeProcessRootState({
    isProcessIdentityAlive: () => { checks += 1; if (checks === 1) return true; throw new Error("observer unavailable"); },
    getProcessIdentity: () => { throw new Error("observer unavailable"); }
  }, identity), "unknown");
  assert.equal(checks, 2);
  assert.equal(observeProcessRootState({
    isProcessIdentityAlive: () => { throw new Error("initial observer unavailable"); },
    getProcessIdentity: () => { assert.fail("initial observation failure must not read another identity"); }
  }, identity), "unknown");
});

test("root observation requires an independent absence proof after a native read race", () => {
  const identity = { pid: 42, processGroupId: 42, startTimeMicros: 100 };
  for (const absence of [false, undefined, "permission-denied"] as const) {
    let checks = 0;
    assert.equal(observeProcessRootState({
      isProcessIdentityAlive: () => { checks += 1; return checks === 1; },
      getProcessIdentity: () => { throw new Error("process identity could not be read"); }
    }, identity, () => absence), "unknown");
    assert.equal(checks, 2);
  }
  let checks = 0;
  assert.equal(observeProcessRootState({
    isProcessIdentityAlive: () => { checks += 1; return checks === 1; },
    getProcessIdentity: () => { throw new Error("process identity could not be read"); }
  }, identity, () => { throw new Error("absence observer unavailable"); }), "unknown");
  assert.equal(checks, 2);
});

test("root absence probe accepts only ESRCH and never sends a termination signal", (t) => {
  const identity = { pid: 42, processGroupId: 42, startTimeMicros: 100 };
  for (const code of [undefined, "ESRCH", "EPERM", "EIO"] as const) {
    let checks = 0;
    t.mock.method(process, "kill", (pid: number, signal?: string | number) => {
      assert.equal(pid, identity.pid);
      assert.equal(signal, 0);
      if (code !== undefined) throw Object.assign(new Error("probe result"), { code });
      return true;
    });
    try {
      assert.equal(observeProcessRootState({
        isProcessIdentityAlive: () => { checks += 1; return checks === 1; },
        getProcessIdentity: () => { throw new Error("process identity could not be read"); }
      }, identity), code === "ESRCH" ? "dead" : "unknown");
      assert.equal(checks, 2);
    } finally {
      t.mock.restoreAll();
    }
  }
});

test("root observation never resolves PID reuse or malformed identity as an absence race", () => {
  const identity = { pid: 42, processGroupId: 42, startTimeMicros: 100 };
  for (const current of [
    { pid: 42, parentPid: 1, processGroupId: 42, startTimeMicros: 101 },
    { pid: 43, parentPid: 1, processGroupId: 43, startTimeMicros: 100 },
    { pid: 42, parentPid: 1, processGroupId: 43, startTimeMicros: 100 },
    { pid: 42 }
  ]) {
    let checks = 0;
    assert.equal(observeProcessRootState({
      isProcessIdentityAlive: () => { checks += 1; return checks === 1; },
      getProcessIdentity: () => current
    }, identity), "unknown");
    assert.equal(checks, 1, "a concrete invalid identity must not be reclassified by a later absence");
  }
});

test("root observation keeps exact live identity and already-absent identity deterministic", () => {
  const identity = { pid: 42, processGroupId: 42, startTimeMicros: 100 };
  assert.equal(observeProcessRootState({
    isProcessIdentityAlive: () => true,
    getProcessIdentity: () => ({ ...identity, parentPid: 1 })
  }, identity), "alive");
  assert.equal(observeProcessRootState({
    isProcessIdentityAlive: () => false,
    getProcessIdentity: () => { assert.fail("already absent identity does not require another read"); }
  }, identity), "dead");
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

test("process supervisor accepts queued stdin writes and makes stdin end idempotent", async () => {
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  const payload = "x".repeat(512 * 1024);
  let sink: ProcessStdinSink | undefined;
  try {
    const result = await supervisor.run({
      executable: "/usr/bin/python3",
      args: ["-c", "import sys,time; time.sleep(0.1); print(len(sys.stdin.read()))"],
      cwd: CWD,
      timeoutMs: 2_000,
      outputCapBytes: 1_024,
      keepStdinOpen: true,
      onStdinReady: (value) => {
        sink = value;
        assert.equal(value.write(payload), true);
        value.end();
        value.end();
        assert.equal(value.write("after-end"), false);
      }
    });
    assert.equal(result.state, "completed");
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout.trim(), String(payload.length));
    assert.equal(result.terminationObserved, true);
    assert.equal(sink!.write("after-close"), false);
    assert.doesNotThrow(() => sink!.end());
    assert.equal(supervisor.activeCount(), 0);
  } finally {
    await supervisor.close();
  }
});

test("process supervisor isolates asynchronous interactive stdin failure", async () => {
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  let sink: ProcessStdinSink | undefined;
  let wrote = false;
  try {
    const result = await supervisor.run({
      executable: "/usr/bin/python3",
      args: ["-c", "import os,time; time.sleep(0.1); os.close(0); os.write(1,b'INPUT_CLOSED'); time.sleep(10)"],
      cwd: CWD,
      timeoutMs: 2_000,
      outputCapBytes: 100,
      keepStdinOpen: true,
      onStdinReady: (value) => { sink = value; },
      streamOutput: true,
      onOutputChunk: () => {
        wrote = true;
        sink!.write("unread-input");
      }
    });
    assert.equal(wrote, true);
    assert.equal(result.state, "failed");
    assert.equal(result.resultClass, "EXECUTION_FAILED");
    assert.equal(result.terminationObserved, true);
    await assertProcessGone(result.processId);
    const independent = await supervisor.run({
      executable: "/usr/bin/printf", args: ["STILL_HEALTHY"], cwd: CWD, timeoutMs: 1_000, outputCapBytes: 100
    });
    assert.equal(independent.stdout, "STILL_HEALTHY");
    assert.equal(independent.state, "completed");
    assert.equal(supervisor.activeCount(), 0);
  } finally {
    await supervisor.close();
  }
});

test("process supervisor isolates streamed output consumer failure and drains the process", async () => {
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  let consumed = 0;
  try {
    const result = await supervisor.run({
      executable: "/usr/bin/python3",
      args: ["-c", "import os,time; os.write(1,b'OUTPUT'); time.sleep(10)"],
      cwd: CWD,
      timeoutMs: 2_000,
      outputCapBytes: 100,
      streamOutput: true,
      onOutputChunk: () => { consumed += 1; throw new Error("consumer unavailable"); }
    });
    assert.equal(consumed, 1);
    assert.equal(result.state, "failed");
    assert.equal(result.resultClass, "EXECUTION_FAILED");
    assert.equal(result.terminationObserved, true);
    await assertProcessGone(result.processId);
    assert.equal(supervisor.activeCount(), 0);
  } finally {
    await supervisor.close();
  }
});

test("process supervisor drains the process tree when stdin startup binding fails", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Startup tree cleanup proof uses the macOS native process observer");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  let snapshot: import("./process-supervisor.js").ProcessOwnershipSnapshot | undefined;
  let output = "";
  try {
    await assert.rejects(supervisor.run({
      executable: "/usr/bin/python3",
      args: ["-c", [
        "import os,time",
        "read_fd,write_fd=os.pipe()",
        "child=os.fork()",
        "if child == 0:",
        " os.close(read_fd); os.setsid(); os.write(write_fd,b'R'); os.close(write_fd); time.sleep(30)",
        "else:",
        " os.close(write_fd); assert os.read(read_fd,1)==b'R'; os.close(read_fd)",
        " os.write(1,('CHILD_PID:' + str(child) + '\\n').encode()); time.sleep(30)"
      ].join("\n")],
      cwd: CWD,
      timeoutMs: 2_000,
      outputCapBytes: 100,
      onStarted: async (value) => {
        snapshot = value;
        // Capture consumers are attached before onStarted; inject failure only
        // after the detached child has actually completed its setsid handshake.
        await waitForFixtureReady(() => /CHILD_PID:[1-9][0-9]*\n/u.test(output), "detached child PID");
      },
      streamOutput: true,
      onOutputChunk: (chunk) => { output += chunk.toString("utf8"); },
      keepStdinOpen: true,
      onStdinReady: () => { throw new Error("session binding unavailable"); }
    }), (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED");
    assert.ok(snapshot);
    const descendantPid = Number(/CHILD_PID:(\d+)/u.exec(output)?.[1]);
    assert.ok(Number.isSafeInteger(descendantPid) && descendantPid > 0);
    await assertProcessGone(snapshot.identity.pid);
    await assertProcessGone(descendantPid);
    assert.equal(supervisor.activeCount(), 0);
  } finally {
    await supervisor.close();
  }
});

test("process supervisor isolates asynchronous one-shot stdin failure", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Startup timing fixture uses the macOS native process observer");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  let output = "";
  try {
    const result = await supervisor.run({
      executable: "/usr/bin/python3",
      args: ["-c", "import os,time; os.close(0); os.write(1,b'INPUT_CLOSED'); time.sleep(30)"],
      cwd: CWD,
      stdin: "queued-input".repeat(5_000),
      timeoutMs: 2_000,
      outputCapBytes: 1_024,
      streamOutput: true,
      onOutputChunk: (chunk) => { output += chunk.toString("utf8"); },
      // Interpreter startup has its own bounded ready wait. The unchanged
      // two-second execution budget still bounds delivery failure after close.
      onStarted: () => waitForFixtureReady(() => output.includes("INPUT_CLOSED"), "closed one-shot stdin")
    });
    assert.match(output, /INPUT_CLOSED/u);
    assert.equal(result.state, "failed");
    assert.equal(result.resultClass, "EXECUTION_FAILED");
    assert.equal(result.terminationObserved, true);
    await assertProcessGone(result.processId);
    assert.equal(supervisor.activeCount(), 0);
  } finally {
    await supervisor.close();
  }
});

test("process supervisor rejects known secret representations in stdin", async () => {
  const supervisor = new ProcessSupervisor();
  await assert.rejects(supervisor.run({
    executable: "/usr/bin/printf",
    args: ["ok"],
    stdin: "token=ghp_1234567890abcdefghijklmnop",
    cwd: CWD,
    timeoutMs: 1_000,
    outputCapBytes: 100
  }), (error: unknown) => error instanceof BrokerError &&
    error.errorClass === "POLICY_DENIED" &&
    error.message === "Filesystem content matched a protected secret signature");
  const encoded = Buffer.from("ghp_1234567890abcdefghijklmnop", "utf8").toString("base64");
  await assert.rejects(supervisor.run({
    executable: "/usr/bin/printf",
    args: ["ok"],
    stdin: encoded,
    cwd: CWD,
    timeoutMs: 1_000,
    outputCapBytes: 100
  }), /protected secret signature/u);
  assert.equal(supervisor.activeCount(), 0);
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

test("process supervisor redacts known credentials from child output", async () => {
  const supervisor = new ProcessSupervisor();
  const result = await supervisor.run({
    executable: "/usr/bin/python3",
    args: ["-c", "print('ghp_' + '1234567890abcdefghijklmnop')"],
    cwd: CWD,
    timeoutMs: 2_000,
    outputCapBytes: 1_024
  });
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(result.stdout.trim(), "[REDACTED]");
  assert.equal(result.stderr, "");
  const splitResult = await supervisor.run({
    executable: "/usr/bin/python3",
    args: ["-c", "import os,time; os.write(1,b'ghp_1234567890'); time.sleep(0.02); os.write(1,b'abcdefghijklmnop'); os.write(2,b'rk_' + b'live_1234567890'); time.sleep(0.02); os.write(2,b'abcdefghijklmnop')"],
    cwd: CWD,
    timeoutMs: 2_000,
    outputCapBytes: 1_024
  });
  assert.equal(splitResult.resultClass, "SUCCEEDED");
  assert.equal(splitResult.stdout, "[REDACTED]");
  assert.equal(splitResult.stderr, "[REDACTED]");
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

test("strict task exit proof keeps a live late descendant unresolved", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Strict task exit proof uses the macOS native process observer");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 25, terminationGraceMs: 50 });
  const result = await supervisor.run({
    executable: "/usr/bin/python3",
    args: ["-c", "import os,time; child=os.fork();\nif child == 0:\n os.close(1); os.close(2); time.sleep(5)\nelse:\n os._exit(0)"],
    cwd: CWD,
    timeoutMs: 2_000,
    outputCapBytes: 100,
    requireCleanExitProof: true
  });
  assert.equal(result.resultClass, "UNKNOWN_OUTCOME");
  assert.equal(result.terminationObserved, true);
  await supervisor.close();
  assert.equal(supervisor.activeCount(), 0);
});

test("strict task exit proof follows an observed detached process group", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Strict task exit proof uses the macOS native process observer");
    return;
  }
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 10, terminationGraceMs: 50 });
  const result = await supervisor.run({
    executable: "/usr/bin/python3",
    args: [
      "-c",
      [
        "import os,time",
        "child=os.fork()",
        "if child == 0:",
        " os.setsid()",
        " grandchild=os.fork()",
        " if grandchild == 0:",
        "  print(os.getpid(), flush=True)",
        "  os.close(1); os.close(2); time.sleep(5)",
        " else:",
        "  time.sleep(0.25); os._exit(0)",
        "else:",
        " time.sleep(0.6); os._exit(0)"
      ].join("\n")
    ],
    cwd: CWD,
    timeoutMs: 2_000,
    outputCapBytes: 10_000,
    requireCleanExitProof: true
  });
  assert.equal(result.resultClass, "UNKNOWN_OUTCOME");
  assert.equal(result.terminationObserved, true);
  await supervisor.close();
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor rechecks cancellation before publishing a closed child as success", async () => {
  let checks = 0;
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 1_000, terminationGraceMs: 50 });
  const result = await supervisor.run({
    executable: "/usr/bin/true",
    args: [],
    cwd: CWD,
    timeoutMs: 1_000,
    outputCapBytes: 100,
    shouldCancel: () => {
      checks += 1;
      return checks >= 3;
    }
  });
  assert.equal(result.resultClass, "CANCELLED");
  assert.equal(result.state, "cancelled");
  assert.ok(checks >= 3);
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

test("process supervisor rejects group- or other-writable cwd directories", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-writable-cwd-"));
  const canonicalDirectory = await realpath(directory);
  try {
    await chmod(canonicalDirectory, 0o777);
    const supervisor = new ProcessSupervisor();
    await assert.rejects(
      supervisor.run({ executable: "/usr/bin/true", args: [], cwd: canonicalDirectory, timeoutMs: 1_000, outputCapBytes: 100 }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED" && /cwd permissions/u.test(error.message)
    );
  } finally {
    await chmod(canonicalDirectory, 0o700).catch(() => undefined);
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

test("process supervisor accepts only a root-published executable path for fixed adapters", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("System-published executable evidence is a macOS boundary");
    return;
  }
  const supervisor = new ProcessSupervisor({
    requireRootOwnedExecutable: true,
    requireSystemPublishedExecutable: true
  });
  const trusted = await supervisor.run({
    executable: "/usr/bin/printf",
    args: ["system-published"],
    cwd: CWD,
    timeoutMs: 1_000,
    outputCapBytes: 100
  });
  assert.equal(trusted.state, "completed");
  assert.equal(trusted.stdout, "system-published");

  const directory = await mkdtemp(join(tmpdir(), "mac-operator-process-published-owner-"));
  const executable = join(await realpath(directory), "runner");
  try {
    await writeFile(executable, "#!/bin/sh\nprintf user-owned\n", { mode: 0o700 });
    await assert.rejects(
      supervisor.run({
        executable,
        args: [],
        cwd: CWD,
        timeoutMs: 1_000,
        outputCapBytes: 100
      }),
      /not root-owned|system-published/u
    );
  } finally {
    await supervisor.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("process supervisor allows only a configured user-owned executable exception", async () => {
  const uid = process.getuid?.();
  if (uid === undefined || uid === 0) return;
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-process-trusted-user-executable-"));
  const executable = join(await realpath(directory), "runner");
  const supervisor = new ProcessSupervisor({
    requireRootOwnedExecutable: true,
    trustedUserOwnedExecutablePaths: [executable]
  });
  try {
    await writeFile(executable, "#!/bin/sh\nprintf trusted-user\n", { mode: 0o700 });
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
    const trusted = await supervisor.run({
      executable,
      args: [],
      cwd: CWD,
      timeoutMs: 1_000,
      outputCapBytes: 100,
      allowUserOwnedExecutable: true
    });
    assert.equal(trusted.state, "completed");
    assert.equal(trusted.stdout, "trusted-user");
  } finally {
    await supervisor.close();
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

test("process supervisor binds an expected executable content identity before spawn", async () => {
  const executable = "/bin/echo";
  const identity = await captureProcessPathIdentity(executable, "executable");
  const supervisor = new ProcessSupervisor();
  try {
    await assert.rejects(
      supervisor.run({
        executable,
        args: ["unexpected"],
        cwd: CWD,
        timeoutMs: 2_000,
        outputCapBytes: 100,
        expectedExecutableContentSha256: "0".repeat(64)
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    const result = await supervisor.run({
      executable,
      args: ["bound"],
      cwd: CWD,
      timeoutMs: 2_000,
      outputCapBytes: 100,
      expectedExecutableContentSha256: identity.contentSha256!
    });
    assert.equal(result.stdout.trim(), "bound");
  } finally {
    await supervisor.close();
  }
});

test("process supervisor rejects executable owner identity drift after authorization", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-process-owner-drift-"));
  const executable = join(await realpath(directory), "runner");
  try {
    await writeFile(executable, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    const identity = await captureProcessPathIdentity(executable, "executable");
    const changedOwnerUid = identity.ownerUid === 0 ? 1 : 0;
    await assert.rejects(
      assertProcessPathIdentityStable(executable, { ...identity, ownerUid: changedOwnerUid }, "executable"),
      /Executable changed after authorization/u
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
  let readyAt = 0;
  let output = "";
  const result = await supervisor.run({
    executable: "/usr/bin/python3",
    args: [
      "-c",
      [
        "import os,time",
        "read_fd,write_fd=os.pipe()",
        "pid=os.fork()",
        "if pid == 0:",
        " os.close(read_fd); os.setsid(); os.write(write_fd,b'R'); os.close(write_fd); time.sleep(30)",
        "else:",
        " os.close(write_fd); assert os.read(read_fd,1)==b'R'; os.close(read_fd)",
        " print(pid,flush=True); time.sleep(30)"
      ].join("\n")
    ],
    cwd: CWD,
    timeoutMs: 200,
    outputCapBytes: 1_024,
    streamOutput: true,
    onOutputChunk: (chunk) => { output += chunk.toString("utf8"); },
    onStarted: async () => {
      await waitForFixtureReady(() => /^[1-9][0-9]*\n$/u.test(output), "detached descendant PID");
      readyAt = Date.now();
    }
  });
  assert.equal(result.state, "timed_out");
  assert.equal(result.resultClass, "TIMEOUT");
  assert.equal(result.terminationObserved, true);
  const descendantPid = Number.parseInt(output, 10);
  assert.ok(Number.isSafeInteger(descendantPid) && descendantPid > 0);
  assert.ok(readyAt > 0);
  assert.ok(Date.now() - readyAt < 2_000, "detached descendant must not hold the supervisor for its full lifetime");
  await assertProcessGone(descendantPid);
  assert.equal(supervisor.activeCount(), 0);
});

test("process supervisor cancellation kills descendants and releases capacity", async () => {
  const supervisor = new ProcessSupervisor({ maxConcurrent: 1, pollIntervalMs: 5, terminationGraceMs: 50 });
  let cancelled = false;
  let output = "";
  const running = supervisor.run({
    executable: "/bin/bash",
    args: ["-c", "/bin/sleep 30 & printf '%s\\n' \"$!\"; wait"],
    cwd: CWD,
    timeoutMs: 30_000,
    outputCapBytes: 1_024,
    streamOutput: true,
    onOutputChunk: (chunk) => { output += chunk.toString("utf8"); },
    shouldCancel: () => cancelled
  });
  // Wait for active admission rather than a wall-clock guess. Under the full
  // cross-package suite, path identity checks can legitimately take longer
  // than 30ms; cancelling before spawn exercises a different contract.
  await waitForActiveProcess(supervisor, 1, FIXTURE_STARTUP_TIMEOUT_MS);
  await waitForFixtureReady(() => /^[1-9][0-9]*\n$/u.test(output), "cancellation descendant PID");
  cancelled = true;
  const result = await running;
  assert.equal(result.state, "cancelled");
  assert.equal(result.resultClass, "CANCELLED");
  assert.equal(result.terminationObserved, true);
  const descendantPid = Number.parseInt(output, 10);
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
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(Object.isFrozen(snapshot!.identity), true);
  assert.equal(Object.isFrozen(snapshot!.descendants), true);
  assert.throws(
    () => { (snapshot!.identity as unknown as { pid: number }).pid = 1; },
    TypeError
  );
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
    // A concurrent Edge/process fixture may reuse the dead root PID while
    // the detached child is being recovered. The safe result is UNKNOWN in
    // that case; never turn observer uncertainty into a false drained claim.
    assert.ok(recovered.outcome === "drained" || recovered.outcome === "unknown");
    assert.equal(recovered.terminationObserved, recovered.outcome === "drained");
  } finally {
    await supervisor.close();
    await running;
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
    args: ["-c", "import os,time; child=os.fork(); (time.sleep(30), os._exit(0)) if child == 0 else (os.waitpid(child, 0), time.sleep(30))"],
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
    // End the observed fixture child only after its PID/start-time identity has
    // been persisted; the root remains alive and waits for that child to exit.
    for (const descendant of snapshot!.descendants) {
      try { process.kill(descendant.pid, "SIGKILL"); } catch { /* already exited */ }
    }
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
    args: ["30"],
    cwd: CWD,
    timeoutMs: 30_000,
    outputCapBytes: 100,
    shouldCancel: () => cancelled
  });
  await waitForActiveProcess(supervisor, 1, FIXTURE_STARTUP_TIMEOUT_MS);
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
    args: ["30"],
    cwd: CWD,
    timeoutMs: 30_000,
    outputCapBytes: 100,
    shouldCancel: () => cancelled
  });
  try {
    await waitForActiveProcess(supervisor, 1, FIXTURE_STARTUP_TIMEOUT_MS);
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
    args: ["30"],
    cwd: CWD,
    timeoutMs: 30_000,
    outputCapBytes: 100,
    shouldCancel: () => cancelled
  }));
  try {
    await waitForActiveProcess(supervisor, 4, FIXTURE_STARTUP_TIMEOUT_MS);
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
