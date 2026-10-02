import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import test from "node:test";
import { BrokerError, signRequest, type BrokerResult, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { PersonalOwnerTerminalExecutor } from "./owner-terminal.js";
import { OwnerTerminalSessionManager } from "./owner-terminal-session.js";
import { BrokerStore, type BrokerJob } from "./persistence.js";
import type { ProcessExecutionResult, ProcessSupervisor } from "./process-supervisor.js";

const supported = process.platform === "darwin" && process.getuid?.() !== 0;
const principalId = "principal-1";
const runFile = promisify(execFile);

async function until(check: () => boolean | Promise<boolean>, timeoutMs = 20_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!(await check())) {
    if (Date.now() >= deadline) throw new Error("PTY reliability condition was not reached");
    await delay(25);
  }
}

function data(result: BrokerResult): Record<string, unknown> {
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.ok(result.ok);
  return result.data as Record<string, unknown>;
}

function ended(result: BrokerResult): void {
  if (result.ok) {
    assert.equal((result.data as Record<string, unknown>).finished, true, JSON.stringify(result));
    return;
  }
  assert.ok(["CONFLICT", "TARGET_NOT_FOUND", "EXECUTION_FAILED"].includes(result.result_class), JSON.stringify(result));
  assert.equal(typeof result.error.message, "string");
  assert.equal(typeof result.error.retryable, "boolean");
}

function absent(pid: number): boolean {
  try { process.kill(pid, 0); return false; } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return true;
    throw error;
  }
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

// Exercise raw input, a foreground PTY group, a child process, and the modes
// interactive CLIs use. The fixture emits readiness only after echo is disabled.
const rawTui = `
import os, signal, subprocess, sys, termios, tty
saved = termios.tcgetattr(0)
child = subprocess.Popen(['/bin/sleep', '300'])
try:
    tty.setraw(0)
    os.write(1, b'\\x1b[?1049h\\x1b[?25l\\x1b[?1000h\\x1b[?2004h')
    os.write(1, ('TUI_READY:%s:%s\\n' % (os.getpid(), child.pid)).encode())
    while True:
        key = os.read(0, 1)
        if not key or key in (b'q', b'\\x03', b'\\x1b'):
            break
        os.write(1, b'TUI_KEY:' + key + b'\\n')
finally:
    termios.tcsetattr(0, termios.TCSANOW, saved)
    os.write(1, b'\\x1b[?2004l\\x1b[?1000l\\x1b[?25h\\x1b[?1049lTUI_EXIT\\n')
    child.terminate()
    child.wait()
`;

async function fixture(retentionMs = 5_000, supervisor?: Pick<ProcessSupervisor, "run" | "close">) {
  const root = await realpath(await mkdtemp("/tmp/owner-session-reliability-"));
  const tuiPath = join(root, "raw-tui.py");
  await writeFile(tuiPath, rawTui);
  const store = new BrokerStore(join(root, "broker.sqlite"), { runtimeFence: true });
  const manager = new OwnerTerminalSessionManager({ enabled: true, maxSessions: 2, finishedRetentionMs: retentionMs,
    ...(supervisor ? { supervisor } : {}) });
  const key = randomBytes(32);
  const base = createDefaultPolicy("edge-1", true, ["mac.terminal.exec", "mac.control.read", "mac.job.read"], ["edge-key-1"]);
  const policy = { ...base, killSwitches: { ...base.killSwitches, mutations: false },
    tools: new Map(base.tools)
      .set("mac_terminal_session", { ...base.tools.get("mac_terminal_session")!, enabled: true })
      .set("mac_terminal_exec", { ...base.tools.get("mac_terminal_exec")!, enabled: true }),
    targetRules: [...base.targetRules, { ruleId: "owner-terminal-reliability", effect: "allow" as const, principalId,
      scope: "mac.terminal.exec" as const, target: { kind: "host" as const, reference: "owner-terminal" } }] };
  const broker = new Broker({ store, policy, ownerTerminalSessions: manager,
    ownerTerminalExecutor: new PersonalOwnerTerminalExecutor({ enabled: true }),
    edgeAuthenticationKeys: new EdgeKeyring([{ edgeId: "edge-1", keyId: "edge-key-1", key,
      notBeforeMs: Date.now() - 60_000, expiresAtMs: Date.now() + 900_000 }]),
    authorizeOwnerTerminal: async operation => {
      const now = Date.now();
      store.issueApproval({ approvalId: `approval:${operation.requestId}`, approverPrincipalId: "owner-delegate",
        requestingPrincipalId: operation.principalId, tool: operation.tool, contractVersion: operation.contractVersion,
        targetKind: operation.targetKind, targetRef: operation.targetRef, payloadDigest: operation.payloadDigest,
        policyVersion: operation.policyVersion, approvalClass: "trusted_profile", unattended: true,
        issuedAtMs: now, expiresAtMs: now + operation.timeoutMs + 30_000, useLimit: 1 });
      return true;
    } });
  let sequence = 0;
  const call = (tool: string, args: Record<string, unknown>) => {
    const now = Date.now(); sequence += 1;
    const request: UnsignedBrokerRequest = { protocolVersion: "0.1", requestId: `reliability-${sequence}`, contractVersion: "0.1",
      tool, arguments: args, principal: { principalId, sessionId: "reliability-session", issuer: "test-issuer",
        audience: "mac-operator-broker", scopes: ["mac.terminal.exec", "mac.control.read", "mac.job.read"],
        issuedAtMs: now - 1_000, expiresAtMs: now + 900_000, edgeId: "edge-1" },
      timestampMs: now, nonce: `reliability-nonce-${sequence}`, policyAudience: "mac-operator-broker",
      policyVersion: policy.version, authenticationKeyId: "edge-key-1" };
    return broker.handle(signRequest(request, key));
  };
  const io = (args: Record<string, unknown>) => call("mac_terminal_session", args);
  const start = async (idempotencyKey: string, cwd = root) => {
    const result = data(await io({ action: "start", cwd, idempotency_key: idempotencyKey, lifetime_ms: 120_000, idle_timeout_ms: 60_000 }));
    assert.equal(result.state, "running");
    return { sessionId: result.session_id as string, jobId: result.job_id as string };
  };
  const terminalJob = async (jobId: string): Promise<BrokerJob> => {
    await until(() => {
      const job = store.ownedJob(jobId, principalId);
      return job !== undefined && ["completed", "failed", "cancelled"].includes(job.state);
    });
    const job = store.ownedJob(jobId, principalId)!;
    assert.ok(job.finishedAtMs !== null);
    assert.notEqual(job.resultClass, "unknown");
    assert.equal(job.processMetadata, undefined, "process metadata remains until cleanup is proven");
    const status = data(await call("mac_job_status", { job_id: jobId, tail_bytes: 0 }));
    assert.equal(status.state, job.state);
    assert.equal(status.exit_code, job.exitCode);
    assert.equal(typeof status.finished_at, "string");
    assert.notEqual(status.result_class, "unknown");
    return job;
  };
  const collector = (sessionId: string) => {
    let cursor = 0;
    let output = "";
    return {
      async poll(waitMs = 100) {
        const read = data(await io({ action: "read", session_id: sessionId, cursor, wait_ms: waitMs }));
        output += read.output as string; cursor = read.next_cursor as number;
        return read;
      },
      get output() { return output; },
      get cursor() { return cursor; }
    };
  };
  const launchTui = async (sessionId: string) => {
    const output = collector(sessionId);
    data(await io({ action: "write", session_id: sessionId, data: `/usr/bin/python3 ${shellQuote(tuiPath)}\n` }));
    await until(async () => { await output.poll(); return /TUI_READY:\d+:\d+\r?\n/u.test(output.output); });
    const ready = /TUI_READY:(\d+):(\d+)\r?\n/u.exec(output.output)!;
    assert.match(output.output, /\u001b\[\?1049h/u);
    return { output, pids: [Number(ready[1]), Number(ready[2])] };
  };
  const independentCalls = async (label: string) => {
    const [health, execution] = await Promise.all([
      call("mac_health", { include_components: false }),
      call("mac_terminal_exec", { command: "echo PARALLEL_OK", cwd: root, idempotency_key: `parallel-${label}` })
    ]);
    assert.equal(data(health).overall, "healthy");
    assert.equal(data(execution).stdout, "PARALLEL_OK\n");
    assert.equal(data(execution).exit_code, 0);
  };
  const expired = async (sessionId: string, jobId: string) => {
    await until(() => {
      try { manager.describe(principalId, sessionId); return false; } catch (error) {
        assert.ok(error instanceof BrokerError);
        assert.equal(error.errorClass, "TARGET_NOT_FOUND");
        assert.ok(store.ownedJob(jobId, principalId)?.finishedAtMs !== null, "eviction follows durable job finalization");
        return true;
      }
    }, retentionMs + 5_000);
  };
  return { root, store, broker, manager, io, call, start, terminalJob, collector, launchTui, independentCalls, expired,
    async close() { await broker.close(); store.close(); key.fill(0); await rm(root, { recursive: true, force: true }); } };
}

test("PTY reliability: shell input waits, raw alternate-screen TUI and independent Broker calls", { skip: !supported, timeout: 120_000 }, async () => {
  const f = await fixture();
  try {
    const shell = await f.start("shell-stdin");
    const output = f.collector(shell.sessionId);
    data(await f.io({ action: "write", session_id: shell.sessionId, data: "printf 'WAIT_%s\\n' READY; read -r answer; printf 'GOT_%s\\n' \"$answer\"\n" }));
    await until(async () => { await output.poll(); return /WAIT_READY\r?\n/u.test(output.output); });
    assert.equal((await output.poll()).finished, false, "waiting for stdin preserves the live session");
    await f.independentCalls("stdin-wait");
    data(await f.io({ action: "write", session_id: shell.sessionId, data: "hello\n" }));
    await until(async () => { await output.poll(); return /GOT_hello\r?\n/u.test(output.output); });
    const stopped = data(await f.io({ action: "stop", session_id: shell.sessionId }));
    assert.equal(stopped.finished, true);
    const normalJob = await f.terminalJob(shell.jobId);
    assert.equal(normalJob.state, "completed"); assert.equal(normalJob.exitCode, 0);

    const tui = await f.start("raw-tui");
    const active = await f.launchTui(tui.sessionId);
    await f.independentCalls("raw-active");
    data(await f.io({ action: "write", session_id: tui.sessionId, data: "a" }));
    await until(async () => { await active.output.poll(); return active.output.output.includes("TUI_KEY:a"); });
    data(await f.io({ action: "write", session_id: tui.sessionId, data: "q" }));
    await until(async () => { await active.output.poll(); return active.output.output.includes("TUI_EXIT"); });
    data(await f.io({ action: "stop", session_id: tui.sessionId }));
    assert.equal((await f.terminalJob(tui.jobId)).state, "completed");
    for (const pid of active.pids) await until(() => absent(pid));
    await f.independentCalls("raw-finished");
  } finally { await f.close(); }
});

test("PTY reliability: unexpected foreground and relay death are explicit and contained", { skip: !supported, timeout: 120_000 }, async () => {
  const f = await fixture();
  try {
    // Killing the foreground application alone returns control to the shell.
    const foreground = await f.start("foreground-kill");
    const active = await f.launchTui(foreground.sessionId);
    process.kill(active.pids[0]!, "SIGKILL");
    await until(() => absent(active.pids[0]!));
    await f.independentCalls("foreground-killed");
    data(await f.io({ action: "stop", session_id: foreground.sessionId }));
    await f.terminalJob(foreground.jobId);
    for (const pid of active.pids) await until(() => absent(pid));

    // Killing the relay removes the transport while its detached PTY tree lives.
    const relay = await f.start("relay-kill");
    const live = await f.launchTui(relay.sessionId);
    const metadata = f.store.ownedJob(relay.jobId, principalId)!.processMetadata!;
    assert.ok(metadata.pid > 0);
    process.kill(metadata.pid, "SIGKILL");
    const final = await f.terminalJob(relay.jobId);
    assert.equal(final.state, "failed");
    await until(() => absent(metadata.pid));
    for (const pid of live.pids) await until(() => absent(pid));
    await f.independentCalls("relay-killed");
    ended(await f.io({ action: "write", session_id: relay.sessionId, data: "x" }));
    ended(await f.io({ action: "read", session_id: relay.sessionId, cursor: 0 }));
    ended(await f.io({ action: "stop", session_id: relay.sessionId }));
  } finally { await f.close(); }
});

test("PTY reliability: concurrent reads, writes and repeated stops finalize before eviction", { skip: !supported, timeout: 120_000 }, async () => {
  const f = await fixture(1_000);
  try {
    const running = await f.start("io-stop-race");
    const active = await f.launchTui(running.sessionId);
    const races = await Promise.all([
      f.io({ action: "read", session_id: running.sessionId, cursor: active.output.cursor, wait_ms: 2_000 }),
      f.io({ action: "write", session_id: running.sessionId, data: "x" }),
      f.io({ action: "stop", session_id: running.sessionId }),
      f.io({ action: "stop", session_id: running.sessionId }),
      f.call("mac_health", { include_components: false })
    ]);
    for (const result of races) {
      if (!result.ok) ended(result);
      else assert.equal(result.result_class, "SUCCEEDED");
    }
    await f.terminalJob(running.jobId);
    for (const pid of active.pids) await until(() => absent(pid));
    ended(await f.io({ action: "write", session_id: running.sessionId, data: "x" }));
    ended(await f.io({ action: "read", session_id: running.sessionId, cursor: 0 }));
    ended(await f.io({ action: "stop", session_id: running.sessionId }));
    await f.expired(running.sessionId, running.jobId);
    for (const action of ["write", "read", "stop"]) {
      const result = await f.io({ action, session_id: running.sessionId, ...(action === "write" ? { data: "x" } : action === "read" ? { cursor: 0 } : {}) });
      assert.equal(result.ok, false);
      assert.equal(result.result_class, "TARGET_NOT_FOUND");
    }
    await f.independentCalls("after-expiry");
  } finally { await f.close(); }
});

test("PTY reliability: durable cancellation wins the process-exit finalization race", { skip: !supported, timeout: 30_000 }, async () => {
  let finish!: (result: ProcessExecutionResult) => void;
  const exit = new Promise<ProcessExecutionResult>(resolve => { finish = resolve; });
  const completed: ProcessExecutionResult = { state: "completed", resultClass: "SUCCEEDED", processId: 12345, processGroupId: 12345,
    exitCode: 0, signal: null, stdout: "", stderr: "", truncated: false, durationMs: 1, terminationObserved: true };
  const f = await fixture(5_000, {
    async run(request) {
      // No OS process is created: this seam orders a valid observed exit after
      // the cancellation commit, which cannot be timed reliably in a real PTY.
      await request.onStarted?.({ identity: { pid: 12345, processGroupId: 12345, startTimeMicros: 1 }, descendants: [] });
      request.onStdinReady?.({ write: () => true, end: () => undefined });
      return exit;
    },
    async close() { finish(completed); }
  });
  try {
    const running = await f.start("cancel-exit-race");
    f.store.requestJobCancellation(running.jobId, principalId, "OWNER_CANCELLED", Date.now());
    finish(completed);
    const job = await f.terminalJob(running.jobId);
    assert.equal(job.state, "cancelled");
    const read = data(await f.io({ action: "read", session_id: running.sessionId, cursor: 0 }));
    assert.equal(read.finished, true); assert.equal(read.state, "cancelled");
    const stop = data(await f.io({ action: "stop", session_id: running.sessionId }));
    assert.equal(stop.finished, true); assert.equal(stop.state, "cancelled");
  } finally { await f.close(); }
});

test("PTY reliability: Broker shutdown commits an active raw-TUI job before returning", { skip: !supported, timeout: 60_000 }, async () => {
  const f = await fixture();
  try {
    const running = await f.start("broker-close-active-tui");
    const active = await f.launchTui(running.sessionId);
    await until(() => {
      const descendants = f.store.ownedJob(running.jobId, principalId)?.processMetadata?.descendants ?? [];
      return active.pids.every(pid => descendants.some(identity => identity.pid === pid));
    });
    const metadata = f.store.ownedJob(running.jobId, principalId)!.processMetadata!;
    const observedPids = new Set([metadata.pid, ...metadata.descendants.map(identity => identity.pid), ...active.pids]);
    // The service's SIGINT handler awaits this boundary before closing its store.
    await f.broker.close();
    const job = f.store.ownedJob(running.jobId, principalId)!;
    assert.ok(["cancelled", "failed"].includes(job.state), `shutdown job ${job.state}/${job.exitCode}`);
    assert.ok(job.finishedAtMs !== null, "shutdown returns after the terminal ledger commit");
    assert.notEqual(job.resultClass, "unknown");
    assert.equal(job.processMetadata, undefined, "shutdown clears ownership only after process-tree cleanup");
    for (const pid of observedPids) await until(() => absent(pid));
    await f.broker.close();
  } finally { await f.close(); }
});

test("PTY reliability: 50 raw-TUI start/stop cycles leave no unknown jobs, children or sessions", { skip: !supported, timeout: 300_000 }, async t => {
  const f = await fixture(1_000);
  const sessions: { sessionId: string; jobId: string }[] = [];
  const startedAt = Date.now();
  try {
    for (let cycle = 0; cycle < 50; cycle += 1) {
      const running = await f.start(`stress-${cycle}`);
      sessions.push(running);
      const active = await f.launchTui(running.sessionId);
      await f.independentCalls(`stress-${cycle}`);
      const stopped = data(await f.io({ action: "stop", session_id: running.sessionId }));
      assert.equal(stopped.finished, true, `cycle ${cycle}`);
      await f.terminalJob(running.jobId);
      for (const pid of active.pids) await until(() => absent(pid));
    }
    for (const session of sessions) {
      await f.expired(session.sessionId, session.jobId);
      const job = f.store.ownedJob(session.jobId, principalId)!;
      assert.ok(["completed", "failed", "cancelled"].includes(job.state));
      assert.notEqual(job.resultClass, "unknown");
    }
    await f.independentCalls("stress-final");
    t.diagnostic(`50 cycles passed in ${Date.now() - startedAt} ms; 0 unknown jobs, 0 surviving observed children, 0 retained sessions`);
  } finally { await f.close(); }
});

function terminalText(output: string): string {
  // Cursor positioning may split the words in Claude's trust dialog.
  return output.replace(/\u001b\[[0-?]*[ -/]*[@-~]/gu, " ").replace(/\s+/gu, " ");
}

async function tmpTrustAccepted(): Promise<boolean | undefined> {
  let text: string;
  try { text = await readFile(join(homedir(), ".claude.json"), "utf8"); } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  const config = JSON.parse(text) as { projects?: Record<string, { hasTrustDialogAccepted?: boolean }> };
  return config.projects?.["/private/tmp"]?.hasTrustDialogAccepted;
}

test("PTY reliability: real Claude trust screen never poisons unrelated requests or persists trust", {
  skip: !supported || process.env.MOPS_REAL_CLAUDE_PTY !== "1", timeout: 120_000
}, async t => {
  const claude = join(homedir(), ".local/bin/claude");
  const version = (await runFile(claude, ["--version"], { timeout: 15_000 })).stdout.trim();
  const trustBefore = await tmpTrustAccepted();
  assert.notEqual(trustBefore, true, "/private/tmp must be untrusted for the real trust-dialog probe");
  const f = await fixture();
  try {
    const running = await f.start("real-claude-trust", "/tmp");
    const output = f.collector(running.sessionId);
    data(await f.io({ action: "write", session_id: running.sessionId,
      data: `${shellQuote(claude)}; printf 'CLAUDE_%s\\n' EXITED\n` }));
    await until(async () => {
      await output.poll(500);
      const text = terminalText(output.output);
      return /Quick safety check/u.test(text) && /No, exit/u.test(text) && /Yes, I trust this folder/u.test(text);
    }, 45_000);
    const metadata = f.store.ownedJob(running.jobId, principalId)!.processMetadata!;
    const observedPids = [metadata.pid, ...metadata.descendants.map(identity => identity.pid)];
    await f.independentCalls("claude-active");
    await output.poll(500);
    // The default highlighted choice is No, exit; Enter refuses workspace trust.
    data(await f.io({ action: "write", session_id: running.sessionId, data: "\r" }));
    // Refusal can take longer than a fixed delay while Claude drains its child
    // processes. Stop only after the shell proves that the foreground CLI exited.
    await until(async () => { await output.poll(500); return /CLAUDE_EXITED\r?\n/u.test(output.output); }, 30_000);
    const stopped = data(await f.io({ action: "stop", session_id: running.sessionId }));
    assert.equal(stopped.finished, true);
    const job = await f.terminalJob(running.jobId);
    await output.poll();
    assert.equal(job.state, "completed", `Claude stop=${JSON.stringify(stopped)}; tail=${terminalText(output.output).slice(-500)}`);
    assert.equal(job.exitCode, 0);
    for (const pid of observedPids) await until(() => absent(pid));
    ended(await f.io({ action: "write", session_id: running.sessionId, data: "x" }));
    ended(await f.io({ action: "read", session_id: running.sessionId, cursor: 0 }));
    ended(await f.io({ action: "stop", session_id: running.sessionId }));
    await f.independentCalls("claude-finished");
    assert.equal(await tmpTrustAccepted(), trustBefore, "No, exit must not persist workspace trust");
    t.diagnostic(`${version}: /private/tmp trust screen observed; No, exit selected; concurrent health and terminal exec succeeded; final job completed/0; observed process tree absent`);
  } finally { await f.close(); }
});
