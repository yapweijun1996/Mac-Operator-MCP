import assert from "node:assert/strict";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { OwnerTerminalSessionManager } from "./owner-terminal-session.js";

const supported = process.platform === "darwin" && process.getuid?.() !== 0;

async function waitFor(check: () => boolean, ms = 20_000): Promise<void> {
  const deadline = Date.now() + ms;
  while (!check()) {
    if (Date.now() > deadline) throw new Error("condition not reached");
    await delay(50);
  }
}

function collector(manager: OwnerTerminalSessionManager, owner: string, id: string) {
  let cursor = 0;
  let text = "";
  return { poll() { const r = manager.read(owner, id, cursor); cursor = r.nextCursor; text += r.data; return r; }, get text() { return text; } };
}

const base = { lifetimeMs: 60_000, idleTimeoutMs: 30_000, shouldCancel: () => false };

test("session manager stays disabled without opt-in", async () => {
  const manager = new OwnerTerminalSessionManager();
  try {
    assert.equal(manager.available, false);
    await assert.rejects(manager.start("owner", { ...base, cwd: "/tmp" }), /not enabled/u);
  } finally { await manager.close(); }
});

test("interactive PTY session accepts stdin, reads by cursor and ends on exit", { skip: !supported }, async () => {
  const root = await realpath(await mkdtemp("/tmp/owner-session-test-"));
  const manager = new OwnerTerminalSessionManager({ enabled: true });
  try {
    let started = false;
    const { sessionId } = await manager.start("owner", { ...base, cwd: root, rows: 30, cols: 100, onProcessStarted: () => { started = true; } });
    assert.equal(started, true);
    const out = collector(manager, "owner", sessionId);
    manager.write("owner", sessionId, "tty >/dev/null && echo TTY_OK; stty size; read -r answer; echo got:$answer\n");
    await waitFor(() => { out.poll(); return out.text.includes("30 100"); });
    assert.match(out.text, /TTY_OK/u);
    manager.write("owner", sessionId, "hello\n");
    await waitFor(() => { out.poll(); return out.text.includes("got:hello"); });
    manager.write("owner", sessionId, "pwd; exit\n");
    await waitFor(() => out.poll().finished);
    assert.match(out.text, new RegExp(root));
    assert.equal(manager.read("owner", sessionId, 0).state, "completed");
    assert.throws(() => manager.write("owner", sessionId, "x\n"), /ended/u);
  } finally { await manager.close(); await rm(root, { recursive: true, force: true }); }
});

test("session input and ownership are screened and bound to the owner", { skip: !supported }, async () => {
  const manager = new OwnerTerminalSessionManager({ enabled: true });
  try {
    const { sessionId } = await manager.start("owner", { ...base, cwd: "/tmp" });
    assert.throws(() => manager.write("owner", sessionId, ""), /invalid|empty/iu);
    assert.throws(() => manager.write("owner", sessionId, "a\0b"), /NUL/u);
    assert.throws(() => manager.write("owner", sessionId, "x".repeat(4097)), /4096/u);
    assert.throws(() => manager.write("owner", sessionId, "echo -----BEGIN OPENSSH PRIVATE KEY-----\n"));
    assert.throws(() => manager.write("intruder", sessionId, "id\n"), /not found/u);
    assert.throws(() => manager.read("intruder", sessionId, 0), /not found/u);
    assert.throws(() => manager.read("owner", sessionId, 999999), /cursor/u);
    manager.stop("owner", sessionId);
    await waitFor(() => manager.read("owner", sessionId, 0).finished);
  } finally { await manager.close(); }
});

test("stop terminates the shell and its children", { skip: !supported }, async () => {
  const manager = new OwnerTerminalSessionManager({ enabled: true });
  try {
    const { sessionId } = await manager.start("owner", { ...base, cwd: "/tmp" });
    const out = collector(manager, "owner", sessionId);
    manager.write("owner", sessionId, "sleep 301 & echo CHILD:$!\n");
    await waitFor(() => { out.poll(); return /CHILD:\d+/u.test(out.text); });
    const pid = Number(/CHILD:(\d+)/u.exec(out.text)![1]);
    manager.stop("owner", sessionId);
    await waitFor(() => manager.read("owner", sessionId, 0).finished);
    await waitFor(() => { try { process.kill(pid, 0); return false; } catch { return true; } });
  } finally { await manager.close(); }
});

test("revocation, idle timeout and lifetime end a live session", { skip: !supported }, async () => {
  const manager = new OwnerTerminalSessionManager({ enabled: true, maxSessions: 3 });
  try {
    let revoked = false;
    const a = await manager.start("owner", { ...base, cwd: "/tmp", shouldCancel: () => revoked });
    revoked = true;
    await waitFor(() => manager.read("owner", a.sessionId, 0).finished, 15_000);
    assert.equal(manager.read("owner", a.sessionId, 0).state, "cancelled");

    const b = await manager.start("owner", { ...base, cwd: "/tmp", idleTimeoutMs: 1_000 });
    await delay(1_200);
    await waitFor(() => manager.read("owner", b.sessionId, 0).finished, 15_000);
    assert.equal(manager.read("owner", b.sessionId, 0).state, "cancelled");

    const c = await manager.start("owner", { ...base, cwd: "/tmp", lifetimeMs: 2_000, idleTimeoutMs: 2_000 });
    for (let i = 0; i < 3; i += 1) { await delay(500); manager.write("owner", c.sessionId, " \n"); }
    await waitFor(() => manager.read("owner", c.sessionId, 0).finished, 15_000);
    assert.equal(manager.read("owner", c.sessionId, 0).state, "timed_out");
  } finally { await manager.close(); }
});

test("output ring reports dropped bytes and capacity is enforced", { skip: !supported }, async () => {
  const manager = new OwnerTerminalSessionManager({ enabled: true, maxSessions: 1 });
  try {
    const { sessionId } = await manager.start("owner", { ...base, cwd: "/tmp" });
    await assert.rejects(manager.start("owner", { ...base, cwd: "/tmp" }), /capacity/u);
    manager.write("owner", sessionId, "head -c 600000 /dev/zero | tr '\\0' 'a'; echo; echo DONE_MARK\n");
    // Do not read until the output has overflowed the ring.
    await delay(3_000);
    const first = manager.read("owner", sessionId, 0);
    assert.ok(first.droppedBytes > 0, "oldest bytes must be reported as dropped");
    assert.ok(first.data.length <= 65_536);
    let cursor = first.nextCursor;
    let text = first.data;
    await waitFor(() => { const r = manager.read("owner", sessionId, cursor); cursor = r.nextCursor; text += r.data; return text.includes("DONE_MARK"); }, 20_000);
    manager.stop("owner", sessionId);
  } finally { await manager.close(); }
});

test("session shell PATH ends with the owner's user bin directory", { skip: !supported }, async () => {
  const manager = new OwnerTerminalSessionManager({ enabled: true });
  try {
    const { sessionId } = await manager.start("owner", { ...base, cwd: "/tmp" });
    const out = collector(manager, "owner", sessionId);
    // The split marker keeps the echoed command line from matching the pattern.
    manager.write("owner", sessionId, "print -r -- \"P\"\"ATH_IS:$PATH:END\"\n");
    await waitFor(() => { out.poll(); return /PATH_IS:\S+:END\r?\n/u.test(out.text); });
    const path = /PATH_IS:(\S+):END\r?\n/u.exec(out.text)![1]!;
    assert.ok(path.startsWith("/opt/homebrew/bin:"), path);
    assert.ok(path.endsWith(`${homedir()}/.local/bin`), path);
    manager.stop("owner", sessionId);
  } finally { await manager.close(); }
});
