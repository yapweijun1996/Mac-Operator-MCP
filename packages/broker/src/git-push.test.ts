import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, realpath, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { GitPushInspectorImpl, isProtectedBranch, noPushReason, validateGitPushInput, type GitPushInput } from "./git-push.js";

const GIT_ENV = { PATH: "/usr/bin:/bin", HOME: "/nonexistent", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid" };
const git = (cwd: string, ...args: string[]) => execFileSync("/usr/bin/git", args, { cwd, env: GIT_ENV, encoding: "utf8" }).trim();
const control = { timeoutMs: 20_000, shouldCancel: () => false, beforeMutation: () => undefined };

interface Fixture { root: string; work: string; bare: string; head: string; inspector: GitPushInspectorImpl; input(overrides?: Partial<GitPushInput>): GitPushInput }

/** Temporary local bare repository as `origin`; nothing here can reach a real remote. */
async function fixture(branch = "agent/task-1"): Promise<Fixture> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mop-push-")));
  const bare = join(root, "origin.git");
  const work = join(root, "work");
  await mkdir(work);
  git(root, "init", "--bare", "--initial-branch=main", bare);
  git(work, "init", "--initial-branch=main");
  await writeFile(join(work, "a.txt"), "one\n");
  git(work, "add", "a.txt");
  git(work, "commit", "-m", "one");
  git(work, "remote", "add", "origin", bare);
  git(work, "checkout", "-b", branch);
  await writeFile(join(work, "a.txt"), "two\n");
  git(work, "commit", "-am", "two");
  const head = git(work, "rev-parse", "HEAD");
  const inspector = new GitPushInspectorImpl({ allowProtocol: "file", endpointAllowed: url => url === bare });
  return { root, work, bare, head, inspector, input: overrides => ({ project_root: work, remote: "origin", branch_name: branch,
    expected_commit: head, idempotency_key: "key-1", ...overrides }) };
}
async function withFixture(run: (f: Fixture) => Promise<void>, branch?: string): Promise<void> {
  const f = await fixture(branch);
  try { await run(f); } finally { await f.inspector.close(); await rm(f.root, { recursive: true, force: true }); }
}
const remoteRef = (f: Fixture, branch: string) => { try { return git(f.bare, "rev-parse", "--verify", `refs/heads/${branch}`); } catch { return undefined; } };
async function denied(promise: Promise<unknown>, code: string, pattern?: RegExp): Promise<void> {
  await assert.rejects(promise, (error: unknown) => error instanceof BrokerError && error.errorClass === code && (!pattern || pattern.test(error.message)));
}

test("pushes the exact approved commit to a local bare origin and reads it back", () => withFixture(async f => {
  const result = await f.inspector.push(f.input(), control);
  assert.deepEqual(result, { remote: "origin", branch_name: "agent/task-1", pushed: true });
  assert.equal(remoteRef(f, "agent/task-1"), f.head);
  assert.equal(await f.inspector.verify(f.input(), control), true);
}));

test("repeating an already-pushed commit is a no-op, not a second push", () => withFixture(async f => {
  await f.inspector.push(f.input(), control);
  let mutations = 0;
  const again = await f.inspector.push(f.input({ idempotency_key: "key-2" }), { ...control, beforeMutation: () => { mutations += 1; } });
  assert.equal(again.pushed, false);
  assert.equal(mutations, 0);
}));

test("protected branches are denied before any remote contact", async () => {
  for (const name of ["main", "master", "release/1.0", "production", "hotfix/x"]) assert.equal(isProtectedBranch(name), true, name);
  for (const name of ["agent/task-1", "feature/main-menu", "codex/task-1"]) assert.equal(isProtectedBranch(name), false, name);
  await withFixture(async f => {
    git(f.work, "checkout", "-b", "release/2.0");
    await denied(f.inspector.push(f.input({ branch_name: "release/2.0" }), control), "POLICY_DENIED", /PROTECTED_BRANCH/u);
    assert.equal(remoteRef(f, "release/2.0"), undefined);
  });
});

test("a NO_PUSH file, macoperator.nopush, or a nopushbranch entry blocks the push", async () => {
  await withFixture(async f => {
    await writeFile(join(f.work, "NO_PUSH"), "");
    await denied(f.inspector.push(f.input(), control), "POLICY_DENIED", /NO_PUSH/u);
    assert.equal(remoteRef(f, "agent/task-1"), undefined);
  });
  await withFixture(async f => {
    git(f.work, "config", "macoperator.nopush", "true");
    await denied(f.inspector.push(f.input(), control), "POLICY_DENIED", /NO_PUSH/u);
    assert.equal(remoteRef(f, "agent/task-1"), undefined);
  });
  await withFixture(async f => {
    git(f.work, "config", "--add", "macoperator.nopushbranch", "agent/task-1");
    await denied(f.inspector.push(f.input(), control), "POLICY_DENIED", /NO_PUSH/u);
    assert.equal(remoteRef(f, "agent/task-1"), undefined);
    // Only the listed branch is blocked.
    git(f.work, "checkout", "-b", "agent/task-2");
    const other = git(f.work, "rev-parse", "HEAD");
    assert.equal((await f.inspector.push(f.input({ branch_name: "agent/task-2", expected_commit: other }), control)).pushed, true);
  });
  assert.equal(noPushReason("macoperator.nopush\nfalse\0", "b", "/nonexistent-root"), undefined);
});

test("force pushes are impossible: a diverged remote branch is never overwritten", () => withFixture(async f => {
  await f.inspector.push(f.input(), control);
  git(f.work, "reset", "--hard", "HEAD~1");
  await writeFile(join(f.work, "a.txt"), "diverged\n");
  git(f.work, "commit", "-am", "diverged");
  const diverged = git(f.work, "rev-parse", "HEAD");
  await assert.rejects(f.inspector.push(f.input({ expected_commit: diverged, idempotency_key: "key-3" }), control));
  assert.equal(remoteRef(f, "agent/task-1"), f.head, "remote keeps the previously pushed commit");
}));

test("a moved HEAD or wrong expected commit changes nothing", () => withFixture(async f => {
  await denied(f.inspector.push(f.input({ expected_commit: "0".repeat(40) }), control), "PRECONDITION_FAILED");
  await denied(f.inspector.push(f.input({ branch_name: "agent/other" }), control), "PRECONDITION_FAILED");
  assert.equal(remoteRef(f, "agent/task-1"), undefined);
  assert.equal(remoteRef(f, "agent/other"), undefined);
}));

test("only the configured origin destination is accepted", async () => {
  await withFixture(async f => {
    const strict = new GitPushInspectorImpl({ allowProtocol: "file" });
    try { await denied(strict.push(f.input(), control), "POLICY_DENIED", /allowed push destination/u); } finally { await strict.close(); }
    git(f.work, "remote", "set-url", "--add", "--push", "origin", join(f.root, "second.git"));
    await denied(f.inspector.push(f.input(), control), "POLICY_DENIED");
    assert.equal(remoteRef(f, "agent/task-1"), undefined);
  });
});

test("live Broker authority is mandatory and repository hooks stay inert", () => withFixture(async f => {
  await denied(f.inspector.push(f.input(), { timeoutMs: 20_000, shouldCancel: () => false }), "POLICY_DENIED", /live Broker authority/u);
  const marker = join(f.root, "hook-ran");
  await mkdir(join(f.work, ".git", "hooks"), { recursive: true });
  await writeFile(join(f.work, ".git", "hooks", "pre-push"), `#!/bin/sh\ntouch ${marker}\n`, { mode: 0o755 });
  await f.inspector.push(f.input(), control);
  assert.equal(existsSync(marker), false);
}));

test("input validation rejects non-origin remotes, extra fields and force-style refs", () => withFixture(async f => {
  const bad: unknown[] = [{ ...f.input(), remote: "upstream" }, { ...f.input(), force: true }, f.input({ branch_name: "+main" }),
    f.input({ branch_name: "a..b" }), f.input({ branch_name: "x.lock" }), f.input({ expected_commit: "HEAD" })];
  for (const value of bad) assert.throws(() => validateGitPushInput(value), (error: unknown) => error instanceof BrokerError);
}));
