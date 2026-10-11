import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { mkdtemp, realpath, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { GitPushInspectorImpl, isProtectedBranch, noPushReason, validateGitPushInput, type GitPushInput } from "./git-push.js";
import { SAFE_GIT_ENVIRONMENT } from "./git-inspector.js";
import { ProcessSupervisor } from "./process-supervisor.js";

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

/** Real Git through the real supervisor, with hooks at the two moments an owner could still change the checkout. */
function inspectorWithHooks(f: Fixture, hooks: {
  afterFirstRemoteRead?: () => void | Promise<void>;
  beforePushSpawn?: () => void;
  endpoints?: string[];
}): GitPushInspectorImpl {
  const real = new ProcessSupervisor({ maxConcurrent: 1, allowedEnvironmentKeys: [...Object.keys(SAFE_GIT_ENVIRONMENT), "GIT_ALLOW_PROTOCOL"] });
  let remoteReads = 0;
  const supervisor = {
    close: () => real.close(),
    run: async (request: Parameters<ProcessSupervisor["run"]>[0]) => {
      if (request.args.includes("push")) hooks.beforePushSpawn?.();
      const result = await real.run(request);
      if (request.args.includes("ls-remote") && ++remoteReads === 1) await hooks.afterFirstRemoteRead?.();
      return result;
    }
  };
  const allowed = hooks.endpoints ?? [f.bare];
  return new GitPushInspectorImpl({ allowProtocol: "file", endpointAllowed: url => allowed.includes(url), supervisor });
}

test("an opt-out added while the network preflight waits still blocks the push", async () => {
  let mutations = 0;
  const counted = { ...control, beforeMutation: () => { mutations += 1; } };
  await withFixture(async f => {
    const inspector = inspectorWithHooks(f, { afterFirstRemoteRead: () => writeFile(join(f.work, "NO_PUSH"), "") });
    try { await denied(inspector.push(f.input(), counted), "POLICY_DENIED", /NO_PUSH: checkout contains a NO_PUSH file/u); } finally { await inspector.close(); }
    assert.equal(remoteRef(f, "agent/task-1"), undefined);
  });
  await withFixture(async f => {
    const inspector = inspectorWithHooks(f, { afterFirstRemoteRead: () => { git(f.work, "config", "macoperator.nopush", "true"); } });
    // Repository configuration is covered by the project identity guard, which fails closed on any .git/config change.
    try { await denied(inspector.push(f.input(), counted), "POLICY_DENIED", /NO_PUSH|project root changed/u); } finally { await inspector.close(); }
    assert.equal(remoteRef(f, "agent/task-1"), undefined);
  });
  await withFixture(async f => {
    const inspector = inspectorWithHooks(f, { afterFirstRemoteRead: () => { git(f.work, "config", "--add", "macoperator.nopushbranch", "agent/task-1"); } });
    try { await denied(inspector.push(f.input(), counted), "POLICY_DENIED", /NO_PUSH|project root changed/u); } finally { await inspector.close(); }
    assert.equal(remoteRef(f, "agent/task-1"), undefined);
  });
  assert.equal(mutations, 0, "no mutation may start once the checkout opted out");
});

test("a NO_PUSH file that appears right before the push process starts still blocks it", () => withFixture(async f => {
  let mutations = 0;
  const inspector = inspectorWithHooks(f, { beforePushSpawn: () => { writeFileSync(join(f.work, "NO_PUSH"), ""); } });
  try {
    await denied(inspector.push(f.input(), { ...control, beforeMutation: () => { mutations += 1; } }), "POLICY_DENIED", /NO_PUSH/u);
  } finally { await inspector.close(); }
  assert.equal(mutations, 0);
  assert.equal(remoteRef(f, "agent/task-1"), undefined);
}));

test("a push destination changed while the preflight waits is never pushed to", () => withFixture(async f => {
  const other = join(f.root, "other.git");
  git(f.root, "init", "--bare", "--initial-branch=main", other);
  const inspector = inspectorWithHooks(f, { endpoints: [f.bare, other],
    afterFirstRemoteRead: () => { git(f.work, "remote", "set-url", "--push", "origin", other); } });
  try {
    // The project identity guard covers .git/config, so a changed remote fails closed before any push.
    await denied(inspector.push(f.input(), control), "POLICY_DENIED", /project root changed/u);
  } finally { await inspector.close(); }
  assert.equal(remoteRef(f, "agent/task-1"), undefined);
  const otherRef = (() => { try { return git(other, "rev-parse", "--verify", "refs/heads/agent/task-1"); } catch { return undefined; } })();
  assert.equal(otherRef, undefined, "the replacement origin never received the branch");
}));

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
