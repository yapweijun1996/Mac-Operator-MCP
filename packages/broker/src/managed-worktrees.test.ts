import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { ManagedWorktrees } from "./managed-worktrees.js";
import { ProcessSupervisor } from "./process-supervisor.js";
import { SAFE_GIT_ENVIRONMENT } from "./git-inspector.js";
import { GitStatusInspector, GitWriteInspectorImpl } from "./git-inspector.js";

const control = { timeoutMs: 30_000, shouldCancel: () => false };
const authority = () => undefined;
function git(cwd: string, args: string[]): string {
  return execFileSync("/usr/bin/git", args, { cwd, encoding: "utf8", env: { GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null", GIT_TERMINAL_PROMPT: "0" } });
}
export async function worktreeFixture(supervisor?: ConstructorParameters<typeof ManagedWorktrees>[2]) {
  const temporary = await mkdtemp(join(tmpdir(), "mac-development-gateway-"));
  const root = await realpath(temporary);
  const project = join(root, "project");
  const state = join(root, "state");
  const trees = join(root, "trees");
  for (const path of [project, state, trees]) await mkdir(path, { mode: 0o700 });
  git(project, ["init", "-b", "main"]);
  git(project, ["config", "user.name", "Gateway Test"]);
  git(project, ["config", "user.email", "gateway@example.invalid"]);
  await writeFile(join(project, "source.txt"), "original\n");
  await writeFile(join(project, ".gitignore"), "ignored.txt\n");
  git(project, ["add", "--", "source.txt", ".gitignore"]);
  git(project, ["commit", "-m", "Fixture baseline"]);
  const registry = new ManagedWorktrees(state, trees, supervisor);
  const create = (taskId = "task-1", overrides = {}) => registry.create({ projectRoot: project, branchName: `codex/${taskId}`,
    baseRef: "HEAD", taskId, idempotencyKey: `key-${taskId}`, owner: "owner", ...overrides }, control, authority);
  return { root, project, state, trees, registry, create,
    cleanup: async () => { await registry.close(); await rm(root, { force: true, recursive: true }); } };
}

test("managed worktree creation is idempotent and preserves primary HEAD, index and content", async () => {
  const f = await worktreeFixture();
  try {
    const head = git(f.project, ["rev-parse", "HEAD"]);
    const index = await readFile(join(f.project, ".git", "index"));
    const created = await f.create();
    assert.equal(created.reused, false);
    const again = await f.create();
    assert.equal(again.reused, true);
    assert.equal(again.record.worktree, created.record.worktree);
    await writeFile(join(created.record.worktree, "source.txt"), "isolated edit\n");
    const inspector = new GitStatusInspector(undefined, f.registry.resolveGitMetadata);
    assert.equal((await inspector.status(created.record.worktree, true, control)).dirty, true);
    const writer = new GitWriteInspectorImpl(undefined, f.registry.resolveGitMetadata);
    const staged = await writer.stage(created.record.worktree, ["source.txt"], control);
    const committed = await writer.commit(created.record.worktree, "Synthetic isolated change", staged.stagedDiffSha256, control);
    assert.match(committed.commitId, /^[a-f0-9]{40}$/u);
    assert.equal(git(f.project, ["rev-parse", "HEAD"]), head);
    assert.deepEqual(await readFile(join(f.project, ".git", "index")), index);
    assert.equal(await readFile(join(f.project, "source.txt"), "utf8"), "original\n");
    assert.equal(git(f.project, ["status", "--porcelain"]), "");
    assert.equal(f.registry.list(f.project, "owner").length, 1);
    assert.equal(f.registry.list(f.project, "intruder").length, 0);
    assert.throws(() => f.registry.require(created.record.worktree, f.project, "intruder"), /not owned/u);
  } finally { await f.cleanup(); }
});

test("worktree retry conflicts and protected branch/ref/traversal requests fail closed", async () => {
  const f = await worktreeFixture();
  try {
    await f.create();
    await assert.rejects(f.create("task-1", { branchName: "codex/different" }), /retry key/u);
    for (const overrides of [{ branchName: "main" }, { branchName: "codex/../escape" }, { baseRef: "--exec=whoami" },
      { projectRoot: `${f.project}/../project` }, { taskId: "../escape" }]) {
      await assert.rejects(f.create("task-bad", overrides));
    }
    await assert.rejects(f.create("task-1", { idempotencyKey: "new-key" }), /already has/u);
  } finally { await f.cleanup(); }
});

test("unmanaged linked worktrees and modified pointers cannot acquire Git authority", async () => {
  const f = await worktreeFixture();
  try {
    const created = await f.create();
    const path = created.record.worktree;
    await assert.rejects(new GitStatusInspector().status(path, true, control), /managed worktree/u);
    await writeFile(join(path, ".git"), `gitdir: ${join(f.project, ".git")}\n`);
    assert.throws(() => f.registry.require(path, f.project, "owner"), /metadata changed/u);
  } finally { await f.cleanup(); }
});

test("worktree removal rejects dirt, ignored files, primary and active jobs; clean removal verifies", async () => {
  const f = await worktreeFixture();
  try {
    const { record } = await f.create();
    const remove = (active = false) => f.registry.remove(f.project, record.worktree, "owner", record.taskId, control, authority, () => active);
    await assert.rejects(remove(true), /active/u);
    await assert.rejects(f.registry.remove(f.project, f.project, "owner", record.taskId, control, authority, () => false), /not owned/u);
    await writeFile(join(record.worktree, "ignored.txt"), "preserve me\n");
    await assert.rejects(remove(), /including ignored/u);
    await rm(join(record.worktree, "ignored.txt"));
    await writeFile(join(record.worktree, "source.txt"), "dirty\n");
    await assert.rejects(remove(), /clean status/u);
    await writeFile(join(record.worktree, "source.txt"), "original\n");
    const removal = await remove();
    assert.deepEqual(removal, { branchName: "codex/task-1", branchDeleted: true });
    assert.equal(git(f.project, ["branch", "--list", "codex/task-1"]), "");
    assert.equal(f.registry.list(f.project, "owner").length, 0);
  } finally { await f.cleanup(); }
});

test("worktree removal deletes a merged task branch but keeps one with unmerged commits", async () => {
  const f = await worktreeFixture();
  try {
    const kept = await f.create("task-keep");
    await writeFile(join(kept.record.worktree, "source.txt"), "unmerged work\n");
    const writer = new GitWriteInspectorImpl(undefined, f.registry.resolveGitMetadata);
    const staged = await writer.stage(kept.record.worktree, ["source.txt"], control);
    await writer.commit(kept.record.worktree, "Unmerged task commit", staged.stagedDiffSha256, control);
    const keptHead = git(f.project, ["rev-parse", "codex/task-keep"]);
    const removal = await f.registry.remove(f.project, kept.record.worktree, "owner", kept.record.taskId, control, authority, () => false, "remove-keep");
    assert.equal(removal.branchDeleted, false);
    assert.match(removal.branchNote ?? "", /was kept because git branch -d refused/u);
    assert.equal(git(f.project, ["rev-parse", "codex/task-keep"]), keptHead);
    assert.equal(f.registry.list(f.project, "owner").length, 0);
    // A retry of the completed removal re-reports the kept branch instead of failing or deleting it.
    const retry = await f.registry.remove(f.project, kept.record.worktree, "owner", kept.record.taskId, control, authority, () => false, "remove-keep");
    assert.equal(retry.branchDeleted, false);
    assert.equal(git(f.project, ["rev-parse", "codex/task-keep"]), keptHead);
    // The primary checkout and its own branch are untouched.
    assert.equal(git(f.project, ["rev-parse", "--abbrev-ref", "HEAD"]).trim(), "main");
    assert.equal(git(f.project, ["status", "--porcelain"]), "");
  } finally { await f.cleanup(); }
});

test("removing one worktree does not invalidate the others although git rewrites .git/config", async () => {
  const f = await worktreeFixture();
  try {
    const stays = await f.create("task-stays");
    const goes = await f.create("task-goes");
    const configBefore = await stat(join(f.project, ".git", "config"));
    await f.registry.remove(f.project, goes.record.worktree, "owner", goes.record.taskId, control, authority, () => false, "remove-goes");
    const configAfter = await stat(join(f.project, ".git", "config"));
    // git branch -d replaces the config file (new inode, same bytes); this is the premise of the regression.
    assert.notEqual(configAfter.ino, configBefore.ino);
    assert.deepEqual(f.registry.list(f.project, "owner").map((entry) => entry.taskId), ["task-stays"]);
    assert.equal(f.registry.require(stays.record.worktree, f.project, "owner", "task-stays").taskId, "task-stays");
    // A real change of the repository configuration is still rejected.
    git(f.project, ["config", "alias.unsafe", "status"]);
    assert.throws(() => f.registry.list(f.project, "owner"), /Primary project identity changed|configuration/u);
  } finally { await f.cleanup(); }
});

test("concurrent tasks are distinct and worktree provenance survives graceful restart", async () => {
  const f = await worktreeFixture();
  try {
    const [a, b] = await Promise.all([f.create("task-a"), f.create("task-b")]);
    assert.notEqual(a.record.worktree, b.record.worktree);
    await f.registry.close();
    const restored = new ManagedWorktrees(f.state, f.trees);
    try {
      assert.equal(restored.list(f.project, "owner").length, 2);
      assert.equal(restored.require(a.record.worktree, f.project, "owner", "task-a").branchName, "codex/task-a");
      assert.throws(() => restored.require(a.record.worktree, f.project, "owner", "task-b"), /not owned/u);
    } finally { await restored.close(); }
  } finally { await f.cleanup(); }
});

test("symlink storage and a replaced worktree directory fail closed", async () => {
  const f = await worktreeFixture();
  try {
    const alias = join(f.root, "alias");
    await symlink(f.trees, alias);
    assert.throws(() => new ManagedWorktrees(f.state, alias), /canonical/u);
    const { record } = await f.create();
    await rm(record.worktree, { recursive: true });
    await symlink(f.project, record.worktree);
    assert.throws(() => f.registry.require(record.worktree, f.project, "owner"));
  } finally { await f.cleanup(); }
});

test("external Git common directories, ref symlinks and object alternates are rejected before writes", async () => {
  const f = await worktreeFixture();
  try {
    const outside = join(f.root, "outside");
    await mkdir(outside, { mode: 0o700 });
    await writeFile(join(f.project, ".git", "commondir"), outside + "\n");
    await assert.rejects(f.create("common-escape"), /external integration/u);
    await rm(join(f.project, ".git", "commondir"));
    const head = git(f.project, ["rev-parse", "HEAD"]);
    const heads = join(f.project, ".git", "refs", "heads");
    await rm(heads, { recursive: true });
    await symlink(outside, heads);
    await assert.rejects(f.create("refs-escape"), /symlink/u);
    assert.equal(git(f.root, ["version"]).startsWith("git version"), true);
    await assert.rejects(readFile(join(outside, "codex", "refs-escape")));
    await rm(heads); await mkdir(heads);
    await writeFile(join(heads, "main"), head);
    await writeFile(join(f.project, ".git", "objects", "info", "alternates"), outside + "\n");
    await assert.rejects(f.create("object-escape"), /external integration/u);
  } finally { await f.cleanup(); }
});

test("managed HEAD cannot be redirected to primary branch before stage or commit", async () => {
  const f = await worktreeFixture();
  try {
    const { record } = await f.create();
    const before = git(f.project, ["rev-parse", "HEAD"]);
    await writeFile(join(record.gitDirectory, "HEAD"), "ref: refs/heads/main\n");
    assert.throws(() => f.registry.require(record.worktree, f.project, "owner"), /metadata changed/u);
    await assert.rejects(new GitWriteInspectorImpl(undefined, f.registry.resolveGitMetadata).stage(record.worktree, ["source.txt"], control));
    assert.equal(git(f.project, ["rev-parse", "HEAD"]), before);
  } finally { await f.cleanup(); }
});

test("revocation after worktree add retains pending quarantine rather than in-memory active authority", async () => {
  const f = await worktreeFixture();
  try {
    let checks = 0;
    await assert.rejects(f.registry.create({ projectRoot: f.project, branchName: "codex/revoked", baseRef: "HEAD",
      taskId: "revoked", idempotencyKey: "revoked-key", owner: "owner" }, control,
      () => { if (++checks >= 3) throw new Error("Authority revoked"); }), /revoked/u);
    assert.equal(f.registry.list(f.project, "owner").length, 0);
    await assert.rejects(f.create("revoked", { idempotencyKey: "revoked-key" }), /different operation|reconciliation/u);
    // The refusal names the task and state and stays UNKNOWN_OUTCOME: the pending checkout may still exist.
    await assert.rejects(f.create("revoked", { idempotencyKey: "revoked-key" }), (error: unknown) => {
      assert.ok(error instanceof BrokerError);
      assert.equal(error.errorClass, "UNKNOWN_OUTCOME");
      assert.match(error.message, /reconciliation.*task revoked.*is pending/u);
      return true;
    });
    await assert.rejects(f.create("revoked", { idempotencyKey: "other-key" }), /already has a managed worktree: task revoked \(branch codex\/revoked, state pending\)/u);
    assert.deepEqual(await f.registry.unresolved(f.project, "owner"), [{ taskId: "revoked", state: "pending" }]);
    assert.deepEqual(await f.registry.unresolved(f.project, "intruder"), []);
  } finally { await f.cleanup(); }
});

test("crash-left inventory lock is reclaimed only after native process identity is absent", async () => {
  const f = await worktreeFixture();
  try {
    await f.registry.close();
    const module = new URL("./managed-worktrees.js", import.meta.url).href;
    execFileSync(process.execPath, ["--input-type=module", "-e", `import { ManagedWorktrees } from ${JSON.stringify(module)}; new ManagedWorktrees(${JSON.stringify(f.state)}, ${JSON.stringify(f.trees)});`], { env: {}, encoding: "utf8" });
    const restored = new ManagedWorktrees(f.state, f.trees);
    try { assert.deepEqual(restored.list(f.project, "owner"), []); }
    finally { await restored.close(); }
  } finally { await f.cleanup(); }
});

test("task branch shared with primary or another checkout is rejected before Git mutation", async () => {
  const f = await worktreeFixture();
  try {
    const { record } = await f.create(); const before = git(f.project, ["rev-parse", "HEAD"]);
    await writeFile(join(f.project, ".git", "HEAD"), `ref: refs/heads/${record.branchName}\n`);
    assert.throws(() => f.registry.require(record.worktree, f.project, "owner"), /primary/u);
    await assert.rejects(new GitWriteInspectorImpl(undefined, f.registry.resolveGitMetadata).stage(record.worktree, ["source.txt"], control), /primary/u);
    assert.equal(git(f.project, ["rev-parse", "HEAD"]), before);
    await writeFile(join(f.project, ".git", "HEAD"), "ref: refs/heads/main\n");
    const other = join(f.root, "other"); git(f.project, ["worktree", "add", "--force", other, record.branchName]);
    assert.throws(() => f.registry.require(record.worktree, f.project, "owner"), /another checkout/u);
  } finally { await f.cleanup(); }
});

test("repeated close cannot release a restarted inventory lock", async () => {
  const f = await worktreeFixture();
  try {
    await f.registry.close(); const restarted = new ManagedWorktrees(f.state, f.trees);
    try { await f.registry.close(); assert.throws(() => new ManagedWorktrees(f.state, f.trees), /live or unknown/u); }
    finally { await restarted.close(); }
  } finally { await f.cleanup(); }
});

function inventory(f: Awaited<ReturnType<typeof worktreeFixture>>): Array<{ idempotencyKey: string; state: string; removalKey: string }> {
  return JSON.parse(readFileSync(join(f.state, "worktrees.json"), "utf8"));
}
function brokerFailure(errorClass: string, pattern: RegExp) {
  return (error: unknown): boolean => {
    assert.ok(error instanceof BrokerError);
    assert.equal(error.errorClass, errorClass);
    assert.match(error.message, pattern);
    assert.ok(error.message.length < 512, `message is ${error.message.length} characters`);
    return true;
  };
}

test("a task re-created after removal is removable again and stale removal keys never reach it", async () => {
  const f = await worktreeFixture();
  try {
    const remove = (worktree: string, key: string) => f.registry.remove(f.project, worktree, "owner", "task-1", control, authority, () => false, key);
    const first = await f.create("task-1");
    assert.deepEqual(await remove(first.record.worktree, "rm-1"), { branchName: "codex/task-1", branchDeleted: true });
    // Before any re-create, a retry of the completed removal only re-attempts the branch cleanup.
    assert.deepEqual(await remove(first.record.worktree, "rm-1"), { branchName: "codex/task-1", branchDeleted: true });
    const second = await f.create("task-1", { idempotencyKey: "key-task-1-again" });
    assert.equal(second.reused, false);
    assert.equal(second.record.worktree, first.record.worktree);
    // The path is deterministic per task, so the stale key now points at a checkout that was created after it.
    const stale = brokerFailure("CONFLICT", /^IDEMPOTENCY_KEY_IN_USE: .*earlier worktree for task task-1.*created later.*new idempotency_key/u);
    await assert.rejects(remove(second.record.worktree, "rm-1"), stale);
    assert.throws(() => f.registry.removalRetry(f.project, second.record.worktree, "owner", "task-1", "rm-1"), stale);
    assert.equal(existsSync(second.record.worktree), true);
    assert.equal(f.registry.list(f.project, "owner").length, 1);
    assert.deepEqual(inventory(f).map((entry) => entry.state), ["removed", "active"]);
    // A fresh key removes the new checkout and leaves the first record's tombstone untouched.
    assert.equal(f.registry.removalRetry(f.project, second.record.worktree, "owner", "task-1", "rm-2"), false);
    assert.deepEqual(await remove(second.record.worktree, "rm-2"), { branchName: "codex/task-1", branchDeleted: true });
    assert.equal(existsSync(second.record.worktree), false);
    assert.equal(f.registry.list(f.project, "owner").length, 0);
    assert.deepEqual(inventory(f).map((entry) => [entry.idempotencyKey, entry.state, entry.removalKey]),
      [["key-task-1", "removed", "rm-1"], ["key-task-1-again", "removed", "rm-2"]]);
    // With nothing live at the path, each key replays only its own completed removal.
    assert.equal(f.registry.removalRetry(f.project, second.record.worktree, "owner", "task-1", "rm-1"), true);
    assert.equal(f.registry.removalRetry(f.project, second.record.worktree, "owner", "task-1", "rm-2"), true);
    await assert.rejects(remove(second.record.worktree, "rm-3"), /another retry key/u);
  } finally { await f.cleanup(); }
});

test("a removal that did not finish blocks every key for the task and is reported as unresolved", async () => {
  const f = await worktreeFixture();
  try {
    const remove = (worktree: string, key: string) => f.registry.remove(f.project, worktree, "owner", "task-1", control, authority, () => false, key);
    const first = await f.create("task-1");
    await remove(first.record.worktree, "rm-1");
    const second = await f.create("task-1", { idempotencyKey: "key-task-1-again" });
    // A locked worktree makes `git worktree remove` fail after the record was persisted as removing.
    git(f.project, ["worktree", "lock", second.record.worktree]);
    await assert.rejects(remove(second.record.worktree, "rm-2"), /Fixed worktree Git operation failed/u);
    assert.deepEqual(inventory(f).map((entry) => entry.state), ["removed", "removing"]);
    // Rule (i) looks at every record: even the key that completed the earlier removal reports the unresolved outcome.
    for (const key of ["rm-1", "rm-2", "rm-3"]) {
      await assert.rejects(remove(second.record.worktree, key), brokerFailure("UNKNOWN_OUTCOME", /requires operator reconciliation/u));
    }
    assert.deepEqual(await f.registry.unresolved(f.project, "owner"), [{ taskId: "task-1", state: "removing" }]);
    await assert.rejects(f.create("task-1", { idempotencyKey: "key-task-1-again" }),
      brokerFailure("UNKNOWN_OUTCOME", /reconciliation.*task task-1 \(branch codex\/task-1\) is removing/u));
  } finally { await f.cleanup(); }
});

test("duplicate create keys name the holder and a removed worktree's key is a conflict, not an unknown outcome", async () => {
  const f = await worktreeFixture();
  try {
    const created = await f.create("task-1");
    await assert.rejects(f.create("task-1", { branchName: "codex/different" }),
      brokerFailure("CONFLICT", /retry key.*held by task task-1 \(branch codex\/task-1, state active\)/u));
    await assert.rejects(f.create("task-1", { idempotencyKey: "new-key" }),
      brokerFailure("CONFLICT", /already has a managed worktree: task task-1 \(branch codex\/task-1, state active\)/u));
    await f.registry.remove(f.project, created.record.worktree, "owner", "task-1", control, authority, () => false, "rm-1");
    const reuse = brokerFailure("CONFLICT", /^IDEMPOTENCY_KEY_IN_USE: .*created the worktree for task task-1 \(branch codex\/task-1\).*later removed.*new idempotency_key.*can be created again/u);
    await assert.rejects(f.create("task-1"), reuse);
    await assert.rejects(f.create("task-1", { branchName: "codex/different" }), brokerFailure("CONFLICT", /retry key.*state removed/u));
    // The task id and branch name are free again under a new key.
    assert.equal((await f.create("task-1", { idempotencyKey: "key-task-1-again" })).reused, false);
  } finally { await f.cleanup(); }
});

test("create refuses an existing branch before any pending record or inventory slot exists", async () => {
  const f = await worktreeFixture();
  try {
    git(f.project, ["branch", "codex/task-taken"]);
    await assert.rejects(f.create("task-taken"), brokerFailure("CONFLICT", /^Branch codex\/task-taken already exists; choose another branch_name$/u));
    assert.equal(existsSync(join(f.state, "worktrees.json")), false);
    assert.deepEqual(await f.registry.unresolved(f.project, "owner"), []);
    // Same key and task succeed once the branch is gone, which a leftover pending record would have blocked.
    git(f.project, ["branch", "-D", "codex/task-taken"]);
    assert.equal((await f.create("task-taken")).reused, false);
    assert.deepEqual(inventory(f).map((entry) => entry.state), ["active"]);
  } finally { await f.cleanup(); }
});

test("removal refusals for unclean worktrees report path counts and the commit remedy without naming files", async () => {
  const f = await worktreeFixture();
  try {
    const { record } = await f.create();
    const remove = () => f.registry.remove(f.project, record.worktree, "owner", record.taskId, control, authority, () => false, "rm-clean");
    const refused = (counts: string) => (error: unknown): boolean => {
      brokerFailure("POLICY_DENIED", /clean status/u)(error);
      const message = (error as BrokerError).message;
      assert.match(message, /including ignored/u);
      assert.ok(message.includes(`Paths found: ${counts} (names are not shown)`), message);
      assert.match(message, /committed with mac_git_stage and mac_git_commit \(the task branch is then kept\); ignored files cannot be removed by any tool/u);
      assert.doesNotMatch(message, /source\.txt|\.env|ignored\.txt|Fixed worktree Git operation failed/u);
      return true;
    };
    await writeFile(join(record.worktree, "source.txt"), "dirty\n");
    await assert.rejects(remove(), refused("staged 0, unstaged 1, untracked 0, ignored 0"));
    git(record.worktree, ["add", "--", "source.txt"]);
    await assert.rejects(remove(), refused("staged 1, unstaged 0, untracked 0, ignored 0"));
    git(record.worktree, ["reset", "-q", "--", "source.txt"]);
    await writeFile(join(record.worktree, "source.txt"), "original\n");
    await writeFile(join(record.worktree, ".env.local"), "SECRET=1\n");
    await assert.rejects(remove(), refused("staged 0, unstaged 0, untracked 1, ignored 0"));
    await rm(join(record.worktree, ".env.local"));
    await writeFile(join(record.worktree, "ignored.txt"), "preserve me\n");
    await assert.rejects(remove(), refused("staged 0, unstaged 0, untracked 0, ignored 1"));
    await rm(join(record.worktree, "ignored.txt"));
    assert.equal((await remove()).branchDeleted, true);
  } finally { await f.cleanup(); }
});

test("listings beyond the Git output cap are the same refusal instead of a generic Git failure", async () => {
  const f = await worktreeFixture();
  try {
    const { record } = await f.create();
    const remove = () => f.registry.remove(f.project, record.worktree, "owner", record.taskId, control, authority, () => false, "rm-big");
    const refused = (counts: string) => (error: unknown): boolean => {
      brokerFailure("POLICY_DENIED", /clean status.*including ignored/u)(error);
      assert.ok((error as BrokerError).message.includes(`Paths found: ${counts} (names are not shown)`), (error as BrokerError).message);
      assert.doesNotMatch((error as BrokerError).message, /Fixed worktree Git operation failed/u);
      return true;
    };
    // 1100 directories with 240-character names push each listing past its cap (131072 bytes for ignored, 262144 for status).
    const directories = Array.from({ length: 1100 }, (_, index) => join(record.worktree, `${String(index).padStart(4, "0")}${"d".repeat(236)}`));
    for (const directory of directories) { await mkdir(directory); await writeFile(join(directory, "ignored.txt"), "x"); }
    await assert.rejects(remove(), refused("staged 0, unstaged 0, untracked 0, ignored over the output limit"));
    for (const directory of directories) await writeFile(join(directory, "untracked.txt"), "x");
    await assert.rejects(remove(), refused("staged over the output limit, unstaged over the output limit, untracked over the output limit, ignored over the output limit"));
    assert.equal(existsSync(record.worktree), true);
    assert.deepEqual(inventory(f).map((entry) => entry.state), ["active"]);
  } finally { await f.cleanup(); }
});

test("ownedWorktreeContaining matches only the owner's active worktree and never a name-prefix sibling", async () => {
  const f = await worktreeFixture();
  try {
    const { record } = await f.create("task-1");
    const owned = (path: string, owner = "owner") => f.registry.ownedWorktreeContaining(path, owner);
    assert.equal(owned(record.worktree), true);
    assert.equal(owned(join(record.worktree, "source.txt")), true);
    assert.equal(owned(join(record.worktree, "missing", "deep.txt")), true);
    assert.equal(owned(`${record.worktree}/../${basename(record.worktree)}/source.txt`), true);
    // A sibling whose name only extends the worktree's name is not inside it, and neither is a path that climbs out.
    assert.equal(owned(`${record.worktree}0`), false);
    assert.equal(owned(join(`${record.worktree}0`, "source.txt")), false);
    assert.equal(owned(`${record.worktree}/../escape.txt`), false);
    assert.equal(owned(f.trees), false);
    assert.equal(owned(join(f.state, "broker.sqlite")), false);
    assert.equal(owned(join(f.project, "source.txt")), false);
    assert.equal(owned(join(record.worktree, "source.txt"), "intruder"), false);
    const second = await f.create("task-10");
    assert.equal(owned(join(second.record.worktree, "source.txt")), true);
    assert.equal(owned(join(second.record.worktree, "source.txt"), "intruder"), false);
    await f.registry.remove(f.project, record.worktree, "owner", record.taskId, control, authority, () => false);
    assert.equal(owned(join(record.worktree, "source.txt")), false);
    assert.equal(owned(join(second.record.worktree, "source.txt")), true);
  } finally { await f.cleanup(); }
});

test("branch pre-flight compares exact refs and refuses either direction of a ref directory/file conflict before any record exists", async () => {
  const f = await worktreeFixture();
  try {
    git(f.project, ["branch", "codex/df"]);
    git(f.project, ["branch", "codex/pre/x"]);
    // An existing parent ref blocks a child: `worktree add -b` would fail with a D/F conflict after the pending record was pushed.
    await assert.rejects(f.create("child", { branchName: "codex/df/x" }),
      brokerFailure("CONFLICT", /^Branch codex\/df\/x cannot be created because branch codex\/df already exists; choose another branch_name$/u));
    // An existing child ref blocks the parent, which a prefix match would have reported as "already exists".
    await assert.rejects(f.create("parent", { branchName: "codex/pre" }),
      brokerFailure("CONFLICT", /^Branch codex\/pre cannot be created because branches below codex\/pre\/ already exist; choose another branch_name$/u));
    await assert.rejects(f.create("same", { branchName: "codex/df" }), brokerFailure("CONFLICT", /^Branch codex\/df already exists; choose another branch_name$/u));
    assert.equal(existsSync(join(f.state, "worktrees.json")), false);
    assert.deepEqual(await f.registry.unresolved(f.project, "owner"), []);
    // A sibling that merely shares a name prefix is free, and the same keys succeed afterwards.
    assert.equal((await f.create("child", { branchName: "codex/df-other" })).reused, false);
    assert.equal((await f.create("parent", { branchName: "codex/prefix" })).reused, false);
    assert.deepEqual(inventory(f).map((entry) => entry.state), ["active", "active"]);
    // Branch cleanup after removal also compares exactly: a nested ref created later is not mistaken for the task branch.
    const removed = await f.registry.remove(f.project, (await f.create("child", { branchName: "codex/df-other" })).record.worktree, "owner", "child", control, authority, () => false, "rm-child");
    assert.equal(removed.branchDeleted, true);
  } finally { await f.cleanup(); }
});

test("unresolved waits for an in-flight create or remove and still reports a record that is really stuck", async () => {
  const real = new ProcessSupervisor({ maxConcurrent: 2, requireRootOwnedExecutable: true, allowedEnvironmentKeys: Object.keys(SAFE_GIT_ENVIRONMENT) });
  let gate: Promise<void> | undefined;
  let entered: (() => void) | undefined;
  const supervisor = { run: async (request: Parameters<typeof real.run>[0]) => {
    const args = request.args ?? [];
    if (gate && (args.includes("add") || args.includes("remove")) && args.includes("worktree")) { entered?.(); await gate; }
    return real.run(request);
  } };
  const f = await worktreeFixture(supervisor);
  try {
    const hold = (): { release: () => void; reached: Promise<void> } => {
      let release!: () => void;
      gate = new Promise<void>((resolve) => { release = resolve; });
      const reached = new Promise<void>((resolve) => { entered = resolve; });
      return { release, reached };
    };
    // During a healthy create the record is pending; the listing waits for it instead of warning.
    const creating = hold();
    const create = f.create("task-live");
    await creating.reached;
    assert.equal(inventory(f)[0]?.state, "pending");
    let reported: readonly unknown[] | undefined;
    const listing = f.registry.unresolved(f.project, "owner").then((value) => { reported = value; });
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(reported, undefined, "unresolved must not read the record while the create is in flight");
    creating.release();
    await create; await listing;
    assert.deepEqual(reported, []);
    // The same during a healthy remove.
    const record = f.registry.list(f.project, "owner")[0]!;
    const removing = hold();
    const remove = f.registry.remove(f.project, record.worktree, "owner", "task-live", control, authority, () => false, "rm-live");
    await removing.reached;
    assert.equal(inventory(f)[0]?.state, "removing");
    reported = undefined;
    const listing2 = f.registry.unresolved(f.project, "owner").then((value) => { reported = value; });
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(reported, undefined);
    removing.release();
    await remove; await listing2;
    assert.deepEqual(reported, []);
    // Once the operation has finished or failed, a record left behind is still reported.
    gate = undefined;
    let checks = 0;
    await assert.rejects(f.registry.create({ projectRoot: f.project, branchName: "codex/stuck", baseRef: "HEAD", taskId: "stuck", idempotencyKey: "stuck-key", owner: "owner" },
      control, () => { if (++checks >= 3) throw new Error("Authority revoked"); }), /revoked/u);
    assert.deepEqual(await f.registry.unresolved(f.project, "owner"), [{ taskId: "stuck", state: "pending" }]);
  } finally { gate = undefined; await f.cleanup(); }
});
