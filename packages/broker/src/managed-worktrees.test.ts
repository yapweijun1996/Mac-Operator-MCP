import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ManagedWorktrees } from "./managed-worktrees.js";
import { GitStatusInspector, GitWriteInspectorImpl } from "./git-inspector.js";

const control = { timeoutMs: 30_000, shouldCancel: () => false };
const authority = () => undefined;
function git(cwd: string, args: string[]): string {
  return execFileSync("/usr/bin/git", args, { cwd, encoding: "utf8", env: { GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null", GIT_TERMINAL_PROMPT: "0" } });
}
export async function worktreeFixture() {
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
  const registry = new ManagedWorktrees(state, trees);
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
