import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError, sha256 } from "@mac-operator/contracts";
import {
  GitBranchListInspector, GitDiffInspectorImpl, GitLogInspectorImpl,
  GitStatusInspector, GitWriteInspectorImpl, SAFE_GIT_ENVIRONMENT
} from "./git-inspector.js";
import { ManagedWorktrees } from "./managed-worktrees.js";
import { ProcessSupervisor, type ProcessExecutionRequest } from "./process-supervisor.js";
import { isSafeProcessEnvironmentKey } from "./process-environment.js";

const control = { timeoutMs: 30_000, shouldCancel: () => false };
function git(cwd: string, args: readonly string[]): string {
  return execFileSync("/usr/bin/git", [...args], { cwd, shell: false, encoding: "utf8",
    env: { ...SAFE_GIT_ENVIRONMENT, PATH: "/usr/bin:/bin" }, timeout: 10_000, maxBuffer: 262_144 });
}
function quote(value: string): string { return `'${value.replace(/'/gu, `'"'"'`)}'`; }

test("configured executable hooks never run through actual Git read, worktree and local mutation adapters", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mac-git-hook-isolation-")));
  const project = join(root, "project");
  const state = join(root, "state");
  const trees = join(root, "trees");
  const marker = join(root, "hook-observation.txt");
  let worktrees: ManagedWorktrees | undefined;
  const supervisor = new ProcessSupervisor({ maxConcurrent: 2, requireRootOwnedExecutable: true,
    allowedEnvironmentKeys: Object.keys(SAFE_GIT_ENVIRONMENT) });
  const observed: string[][] = [];
  const tracedSupervisor = { run: (request: ProcessExecutionRequest) => {
    observed.push([...request.args]);
    return supervisor.run(request);
  } };
  try {
    await Promise.all([project, state, trees].map(path => mkdir(path, { mode: 0o700 })));
    await mkdir(join(project, ".githooks"), { mode: 0o700 });
    const hooks = ["pre-commit", "prepare-commit-msg", "commit-msg", "post-commit", "post-checkout", "post-index-change", "reference-transaction"];
    for (const name of hooks) await writeFile(join(project, ".githooks", name),
      `#!/bin/sh\nprintf 'hook\\n' >> ${quote(marker)}\nexit 0\n`, { mode: 0o700 });
    await writeFile(join(project, "source.txt"), "primary source\n", { mode: 0o600 });
    git(project, ["init", "--initial-branch=main"]);
    git(project, ["config", "user.name", "Hook Isolation Test"]);
    git(project, ["config", "user.email", "hooks@example.invalid"]);
    git(project, ["config", "core.hooksPath", ".githooks"]);
    git(project, ["-c", "core.hooksPath=/dev/null", "add", "--", "source.txt", ".githooks"]);
    // Positive control proves the configured hooks are real and executable.
    git(project, ["commit", "-m", "Create hook isolation fixture"]);
    assert.match(await readFile(marker, "utf8"), /hook\n/u);
    await rm(marker);
    const before = {
      head: git(project, ["rev-parse", "HEAD"]),
      index: sha256(await readFile(join(project, ".git", "index"))),
      config: await readFile(join(project, ".git", "config"), "utf8"),
      source: await readFile(join(project, "source.txt"), "utf8")
    };
    assert.equal((await new GitStatusInspector(tracedSupervisor).status(project, true, control)).dirty, false);
    await new GitBranchListInspector(tracedSupervisor).branches(project, true, control);
    await new GitLogInspectorImpl(tracedSupervisor).log(project, 10, undefined, control);
    await new GitDiffInspectorImpl(tracedSupervisor).diff(project, [], false, undefined, 8192, control);
    worktrees = new ManagedWorktrees(state, trees, tracedSupervisor);
    const { record } = await worktrees.create({ projectRoot: project, branchName: "codex/hooks-isolation", baseRef: "main",
      taskId: "hooks-isolation", idempotencyKey: "hooks-isolation", owner: "hook-test-owner" }, control, () => undefined);
    assert.equal((await new GitStatusInspector(tracedSupervisor, worktrees.resolveGitMetadata).status(record.worktree, true, control)).dirty, false);
    await writeFile(join(record.worktree, "source.txt"), "isolated source\n", { mode: 0o600 });
    const writer = new GitWriteInspectorImpl(tracedSupervisor, worktrees.resolveGitMetadata);
    const staged = await writer.stage(record.worktree, ["source.txt"], control);
    assert.deepEqual(staged.stagedPaths, ["source.txt"]);
    const committed = await writer.commit(record.worktree, "Commit without configured hooks", staged.stagedDiffSha256, control);
    assert.match(committed.commitId, /^[a-f0-9]{40}$/u);
    await new GitLogInspectorImpl(tracedSupervisor, worktrees.resolveGitMetadata).log(record.worktree, 10, undefined, control);
    await new GitDiffInspectorImpl(tracedSupervisor, worktrees.resolveGitMetadata).diff(record.worktree, ["source.txt"], false, "main", 8192, control);
    await worktrees.remove(project, record.worktree, "hook-test-owner", record.taskId, control, () => undefined, () => false, "remove-hooks-test");
    await assert.rejects(access(marker), (error: unknown) => (error as NodeJS.ErrnoException).code === "ENOENT");
    assert.equal(git(project, ["rev-parse", "HEAD"]), before.head);
    assert.equal(sha256(await readFile(join(project, ".git", "index"))), before.index);
    assert.equal(await readFile(join(project, ".git", "config"), "utf8"), before.config);
    assert.equal(await readFile(join(project, "source.txt"), "utf8"), before.source);
    assert.equal(git(project, ["-c", "core.hooksPath=/dev/null", "status", "--porcelain=v1"]), "");
    assert.ok(observed.length >= 20);
    for (const args of observed) {
      const hookOverrides = args.filter((arg, index) => args[index - 1] === "-c" && arg.startsWith("core.hooksPath="));
      assert.equal(hookOverrides.at(-1), "core.hooksPath=/dev/null", `Git execution lacks its final hook override: ${args.join(" ")}`);
    }
    for (const command of ["status", "for-each-ref", "log", "diff", "add", "commit", "worktree", "ls-files", "rev-parse", "rev-list"]) {
      assert.ok(observed.some(args => args.includes(command)), `Adapter command was not physically exercised: ${command}`);
    }
  } finally { await worktrees?.close(); await supervisor.close(); await rm(root, { recursive: true, force: true }); }
});

test("partial-clone missing objects cannot execute a remote helper during governed Git reads", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mac-git-lazy-fetch-isolation-")));
  const project = join(root, "project");
  const marker = join(root, "remote-helper-observation.txt");
  try {
    await mkdir(project, { mode: 0o700 });
    await writeFile(join(project, "source.txt"), "original public source\n", { mode: 0o600 });
    git(project, ["init", "--initial-branch=main"]);
    git(project, ["config", "user.name", "Lazy Fetch Isolation Test"]);
    git(project, ["config", "user.email", "lazy-fetch@example.invalid"]);
    git(project, ["add", "--", "source.txt"]);
    git(project, ["commit", "-m", "Create lazy fetch isolation fixture"]);
    const blob = git(project, ["rev-parse", "HEAD:source.txt"]).trim();
    assert.match(blob, /^[a-f0-9]{40}$/u);
    await writeFile(join(project, "source.txt"), "changed public source\n", { mode: 0o600 });
    git(project, ["config", "core.repositoryformatversion", "1"]);
    git(project, ["config", "extensions.partialClone", "origin"]);
    git(project, ["config", "remote.origin.promisor", "true"]);
    git(project, ["config", "remote.origin.url", `ext::/usr/bin/touch ${marker}`]);
    git(project, ["config", "protocol.ext.allow", "always"]);
    await rm(join(project, ".git", "objects", blob.slice(0, 2), blob.slice(2)));
    // Enable only the innocuous fixture helper for the positive control.
    assert.throws(() => execFileSync("/usr/bin/git", ["diff", "HEAD", "--", "source.txt"], {
      cwd: project, shell: false, stdio: "pipe", env: { ...SAFE_GIT_ENVIRONMENT, PATH: "/usr/bin:/bin",
        GIT_NO_LAZY_FETCH: "0", GIT_ALLOW_PROTOCOL: "ext" }, timeout: 10_000, maxBuffer: 262_144
    }));
    await access(marker);
    await rm(marker);
    const config = await readFile(join(project, ".git", "config"), "utf8");
    await assert.rejects(new GitDiffInspectorImpl().diff(project, ["source.txt"], false, "HEAD", 8192, control),
      (error: unknown) => error instanceof BrokerError && ["EXECUTION_FAILED", "POLICY_DENIED", "TARGET_NOT_FOUND"].includes(error.errorClass));
    await assert.rejects(access(marker), (error: unknown) => (error as NodeJS.ErrnoException).code === "ENOENT");
    assert.equal(await readFile(join(project, ".git", "config"), "utf8"), config);
    assert.equal(await readFile(join(project, "source.txt"), "utf8"), "changed public source\n");
    assert.equal(SAFE_GIT_ENVIRONMENT.GIT_NO_LAZY_FETCH, "1");
    assert.equal(SAFE_GIT_ENVIRONMENT.GIT_ALLOW_PROTOCOL, "");
    for (const key of ["GIT_NO_LAZY_FETCH", "GIT_ALLOW_PROTOCOL"]) {
      assert.equal(isSafeProcessEnvironmentKey(key, false), false);
      assert.equal(isSafeProcessEnvironmentKey(key, true), true);
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});
