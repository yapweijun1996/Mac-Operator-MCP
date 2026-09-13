import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { GitBranchListInspector, GitDiffInspectorImpl, GitLogInspectorImpl, GitStatusInspector, GitWriteInspectorImpl, parseGitBranchResult, parseGitDiffResult, parseGitLogResult, parseGitStatusOutput, validateGitCommitRequest, validateGitDiffRequest, validateGitLogRequest, validateGitStageRequest, validateGitStatusRequest } from "./git-inspector.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";

function success(stdout: string): ProcessExecutionResult {
  return {
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
    signal: null,
    stdout,
    stderr: "",
    truncated: false,
    durationMs: 1,
    processId: 1,
    processGroupId: 1,
    terminationObserved: true
  };
}

async function runFixtureGit(cwd: string, args: readonly string[]): Promise<string> {
  return await new Promise<string>((resolveResult, reject) => {
    const child = spawn("/usr/bin/git", [...args], {
      cwd,
      env: {
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_SYSTEM: "/dev/null",
        GIT_NO_REPLACE_OBJECTS: "1",
        GIT_TERMINAL_PROMPT: "0",
        GIT_OPTIONAL_LOCKS: "0"
      },
      shell: false,
      stdio: ["ignore", "pipe", "pipe"]
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (code !== 0) {
        reject(new Error(`fixture Git failed (${code ?? signal ?? "unknown"}): ${Buffer.concat(stderr).toString("utf8")}`));
        return;
      }
      resolveResult(Buffer.concat(stdout).toString("utf8"));
    });
  });
}

test("Git status parser returns bounded staged, unstaged, untracked, and conflict paths", () => {
  const result = parseGitStatusOutput(
    "/tmp/project",
    success([
      "# branch.oid ", "a".repeat(40), "\0",
      "# branch.head main\0",
      "1 M. N... 100644 100644 100644 ", "a".repeat(40), " ", "a".repeat(40), " src/main.ts\0",
      "1 .M N... 100644 100644 100644 ", "a".repeat(40), " ", "a".repeat(40), " src/dirty.ts\0",
      "? secrets.env\0",
      "u UU N... 100644 100644 100644 100644 ", "a".repeat(40), " ", "b".repeat(40), " ", "c".repeat(40), " conflict.ts\0"
    ].join(""))
  );
  assert.equal(result.branch, "main");
  assert.equal(result.head, "a".repeat(40));
  assert.deepEqual(result.stagedPaths, ["src/main.ts", "conflict.ts"]);
  assert.deepEqual(result.unstagedPaths, ["src/dirty.ts", "conflict.ts"]);
  assert.deepEqual(result.untrackedPaths, ["secrets.env"]);
  assert.deepEqual(result.conflictedPaths, ["conflict.ts"]);
  assert.equal(result.dirty, true);
});

test("Git status rejects malformed requests and missing HEAD", () => {
  for (const projectRoot of ["relative", "/tmp/../tmp/project", "/tmp/project\n"]) {
    assert.throws(() => validateGitStatusRequest(projectRoot), BrokerError);
  }
  assert.throws(() => validateGitStatusRequest("/tmp/project", "yes" as unknown as boolean), BrokerError);
  assert.throws(() => parseGitStatusOutput("/tmp/project", success("# branch.oid " + "0".repeat(40) + "\0")), /no committed HEAD/u);
});

test("Git branch parser returns upstream and ahead/behind metadata", () => {
  const result = parseGitBranchResult(
    "/tmp/project",
    success([
      "main\0*\0origin/main\0[ahead 2, behind 3]\0",
      "topic\0 \0\0\0",
      "origin/main\0 \0\0\0"
    ].join(""))
  );
  assert.deepEqual(result.branches, [
    { name: "main", current: true, upstream: "origin/main", ahead: 2, behind: 3 },
    { name: "topic", current: false },
    { name: "origin/main", current: false }
  ]);
  assert.equal(result.truncated, false);
});

test("Git branch listing uses the fixed command boundary", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-git-branches-"));
  const target = join(directory, "target");
  await mkdir(join(target, ".git"), { recursive: true });
  await writeFile(join(target, ".git", "config"), "[core]\n\tbare = false\n");
  let observed: { args: readonly string[]; environment?: Readonly<Record<string, string>> } | undefined;
  const inspector = new GitBranchListInspector({
    run: async (request) => {
      observed = { args: request.args, ...(request.environment ? { environment: request.environment } : {}) };
      return success("");
    }
  });
  const canonicalTarget = await realpath(target);
  const result = await inspector.branches(canonicalTarget, false, { timeoutMs: 1_000, shouldCancel: () => false });
  assert.equal(result.branches.length, 0);
    assert.ok(observed);
    assert.ok(observed.args.includes("for-each-ref"));
    assert.equal(observed.args.includes("refs/remotes"), false);
    assert.equal(observed.environment?.GIT_CONFIG_NOSYSTEM, "1");
    assert.equal(observed.environment?.GIT_NO_REPLACE_OBJECTS, "1");
    assert.equal(observed.environment?.GIT_TERMINAL_PROMPT, "0");
});

test("Git log parser returns bounded commit metadata and rejects revision injection", () => {
  const result = parseGitLogResult(
    "/tmp/project",
    success([
      "a".repeat(40), "\0", "Alice", "\0", "2026-09-12T10:00:00+08:00", "\0", "safe subject", "\0",
      "b".repeat(40), "\0", "", "\0", "2026-09-11T10:00:00Z", "\0", "", "\0"
    ].join(""))
  );
  assert.equal(result.commits.length, 2);
  assert.deepEqual(result.commits[0], {
    id: "a".repeat(40),
    author: "Alice",
    timestamp: "2026-09-12T02:00:00.000Z",
    subject: "safe subject"
  });
  assert.equal(result.commits[1]!.author, undefined);
  assert.throws(() => validateGitLogRequest("/tmp/project", 5, "HEAD..origin/main"), BrokerError);
  assert.throws(() => validateGitLogRequest("/tmp/project", 201), BrokerError);
});

test("Git log inspector binds ref arguments and fixed no-network execution", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-git-log-"));
  const target = join(directory, "target");
  await mkdir(join(target, ".git"), { recursive: true });
  await writeFile(join(target, ".git", "config"), "[core]\n\tbare = false\n");
  let observed: { args: readonly string[]; environment?: Readonly<Record<string, string>> } | undefined;
  const inspector = new GitLogInspectorImpl({
    run: async (request) => {
      observed = { args: request.args, ...(request.environment ? { environment: request.environment } : {}) };
      return success("");
    }
  });
  const canonicalTarget = await realpath(target);
  const result = await inspector.log(canonicalTarget, 5, "HEAD", { timeoutMs: 1_000, shouldCancel: () => false });
  assert.equal(result.commits.length, 0);
  assert.ok(observed);
  assert.ok(observed.args.includes("log"));
  assert.ok(observed.args.includes("--max-count=5"));
  assert.equal(observed.args.at(-1), "HEAD");
  assert.equal(observed.environment?.GIT_CONFIG_GLOBAL, "/dev/null");
});

test("Git diff parser redacts content, extracts bounded paths, and hashes sanitized output", () => {
  const result = parseGitDiffResult(
    "/tmp/project",
    ["src/main.ts"],
    false,
    "HEAD",
    4096,
    success([
      "diff --git a/src/main.ts b/src/main.ts\n",
      "index 1111111..2222222 100644\n",
      "--- a/src/main.ts\n",
      "+++ b/src/main.ts\n",
      "@@ -1 +1 @@\n",
      "+token=super-secret-value\n"
    ].join(""))
  );
  assert.deepEqual(result.changedPaths, ["src/main.ts"]);
  assert.equal(result.staged, false);
  assert.equal(result.base, "HEAD");
  assert.equal(result.diff.includes("super-secret-value"), false);
  assert.equal(result.warnings.includes("Sensitive Git diff text was redacted"), true);
  assert.match(result.sha256, /^[a-f0-9]{64}$/u);
});

test("Git diff validates literal paths, revisions, and byte budgets", () => {
  for (const path of ["/absolute/path", "../outside", "nested/../outside", ":(glob)secret", "bad\\path"]) {
    assert.throws(() => validateGitDiffRequest("/tmp/project", [path]), BrokerError);
  }
  assert.throws(() => validateGitDiffRequest("/tmp/project", [], false, "HEAD..main"), BrokerError);
  assert.throws(() => validateGitDiffRequest("/tmp/project", [], false, undefined, 1_048_577), BrokerError);
});

test("Git diff inspector binds staged, revision, literal paths, and fixed environment", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-git-diff-"));
  const target = join(directory, "target");
  await mkdir(join(target, ".git"), { recursive: true });
  await writeFile(join(target, ".git", "config"), "[core]\n\tbare = false\n");
  let observed: { args: readonly string[]; environment?: Readonly<Record<string, string>> } | undefined;
  const inspector = new GitDiffInspectorImpl({
    run: async (request) => {
      observed = { args: request.args, ...(request.environment ? { environment: request.environment } : {}) };
      return success("diff --git a/src/file.ts b/src/file.ts\n");
    }
  });
  const canonicalTarget = await realpath(target);
  const result = await inspector.diff(canonicalTarget, ["src/file.ts"], true, "HEAD", 4096, { timeoutMs: 1_000, shouldCancel: () => false });
  assert.equal(result.changedPaths[0], "src/file.ts");
  assert.ok(observed);
  assert.ok(observed.args.includes("--literal-pathspecs"));
  assert.ok(observed.args.includes("--cached"));
  assert.ok(observed.args.includes("--no-ext-diff"));
  assert.ok(observed.args.includes("--no-textconv"));
  assert.ok(observed.args.includes("--end-of-options"));
  assert.equal(observed.args.at(-3), "HEAD");
  assert.equal(observed.args.at(-2), "--");
  assert.equal(observed.args.at(-1), "src/file.ts");
  assert.equal(observed.environment?.GIT_CONFIG_SYSTEM, "/dev/null");
});

test("Git write validators reject traversal, secret, and unsafe commit inputs", () => {
  assert.throws(() => validateGitStageRequest("/tmp/project", ["../outside"]), BrokerError);
  assert.throws(() => validateGitStageRequest("/tmp/project", [".git/config"]), BrokerError);
  assert.throws(() => validateGitStageRequest("/tmp/project", [".env"]), BrokerError);
  assert.throws(() => validateGitCommitRequest("/tmp/project", "\u0001unsafe"), BrokerError);
  assert.throws(() => validateGitCommitRequest("/tmp/project", "message", "not-a-digest"), BrokerError);
});

test("Git stage uses explicit literal paths and verifies the staged index hash", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-git-stage-"));
  const target = join(directory, "target");
  await mkdir(join(target, ".git"), { recursive: true });
  await mkdir(join(target, "src"), { recursive: true });
  await writeFile(join(target, ".git", "config"), "[core]\n\tbare = false\n");
  await writeFile(join(target, "src", "main.ts"), "export {}\n", { mode: 0o600 });
  let staged = false;
  const commands: readonly string[][] = [];
  const inspector = new GitWriteInspectorImpl({
    run: async (request) => {
      (commands as string[][]).push([...request.args]);
      if (request.args.includes("add")) {
        staged = true;
        return success("");
      }
      if (request.args.includes("--raw")) return success(staged ? "raw-after" : "raw-before");
      if (request.args.includes("--text")) return success("safe staged content");
      if (request.args.includes("--name-only")) return success(staged ? "src/main.ts\0" : "");
      throw new Error(`unexpected Git command: ${request.args.join(" ")}`);
    }
  });
  try {
    const result = await inspector.stage(await realpath(target), ["src/main.ts"], { timeoutMs: 2_000, shouldCancel: () => false });
    assert.deepEqual(result.stagedPaths, ["src/main.ts"]);
    assert.deepEqual(result.skippedPaths, []);
    assert.equal(result.indexChanged, true);
    assert.match(result.stagedDiffSha256, /^[a-f0-9]{64}$/u);
    const add = commands.find((args) => args.includes("add"));
    assert.ok(add);
    assert.equal(add?.includes("--all"), false);
    assert.equal(add?.includes("reset"), false);
    assert.equal(add?.includes("push"), false);
    assert.equal(add?.at(-2), "--");
    assert.equal(add?.at(-1), "src/main.ts");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("Git commit binds staged digest and reads back HEAD parents and a clean index", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-git-commit-"));
  const target = join(directory, "target");
  await mkdir(join(target, ".git"), { recursive: true });
  await mkdir(join(target, "src"), { recursive: true });
  await writeFile(join(target, ".git", "config"), "[core]\n\tbare = false\n");
  await writeFile(join(target, "src", "main.ts"), "export {}\n", { mode: 0o600 });
  const firstHead = "a".repeat(40);
  const secondHead = "b".repeat(40);
  let commitRan = false;
  const commands: readonly string[][] = [];
  const inspector = new GitWriteInspectorImpl({
    run: async (request) => {
      (commands as string[][]).push([...request.args]);
      if (request.args.includes("rev-parse")) return success(`${commitRan ? secondHead : firstHead}\n`);
      if (request.args.includes("rev-list")) return success(`${commitRan ? secondHead : firstHead} ${firstHead}\n`);
      if (request.args.includes("--raw")) return success(commitRan ? "" : "raw-staged");
      if (request.args.includes("--text")) return success("safe staged content");
      if (request.args.includes("--name-only")) return success(commitRan ? "" : "src/main.ts\0");
      if (request.args.includes("commit")) {
        commitRan = true;
        return success("[main bbbbbbb] safe commit\n");
      }
      if (request.args.includes("status")) return success(`# branch.oid ${secondHead}\0# branch.head main\0`);
      throw new Error(`unexpected Git command: ${request.args.join(" ")}`);
    }
  });
  try {
    const result = await inspector.commit(await realpath(target), "safe commit", undefined, { timeoutMs: 2_000, shouldCancel: () => false });
    assert.equal(result.commitId, secondHead);
    assert.deepEqual(result.parentIds, [firstHead]);
    assert.equal(result.precondition.expectedSha256, null);
    assert.equal(result.precondition.matched, true);
    assert.equal(result.workingTreeState, "clean");
    const commit = commands.find((args) => args.includes("commit"));
    assert.ok(commit);
    assert.ok(commit?.includes("--no-verify"));
    assert.ok(commit?.includes("--no-gpg-sign"));
    assert.equal(commit?.includes("push"), false);
    assert.equal(commit?.includes("reset"), false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("Git write inspector performs a real bounded temporary-repository stage and commit", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-git-real-"));
  try {
    const projectRoot = await realpath(directory);
    await runFixtureGit(projectRoot, ["init", "--quiet", "--initial-branch=main"]);
    await runFixtureGit(projectRoot, ["config", "user.name", "Mac Operator Fixture"]);
    await runFixtureGit(projectRoot, ["config", "user.email", "fixture@example.invalid"]);
    const sourcePath = join(projectRoot, "main.ts");
    await writeFile(sourcePath, "export const value = 1;\n", { mode: 0o600 });
    await runFixtureGit(projectRoot, ["add", "--", "main.ts"]);
    await runFixtureGit(projectRoot, ["commit", "--quiet", "--no-verify", "--no-gpg-sign", "-m", "fixture initial"]);
    const initialHead = (await runFixtureGit(projectRoot, ["rev-parse", "HEAD"])).trim();
    await writeFile(sourcePath, "export const value = 2;\n", { mode: 0o600 });

    const inspector = new GitWriteInspectorImpl();
    const control = { timeoutMs: 5_000, shouldCancel: () => false };
    const staged = await inspector.stage(projectRoot, ["main.ts"], control);
    assert.deepEqual(staged.stagedPaths, ["main.ts"]);
    assert.deepEqual(staged.skippedPaths, []);
    assert.equal(staged.indexChanged, true);
    assert.match(staged.stagedDiffSha256, /^[a-f0-9]{64}$/u);

    const committed = await inspector.commit(projectRoot, "fixture governed commit", staged.stagedDiffSha256, control);
    assert.match(committed.commitId, /^[a-f0-9]{40}$/u);
    assert.deepEqual(committed.parentIds, [initialHead]);
    assert.equal(committed.precondition.expectedSha256, staged.stagedDiffSha256);
    assert.equal(committed.precondition.actualSha256, staged.stagedDiffSha256);
    assert.equal(committed.precondition.matched, true);
    assert.equal(committed.workingTreeState, "clean");
    assert.equal((await runFixtureGit(projectRoot, ["status", "--porcelain"])).trim(), "");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("Git status rejects a symlink project root before child execution", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-git-inspector-"));
  const target = join(directory, "target");
  const link = join(directory, "link");
  await mkdir(target);
  await symlink(target, link);
  const inspector = new GitStatusInspector({
    run: async () => { throw new Error("child execution must not occur"); }
  });
  await assert.rejects(
    inspector.status(resolve(link), false, { timeoutMs: 1_000, shouldCancel: () => false }),
    /non-symlink directory/u
  );
});

test("Git status rejects repository configurations that could execute scripts", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-git-config-"));
  const target = join(directory, "target");
  await mkdir(join(target, ".git"), { recursive: true });
  await writeFile(join(target, ".git", "config"), "[filter \"unsafe\"]\n\tprocess = ./untrusted-filter\n");
  const inspector = new GitStatusInspector({
    run: async () => { throw new Error("child execution must not occur"); }
  });
  const canonicalTarget = await realpath(target);
  await assert.rejects(
    inspector.status(canonicalTarget, false, { timeoutMs: 1_000, shouldCancel: () => false }),
    /executable integration/u
  );
});
