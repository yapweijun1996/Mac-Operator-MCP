import assert from "node:assert/strict";
import { mkdir, mkdtemp, realpath, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { GitBranchListInspector, GitDiffInspectorImpl, GitLogInspectorImpl, GitStatusInspector, parseGitBranchResult, parseGitDiffResult, parseGitLogResult, parseGitStatusOutput, validateGitDiffRequest, validateGitLogRequest, validateGitStatusRequest } from "./git-inspector.js";
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
