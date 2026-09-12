import assert from "node:assert/strict";
import { mkdir, mkdtemp, realpath, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { GitStatusInspector, parseGitStatusOutput, validateGitStatusRequest } from "./git-inspector.js";
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
