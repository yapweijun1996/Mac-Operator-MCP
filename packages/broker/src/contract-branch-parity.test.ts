import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, realpath, readFile, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { BrokerError } from "@mac-operator/contracts";
import { validateCreate } from "./managed-worktrees.js";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020").default;
const ajv = new Ajv2020({ strict: true, allErrors: true });
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

async function contract(tool: string): Promise<any> {
  return JSON.parse(await readFile(join(repositoryRoot, "tool-contracts", `${tool}.json`), "utf8"));
}

const MAX_NAME = `codex/${"a".repeat(121)}`;
const TOO_LONG_NAME = `codex/${"a".repeat(122)}`;
const BRANCH_CORPUS = ["codex/x", "codex/a/b", "codex/a", MAX_NAME, TOO_LONG_NAME, "feature/x", "main", "codex/", "CODEX/x",
  "codex/-x", "codex/_x", "codex/ a", "codex/a..b", "codex/a//b", "codex/a/", "codex/a.lock", "codex/a.lock/b", "codex/a/.b",
  "codex/a./b", "codex/a."];
const LOOSER_THAN_SCHEMA = ["codex/a..b", "codex/a//b", "codex/a/", "codex/a.lock", "codex/a.lock/b", "codex/a/.b", "codex/a./b", "codex/a."];
const BASE_REF_CORPUS = ["HEAD", "main", "origin/main", "v1.0", "HEAD~1", "main@{1}", "x@y", "a..b", "-x", "a".repeat(256)];
// The pattern avoids lookaheads, so ".." stays a documented gap that only the runtime message explains.
const BASE_REF_LOOSER_THAN_SCHEMA = ["a..b"];

test("branch_name and base_ref input schemas never admit more than the runtime accepts", async (t) => {
  const projectRoot = await realpath(await mkdtemp(join(tmpdir(), "branch-parity-")));
  t.after(() => rm(projectRoot, { recursive: true, force: true }));
  execFileSync("git", ["init", "-q"], { cwd: projectRoot });
  const runtimeError = (branchName: string, baseRef = "main"): BrokerError | undefined => {
    try {
      validateCreate({ projectRoot, branchName, baseRef, taskId: "task-1", idempotencyKey: "key-1", owner: "owner-1" });
    } catch (error) {
      assert.ok(error instanceof BrokerError);
      return error;
    }
    return undefined;
  };

  const create = await contract("mac_git_worktree_create");
  const branchCreate = await contract("mac_git_branch_create");
  const prepare = await contract("mac_pr_prepare");
  const createBranch = create.input_schema.properties.branch_name;
  assert.deepEqual(createBranch, branchCreate.input_schema.properties.branch_name);
  const validateBranch = ajv.compile(createBranch);

  const outputBranchSchemas = [
    create.output_schema.properties.data.properties.branch_name,
    branchCreate.output_schema.properties.data.properties.branch_name,
    (await contract("mac_git_worktree_list")).output_schema.properties.data.properties.worktrees.items.properties.branch_name,
    (await contract("mac_git_worktree_remove")).output_schema.properties.data.properties.branch_name,
  ];
  assert.ok(outputBranchSchemas.every((schema) => schema !== undefined));
  const outputValidators = outputBranchSchemas.map((schema) => ajv.compile(schema));

  for (const name of BRANCH_CORPUS) {
    const rejected = runtimeError(name);
    if (!validateBranch(name)) assert.ok(rejected, `schema rejects ${name} but runtime accepts it`);
    if (!rejected) outputValidators.forEach((validate) => assert.equal(validate(name), true, `output schema rejects ${name}`));
  }
  assert.equal(validateBranch(MAX_NAME) && runtimeError(MAX_NAME) === undefined, true);
  assert.equal(validateBranch("codex/a") && runtimeError("codex/a") === undefined, true);
  assert.equal(validateBranch(TOO_LONG_NAME) || runtimeError(TOO_LONG_NAME) === undefined, false);
  for (const name of LOOSER_THAN_SCHEMA) {
    const error = runtimeError(name);
    assert.equal(error?.errorClass,"PRECONDITION_FAILED", name);
    assert.match(error!.message, /no empty, dotted or \.lock segments/u, name);
  }

  for (const [tool, schema] of [["create", create], ["branch_create", branchCreate], ["pr_prepare", prepare]] as const) {
    const validateRef = ajv.compile(schema.input_schema.properties.base_ref);
    for (const ref of BASE_REF_CORPUS) {
      if (validateRef(ref) && !BASE_REF_LOOSER_THAN_SCHEMA.includes(ref)) assert.equal(runtimeError("codex/x", ref), undefined, `${tool}: schema accepts base_ref ${ref} but runtime rejects it`);
    }
  }
  for (const ref of ["HEAD~1", "main@{1}", "x@y", ...BASE_REF_LOOSER_THAN_SCHEMA]) assert.match(runtimeError("codex/x", ref)!.message, /revision expressions/u);
});
