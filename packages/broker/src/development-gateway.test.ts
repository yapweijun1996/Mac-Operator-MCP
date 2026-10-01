import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, realpath, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { canonicalJson, sha256, signRequest, type BrokerResult, type Scope, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { DevelopmentGateway, type CodingAgentProvider } from "./development-gateway.js";
import { DEVELOPMENT_TOOL_NAMES } from "./development-policy.js";
import { ManagedWorktrees } from "./managed-worktrees.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { BrokerStore } from "./persistence.js";
import { TaskProfileRegistry, type TaskProfile } from "./task-profile.js";
import type { TaskRunner } from "./task-runner.js";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020").default;
const ajv = new Ajv2020({ strict: true, allErrors: true });
require("ajv-formats").default(ajv);
const validators = new Map<string, ReturnType<typeof ajv.compile>>();
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
async function checkContract(result: BrokerResult) {
  if (!result.ok) return result;
  let validate = validators.get(result.tool);
  if (!validate) {
    const contract = JSON.parse(await readFile(join(repositoryRoot, "tool-contracts", `${result.tool}.json`), "utf8"));
    validate = ajv.compile(contract.output_schema); validators.set(result.tool, validate);
  }
  assert.equal(validate(result), true, `${result.tool}: ${ajv.errorsText(validate.errors)}`);
  return result;
}
const NOW = 1_700_000_000_000;
const scopes: Scope[] = ["mac.control.read", "mac.policy.explain", "mac.project.read", "mac.project.write", "mac.git.read", "mac.git.write", "mac.git.push", "mac.agent.read", "mac.agent.run", "mac.task.run", "mac.audit.read", "mac.job.read", "mac.job.cancel"];
function git(cwd: string, args: string[]): string {
  return execFileSync("/usr/bin/git", args, { cwd, encoding: "utf8", env: { GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null", GIT_TERMINAL_PROMPT: "0" } });
}
async function setup(run?: TaskRunner["run"], agent = false) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mac-v2-broker-")));
  const project = join(root, "project"), state = join(root, "state"), trees = join(root, "trees");
  for (const path of [project, state, trees]) await mkdir(path, { mode: 0o700 });
  git(project, ["init", "-b", "main"]); git(project, ["config", "user.name", "Gateway Fixture"]); git(project, ["config", "user.email", "fixture@example.invalid"]);
  await writeFile(join(project, "source.txt"), "original\n"); git(project, ["add", "--", "source.txt"]); git(project, ["commit", "-m", "Fixture baseline"]);
  const registry = new ManagedWorktrees(state, trees);
  const profile: TaskProfile = { schemaVersion: "0.1", profile: "validation.echo", executable: "/bin/echo", fixedArgs: ["fixture"], allowedCwdRoots: [trees], filesystemRoots: [trees], networkPolicy: "none", sandboxProfile: "deny-default-v0.1", timeoutMs: 1000, outputCapBytes: 1024, verificationStrategy: "exit_status_and_declared_task_verification", enabled: true };
  const profiles = new TaskProfileRegistry([profile]);
  const provider: CodingAgentProvider = { readiness: { installed: true, version: "fixture-only", authentication: "ready", supportedModels: ["fixture"], enforcedProfiles: ["readonly", "workspace-write", "test-only"], hostGitDenied: true, networkPolicies: ["none"] },
    async resolve(_input, record) { const resolved = await profiles.resolve({ profile: profile.profile, cwd: record.worktree, args: [] }); return { ...resolved, filesystemRoots: [record.worktree] }; } };
  const gateway = new DevelopmentGateway({ worktrees: registry, commands: [{ projectRoot: project, type: "test", profile: profile.profile }, { projectRoot: project, type: "build", profile: profile.profile }], ...(agent ? { codingAgent: provider } : {}) });
  let calls = 0;
  // This runner is a UNIT TEST double. It provides no OS containment evidence.
  const runner: TaskRunner = { available: true, publicEnablement: "production", mechanism: "sandbox-exec", isolationProof: { schemaVersion: "0.1", sandboxMechanism: "sandbox-exec", sandboxProfile: "deny-default-v0.1", filesystem: "enforced", network: "enforced", credentials: "isolated", persistence: "isolated", credentialIsolation: "sandbox-exec-empty-env-deny-secret-zones-v1", processTree: "owned", processTreePolicy: "single_process", evidenceRef: "test://development-gateway-only" },
    async run(resolved, control) { calls++; assert.deepEqual(resolved.filesystemRoots, [resolved.cwd]); assert.equal(Object.isFrozen(resolved), true); assert.equal(Object.isFrozen(resolved.process), true); return run ? run(resolved, control) : { state: "completed", resultClass: "SUCCEEDED", exitCode: 0, stdout: "fixture validation", stderr: "", truncated: false, durationMs: 1, verification: { status: "verified" } }; } };
  const base = createDefaultPolicy("edge-1", true, scopes, ["edge-key-1"], [], [], [], [project]);
  const tools = new Map([...base.tools].map(([name, p]) => [name, { ...p, enabled: DEVELOPMENT_TOOL_NAMES.includes(name) || ["mac_git_stage", "mac_git_commit"].includes(name) ? true : p.enabled }]));
  const policy = { ...base, tools, targetRules: [...base.targetRules, ...scopes.map((scope, i) => ({ ruleId: `v2-project-${i}`, effect: "allow" as const, principalId: "principal-1", scope, target: { kind: "project" as const, reference: project } }))] };
  const store = new BrokerStore(join(root, "broker.sqlite")); const key = randomBytes(32);
  const broker = new Broker({ store, policy, developmentGateway: gateway, taskRunner: runner, taskProfileRegistry: profiles, now: () => NOW, edgeAuthenticationKeys: new EdgeKeyring([{ edgeId: "edge-1", keyId: "edge-key-1", key, notBeforeMs: NOW - 1000, expiresAtMs: NOW + 120_000 }]) });
  let index = 0;
  const request = (tool: string, args: Record<string, unknown>): UnsignedBrokerRequest => ({ protocolVersion: "0.1", requestId: `v2-request-${++index}`, contractVersion: "0.1", tool, arguments: args, principal: { principalId: "principal-1", sessionId: "session-1", issuer: "test-issuer", audience: "mac-operator-broker", scopes, issuedAtMs: NOW - 1000, expiresAtMs: NOW + 60_000, edgeId: "edge-1" }, timestampMs: NOW, nonce: `v2-nonce-${index}`, policyAudience: "mac-operator-broker", policyVersion: "policy-0.1", authenticationKeyId: "edge-key-1" });
  const handle = async (tool: string, args: Record<string, unknown>) => checkContract(await broker.handle(signRequest(request(tool, args), key)));
  const approve = (tool: string, args: Record<string, unknown>, target = project) => store.issueApproval({ approvalId: `approval:v2-${++index}`, approverPrincipalId: "operator-1", requestingPrincipalId: "principal-1", tool, contractVersion: "0.1", targetKind: "project", targetRef: `project:${target}`, payloadDigest: sha256(canonicalJson(args)), policyVersion: "policy-0.1", approvalClass: ["mac_test_run", "mac_build_run", "mac_codex_run"].includes(tool) ? "trusted_profile" : "trusted_write", unattended: false, issuedAtMs: NOW - 1000, expiresAtMs: NOW + 60_000 });
  async function create(task = "task-1") { const args = { project_root: project, branch_name: `codex/${task}`, base_ref: "HEAD", task_id: task, idempotency_key: `create-${task}` }; approve("mac_git_worktree_create", args); return data(await handle("mac_git_worktree_create", args)); }
  return { root, project, registry, gateway, broker, store, request, handle, approve, create, profiles, runner, get calls() { return calls; }, close: async () => { await broker.close(); store.close(); await rm(root, { recursive: true, force: true }); } };
}
function data(result: BrokerResult): Record<string, unknown> { assert.equal(result.ok, true, JSON.stringify(result)); if (!result.ok) throw new Error("Expected success"); return result.data as Record<string, unknown>; }
async function settle(f: Awaited<ReturnType<typeof setup>>, receipt: Record<string, unknown>) { for (let i = 0; i < 200; i++) { const state = f.store.ownedJob(receipt.job_id as string, "principal-1")?.state; if (state !== "running" && state !== "queued") return state; await new Promise<void>(resolve => setTimeout(resolve, 5)); } assert.fail("Job did not settle"); }

test("V2 signed Broker worktree/Git workflow preserves the primary checkout and produces audit/review", async () => {
  const f = await setup(); try {
    const before = git(f.project, ["rev-parse", "HEAD"]); const index = await readFile(join(f.project, ".git", "index"));
    const created = await f.create(); const worktree = created.worktree as string;
    const listed = data(await f.handle("mac_git_worktree_list", { project_root: f.project })); assert.equal((listed.worktrees as unknown[]).length, 1);
    await writeFile(join(worktree, "source.txt"), "synthetic isolated edit\n");
    const empty = await f.handle("mac_git_stage", { project_root: worktree, paths: [] }); assert.equal(empty.ok, false);
    data(await f.handle("mac_git_status", { project_root: worktree }));
    const stageArgs = { project_root: worktree, paths: ["source.txt"] }; f.approve("mac_git_stage", stageArgs, worktree);
    const staged = data(await f.handle("mac_git_stage", stageArgs));
    const commitArgs = { project_root: worktree, message: "Synthetic development fixture", expected_staged_diff_sha256: staged.staged_diff_sha256 };
    f.approve("mac_git_commit", commitArgs, worktree); const committed = data(await f.handle("mac_git_commit", commitArgs)); assert.match(committed.commit_id as string, /^[a-f0-9]{40}$/u);
    const review = data(await f.handle("mac_pr_prepare", { project_root: f.project, worktree })); assert.deepEqual(review.changed_files, ["source.txt"]); assert.equal((review.commits as unknown[]).length, 1);
    const audit = data(await f.handle("mac_execution_audit", { project_root: f.project, limit: 100 })); assert.ok((audit.events as { tool: string }[]).some(row => row.tool === "mac_git_commit"));
    assert.equal(git(f.project, ["rev-parse", "HEAD"]), before); assert.deepEqual(await readFile(join(f.project, ".git", "index")), index); assert.equal(await readFile(join(f.project, "source.txt"), "utf8"), "original\n"); assert.equal(git(f.project, ["status", "--porcelain"]), ""); assert.equal(f.calls, 0);
  } finally { await f.close(); }
});

test("V2 registered validation commands use bounded managed jobs and reject arbitrary input", async () => {
  const f = await setup(); try {
    const { worktree } = await f.create(); const args = { project_root: f.project, worktree, task_id: "task-1", max_runtime: 500, idempotency_key: "test-first" };
    f.approve("mac_test_run", args); const receipt = data(await f.handle("mac_test_run", args)); assert.equal("stdout" in receipt, false); assert.equal(await settle(f, receipt), "completed"); assert.equal(f.calls, 1);
    const repeated = data(await f.handle("mac_test_run", args)); assert.equal(repeated.job_id, receipt.job_id); assert.equal(f.calls, 1);
    const injected = await f.handle("mac_test_run", { ...args, script: "sudo whoami", idempotency_key: "bad" }); assert.equal(injected.ok, false); assert.equal(f.calls, 1);
    const unknown = await f.handle("mac_build_run", { ...args, profile: "unregistered", idempotency_key: "unknown" }); assert.equal(unknown.ok, false);
    const audit = data(await f.handle("mac_execution_audit", { project_root: f.project })); assert.ok((audit.events as { scope: string[] }[]).some(row => row.scope.includes("mac.task.run")));
  } finally { await f.close(); }
});

test("V2 dry-run/preflight never execute; unprovisioned coding and push fail closed", async () => {
  const f = await setup(); try {
    const { worktree } = await f.create();
    assert.equal(f.broker.enabledRuntimeCapabilityNames().includes("mac_codex_run"), false);
    assert.equal(f.broker.enabledRuntimeCapabilityNames().includes("mac_git_push"), false);
    assert.equal(f.broker.enabledRuntimeCapabilityNames().includes("mac_test_run"), true);
    const preflight = data(await f.handle("mac_codex_preflight", { project_root: f.project, worktree })); assert.equal(preflight.permission, "deny"); assert.ok((preflight.reason_codes as string[]).includes("CODING_AGENT_ADAPTER_UNAVAILABLE"));
    const proposed = { project_root: f.project, worktree, task_id: "task-1", max_runtime: 500, idempotency_key: "dry-test" };
    const explanation = data(await f.handle("mac_policy_explain", { proposed_tool: "mac_test_run", target: { kind: "project", reference: f.project }, proposed_arguments: proposed })); assert.equal(explanation.decision, "allow"); assert.equal(f.calls, 0);
    const secretExplain = data(await f.handle("mac_policy_explain", { proposed_tool: "mac_codex_run", target: { kind: "project", reference: f.project }, proposed_arguments: { ...proposed, task: "Synthetic fixture", execution_profile: "readonly", network_policy: "none", allowed_paths: [".env"] } }));
    assert.equal(secretExplain.decision, "deny"); assert.ok((secretExplain.reason_codes as string[]).includes("SECRET_PATH_ACCESS")); assert.equal(f.calls, 0);
    const push = await f.handle("mac_git_push", { project_root: f.project, worktree, remote: "origin", branch_name: "codex/task-1", idempotency_key: "push" }); assert.equal(push.ok, false); assert.equal(push.result_class, "POLICY_DENIED"); assert.equal(f.calls, 0);
    const unauthorizedRoot = join(f.root, "unauthorized"); await mkdir(unauthorizedRoot); git(unauthorizedRoot, ["init", "-b", "main"]);
    const unauthorized = await f.handle("mac_git_worktree_list", { project_root: unauthorizedRoot }); assert.equal(unauthorized.ok, false); assert.equal(unauthorized.result_class, "POLICY_DENIED");
    const traversal = await f.handle("mac_git_worktree_list", { project_root: `${f.project}/../project` }); assert.equal(traversal.ok, false);
  } finally { await f.close(); }
});

for (const executionProfile of ["readonly", "workspace-write", "test-only"]) {
  test(`V2 ${executionProfile} coding admission validates confinement using a fixture adapter`, async () => {
    const f = await setup(undefined, true); try {
      const { worktree } = await f.create(); const args = { project_root: f.project, worktree, task: "Synthetic fixture only", task_id: "task-1", execution_profile: executionProfile, max_runtime: 500, idempotency_key: `agent-${executionProfile}`, network_policy: "none", model: "fixture", allowed_paths: ["source.txt"] };
      f.approve("mac_codex_run", args); const receipt = data(await f.handle("mac_codex_run", args)); assert.equal(await settle(f, receipt), "completed"); assert.equal(f.calls, 1);
      for (const path of ["../escape", ".ssh/id_rsa", ".env", ".git/HEAD", "/etc/passwd"]) { const blocked = await f.handle("mac_codex_run", { ...args, allowed_paths: [path], idempotency_key: "blocked" }); assert.equal(blocked.ok, false, path); }
      assert.equal(f.calls, 1); assert.equal(git(f.project, ["status", "--porcelain"]), "");
    } finally { await f.close(); }
  });
}

test("V2 active jobs pin one worktree while independent task checkouts remain usable", async () => {
  let release!: () => void; const pending = new Promise<void>(resolve => { release = resolve; });
  const f = await setup(async () => { await pending; return { state: "completed", resultClass: "SUCCEEDED", exitCode: 0, stdout: "", stderr: "", durationMs: 1, truncated: false, verification: { status: "verified" } }; });
  try {
    const a = await f.create("task-a"), b = await f.create("task-b");
    const args = { project_root: f.project, worktree: a.worktree, task_id: "task-a", max_runtime: 500, idempotency_key: "pin-a" };
    f.approve("mac_test_run", args); const first = data(await f.handle("mac_test_run", args));
    const prematureStage = await f.handle("mac_git_stage", { project_root: a.worktree, paths: ["source.txt"] }); assert.equal(prematureStage.result_class, "CONFLICT");
    const conflicting = { ...args, idempotency_key: "pin-other" }; f.approve("mac_test_run", conflicting); const denied = await f.handle("mac_test_run", conflicting); assert.equal(denied.result_class, "CONFLICT");
    const secondArgs = { ...args, worktree: b.worktree, task_id: "task-b", idempotency_key: "pin-b" }; f.approve("mac_test_run", secondArgs); const second = data(await f.handle("mac_test_run", secondArgs)); assert.notEqual(first.job_id, second.job_id);
    release(); assert.equal(await settle(f, first), "completed"); assert.equal(await settle(f, second), "completed");
  } finally { release(); await f.close(); }
});

test("V2 branch alias, build receipt and clean removal conform to their contracts", async () => {
  const f = await setup(); try {
    const createArgs = { project_root: f.project, branch_name: "codex/alias", base_ref: "HEAD", task_id: "alias", idempotency_key: "alias-create" };
    f.approve("mac_git_branch_create", createArgs); const { worktree } = data(await f.handle("mac_git_branch_create", createArgs));
    const buildArgs = { project_root: f.project, worktree, task_id: "alias", idempotency_key: "alias-build", max_runtime: 500 };
    f.approve("mac_build_run", buildArgs); const receipt = data(await f.handle("mac_build_run", buildArgs)); assert.equal(await settle(f, receipt), "completed");
    const removeArgs = { project_root: f.project, worktree, task_id: "alias", idempotency_key: "alias-remove" };
    f.approve("mac_git_worktree_remove", removeArgs); assert.equal(data(await f.handle("mac_git_worktree_remove", removeArgs)).removed, true);
    f.approve("mac_git_worktree_remove", removeArgs); assert.equal(data(await f.handle("mac_git_worktree_remove", removeArgs)).removed, true);
    assert.equal(f.registry.list(f.project, "principal-1").length, 0); assert.equal(git(f.project, ["status", "--porcelain"]), "");
  } finally { await f.close(); }
});

test("V2 provenance and all-task storage cannot be exposed through ordinary filesystem roots", async () => {
  const f = await setup(); try {
    for (const path of ["/", f.root, f.registry.stateRoot, join(f.registry.stateRoot, "nested"), f.registry.worktreeRoot]) {
      assert.throws(() => f.gateway.assertProtectedStorage([{ path }]), /ordinary filesystem roots/u);
    }
    assert.doesNotThrow(() => f.gateway.assertProtectedStorage([{ path: f.project }]));
  } finally { await f.close(); }
});
