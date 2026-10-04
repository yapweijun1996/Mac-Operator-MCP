import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, realpath, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { BrokerError, canonicalJson, sha256, signRequest, type BrokerResult, type Scope, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { DevelopmentGateway, decodeAuditCursor, encodeAuditCursor, type CodingAgentProvider } from "./development-gateway.js";
import { DEVELOPMENT_TOOL_NAMES } from "./development-policy.js";
import type { GitWriteInspector } from "./git-inspector.js";
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
async function setup(run?: TaskRunner["run"], agent = false, gitWriteInspector?: GitWriteInspector) {
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
  const broker = new Broker({ store, policy, developmentGateway: gateway, ...(gitWriteInspector ? { gitWriteInspector } : {}), taskRunner: runner, taskProfileRegistry: profiles, now: () => NOW, edgeAuthenticationKeys: new EdgeKeyring([{ edgeId: "edge-1", keyId: "edge-key-1", key, notBeforeMs: NOW - 1000, expiresAtMs: NOW + 120_000 }]) });
  let index = 0;
  const request = (tool: string, args: Record<string, unknown>): UnsignedBrokerRequest => ({ protocolVersion: "0.1", requestId: `v2-request-${++index}`, contractVersion: "0.1", tool, arguments: args, principal: { principalId: "principal-1", sessionId: "session-1", issuer: "test-issuer", audience: "mac-operator-broker", scopes, issuedAtMs: NOW - 1000, expiresAtMs: NOW + 60_000, edgeId: "edge-1" }, timestampMs: NOW, nonce: `v2-nonce-${index}`, policyAudience: "mac-operator-broker", policyVersion: "policy-0.1", authenticationKeyId: "edge-key-1" });
  const handle = async (tool: string, args: Record<string, unknown>) => checkContract(await broker.handle(signRequest(request(tool, args), key)));
  const approve = (tool: string, args: Record<string, unknown>, target = project) => store.issueApproval({ approvalId: `approval:v2-${++index}`, approverPrincipalId: "operator-1", requestingPrincipalId: "principal-1", tool, contractVersion: "0.1", targetKind: "project", targetRef: `project:${target}`, payloadDigest: sha256(canonicalJson(args)), policyVersion: "policy-0.1", approvalClass: ["mac_test_run", "mac_build_run", "mac_codex_run"].includes(tool) ? "trusted_profile" : "trusted_write", unattended: false, issuedAtMs: NOW - 1000, expiresAtMs: NOW + 60_000 });
  async function create(task = "task-1") { const args = { project_root: project, branch_name: `codex/${task}`, base_ref: "HEAD", task_id: task, idempotency_key: `create-${task}` }; approve("mac_git_worktree_create", args); return data(await handle("mac_git_worktree_create", args)); }
  return { root, project, registry, gateway, broker, store, request, handle, approve, create, profiles, runner, get calls() { return calls; }, close: async () => { await broker.close(); store.close(); await rm(root, { recursive: true, force: true }); } };
}
function data(result: BrokerResult): Record<string, unknown> { assert.equal(result.ok, true, JSON.stringify(result)); if (!result.ok) throw new Error("Expected success"); return result.data as Record<string, unknown>; }
function failure(result: BrokerResult) { assert.equal(result.ok, false, JSON.stringify(result)); if (result.ok) throw new Error("Expected failure"); return result; }
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
    // A host process runner reports no phase timing, so its runs add no phase_ms to the audit view.
    assert.ok((audit.events as { phase_ms?: unknown }[]).every(row => row.phase_ms === undefined));
    const limited = await f.handle("mac_execution_audit", { project_root: f.project, limit: 1 }); assert.equal(limited.ok, true);
    const envelope = limited as unknown as { truncated: boolean; warnings: string[]; data: { truncated: boolean } };
    assert.equal(envelope.data.truncated, true); assert.equal(envelope.truncated, true); assert.ok(envelope.warnings.some(w => /limited to the newest 1/u.test(w)));
  } finally { await f.close(); }
});

test("V2 a task idempotency key held by another tool or payload names the holder job and the differing binding", async () => {
  const f = await setup(); try {
    const { worktree } = await f.create(); const args = { project_root: f.project, worktree, task_id: "task-1", max_runtime: 500, idempotency_key: "shared-task-key" };
    f.approve("mac_test_run", args); const receipt = data(await f.handle("mac_test_run", args)); assert.equal(await settle(f, receipt), "completed"); assert.equal(f.calls, 1);
    const holder = f.store.ownedJob(receipt.job_id as string, "principal-1")!;
    const head = `IDEMPOTENCY_KEY_IN_USE: this idempotency_key already belongs to job ${holder.jobId} (mac_test_run, completed, created ${new Date(holder.createdAtMs).toISOString()}), but the new request differs in`;
    const failureSchema = JSON.parse(await readFile(join(repositoryRoot, "schemas", "broker-failure.schema.json"), "utf8")); const validateFailure = ajv.compile(failureSchema);
    // The same key under mac_build_run shares the namespace and is refused with the tool label.
    f.approve("mac_build_run", args); const otherTool = failure(await f.handle("mac_build_run", args));
    assert.equal(otherTool.result_class, "CONFLICT"); assert.equal(otherTool.error.message, `${head} tool. Use a new idempotency_key.`);
    assert.equal(validateFailure(otherTool), true, ajv.errorsText(validateFailure.errors));
    // The same tool with other arguments is refused with the arguments label.
    const changed = { ...args, max_runtime: 400 }; f.approve("mac_test_run", changed); const otherArguments = failure(await f.handle("mac_test_run", changed));
    assert.equal(otherArguments.result_class, "CONFLICT"); assert.equal(otherArguments.error.message, `${head} arguments. Use a new idempotency_key.`);
    // The identical request still replays the recorded job and nothing runs again.
    const repeated = data(await f.handle("mac_test_run", args)); assert.equal(repeated.job_id, receipt.job_id); assert.equal(f.calls, 1);
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

test("V2 re-created task worktree is removable through the Broker and a stale removal key cannot reach it", async () => {
  const f = await setup(); try {
    const make = async (key: string) => { const args = { project_root: f.project, branch_name: "codex/again", base_ref: "HEAD", task_id: "again", idempotency_key: key }; f.approve("mac_git_worktree_create", args); return data(await f.handle("mac_git_worktree_create", args)); };
    const drop = async (worktree: unknown, key: string) => { const args = { project_root: f.project, worktree, task_id: "again", idempotency_key: key }; f.approve("mac_git_worktree_remove", args); return f.handle("mac_git_worktree_remove", args); };
    const first = await make("again-create-1");
    assert.equal(data(await drop(first.worktree, "again-remove-1")).removed, true);
    const second = await make("again-create-2");
    assert.equal(second.worktree, first.worktree);
    const stale = failure(await drop(second.worktree, "again-remove-1"));
    assert.equal(stale.result_class, "CONFLICT"); assert.match(stale.error.message, /^IDEMPOTENCY_KEY_IN_USE: .*new idempotency_key/u);
    assert.equal(await readFile(join(second.worktree as string, "source.txt"), "utf8"), "original\n"); assert.equal(f.registry.list(f.project, "principal-1").length, 1);
    assert.equal(data(await drop(second.worktree, "again-remove-2")).removed, true);
    assert.equal(f.registry.list(f.project, "principal-1").length, 0); assert.equal(git(f.project, ["status", "--porcelain"]), "");
  } finally { await f.close(); }
});

test("V2 worktree removal names the caller's unfinished jobs, counts the rest and says which can be cancelled", async () => {
  const f = await setup(); try {
    const { worktree } = await f.create();
    const pin = (jobId: string, owner: string, createdAtMs: number) => f.store.createJob({ jobId, ownerPrincipalId: owner, ownerSessionId: `${owner}-session`, tool: "mac_test_run",
      targetRef: `project:${f.project}`, policyVersion: "policy-0.1", payloadDigest: "a".repeat(64), idempotencyKey: jobId, createdAtMs });
    const id = (name: string) => `job:task-${name.repeat(48)}`;
    const refusal = async (key: string) => { const args = { project_root: f.project, worktree, task_id: "task-1", idempotency_key: key }; f.approve("mac_git_worktree_remove", args); return failure(await f.handle("mac_git_worktree_remove", args)); };
    // The pin is global, but another principal's job is only counted, never named.
    pin(id("6"), "another-owner", NOW - 1);
    assert.match((await refusal("remove-others")).error.message, /blocked by 1 unfinished job on this project \(none of them are yours\)/u);
    f.store.requestJobCancellation(id("6"), "another-owner", "synthetic-stop", NOW);
    // Restart recovery turns a running job without container or process metadata into an unknown one that nothing resolves.
    pin(id("1"), "principal-1", NOW); f.store.startJob(id("1"), "principal-1", 0, NOW); f.store.reconcileInterruptedJobs(NOW);
    pin(id("2"), "principal-1", NOW + 1); f.store.startJob(id("2"), "principal-1", 0, NOW + 1);
    pin(id("3"), "principal-1", NOW + 2); pin(id("4"), "principal-1", NOW + 3); pin(id("5"), "another-owner", NOW + 4);
    const refused = await refusal("remove-pinned");
    assert.equal(refused.result_class, "CONFLICT");
    const message = refused.error.message;
    assert.ok(message.length < 512, `message is ${message.length} characters`);
    assert.match(message, /blocked by 5 unfinished jobs/u);
    assert.ok(message.includes(`${id("1")} (mac_test_run, unknown), ${id("2")} (mac_test_run, running), ${id("3")} (mac_test_run, queued), and 2 more`), message);
    assert.doesNotMatch(message, new RegExp(`${id("4")}|${id("5")}`, "u"));
    assert.match(message, /Queued or running jobs can be cancelled with mac_job_cancel; unknown jobs cannot be cancelled and stay until the owner reconciles the ledger/u);
    assert.doesNotMatch(message, /primary or/u);
    // Cancelling queued jobs frees them; the running job needs its runner to stop and the unknown job never leaves.
    for (const [job, owner] of [[id("3"), "principal-1"], [id("4"), "principal-1"], [id("5"), "another-owner"]] as const) f.store.requestJobCancellation(job, owner, "synthetic-stop", NOW + 5);
    const pinned = (await refusal("remove-pinned-2")).error.message;
    assert.ok(pinned.includes(`blocked by 2 unfinished jobs on this project (${id("1")} (mac_test_run, unknown), ${id("2")} (mac_test_run, running)).`), pinned);
    assert.equal(f.registry.list(f.project, "principal-1").length, 1);
  } finally { await f.close(); }
});

test("V2 worktree removal refusal stays under the failure message bound when the caller's job ids are very long", async () => {
  const f = await setup(); try {
    const { worktree } = await f.create();
    // The job id pattern allows 245 characters; three such ids cannot all be named in 512 characters.
    const id = (name: string) => `job:${name.repeat(230)}`;
    for (const [n, name] of ["a", "b", "c"].entries()) {
      f.store.createJob({ jobId: id(name), ownerPrincipalId: "principal-1", ownerSessionId: "principal-1-session", tool: "mac_test_run", targetRef: `project:${f.project}`,
        policyVersion: "policy-0.1", payloadDigest: "a".repeat(64), idempotencyKey: `long-${name}`, createdAtMs: NOW + n });
    }
    const args = { project_root: f.project, worktree, task_id: "task-1", idempotency_key: "remove-long" }; f.approve("mac_git_worktree_remove", args);
    const refused = failure(await f.handle("mac_git_worktree_remove", args));
    assert.equal(refused.result_class, "CONFLICT");
    const message = refused.error.message;
    assert.ok(message.length < 512, `message is ${message.length} characters`);
    assert.match(message, /blocked by 3 unfinished jobs/u);
    const named = (message.match(/\(mac_test_run, queued\)/gu) ?? []).length;
    assert.ok(named >= 1 && named < 3, `${named} jobs named`);
    assert.ok(message.includes(`, and ${3 - named} more)`), message);
    assert.doesNotMatch(message, /none of them are yours/u);
  } finally { await f.close(); }
});

test("V2 worktree list warns about pending and removing records that no other tool can show", async () => {
  const f = await setup(); try {
    const control = { timeoutMs: 30_000, shouldCancel: () => false };
    const stuck = await f.create("task-stuck"); await f.create("task-ok");
    // A locked worktree makes `git worktree remove` fail after the record was persisted as removing.
    git(f.project, ["worktree", "lock", stuck.worktree as string]);
    await assert.rejects(f.registry.remove(f.project, stuck.worktree as string, "principal-1", "task-stuck", control, () => undefined, () => false, "stuck-remove"), /Git operation failed/u);
    let checks = 0;
    await assert.rejects(f.registry.create({ projectRoot: f.project, branchName: "codex/task-pending", baseRef: "HEAD", taskId: "task-pending", idempotencyKey: "pending-key", owner: "principal-1" },
      control, () => { if (++checks >= 3) throw new Error("Authority revoked"); }), /revoked/u);
    const listed = await f.handle("mac_git_worktree_list", { project_root: f.project });
    assert.deepEqual((data(listed).worktrees as { task_id: string }[]).map(entry => entry.task_id), ["task-ok"]);
    assert.deepEqual((listed as unknown as { warnings: string[] }).warnings, [
      "Worktree for task task-stuck is removing and is not usable; needs operator reconciliation",
      "Worktree for task task-pending is pending and is not usable; needs operator reconciliation"]);
  } finally { await f.close(); }
});

function requestRows(f: Awaited<ReturnType<typeof setup>>, requestId: string) { return f.store.auditRows().filter(row => row.request_id === requestId); }
function gitJobOf(f: Awaited<ReturnType<typeof setup>>, requestId: string) { const jobId = f.store.requestRecord(requestId)?.jobId; assert.ok(jobId, `request ${requestId} has no job`); return f.store.ownedJob(jobId, "principal-1")!; }

test("V2 a Git mutation refused before git ran settles its job as failed, keeps a visible failure row and leaves the worktree usable", async () => {
  const f = await setup(); try {
    const worktree = (await f.create()).worktree as string;
    const commitArgs = { project_root: worktree, message: "Nothing to commit" };
    f.approve("mac_git_commit", commitArgs, worktree);
    const refused = failure(await f.handle("mac_git_commit", commitArgs));
    assert.equal(refused.result_class, "PRECONDITION_FAILED");
    assert.match(refused.error.message, /Nothing is staged to commit; stage the intended paths with mac_git_stage first/u);
    const rows = requestRows(f, refused.request_id);
    assert.deepEqual(rows.map(row => [row.event_type, row.result_class]), [["decision", "AUTHORIZED"], ["intent", "INTENT_RECORDED"], ["completion", "PRECONDITION_FAILED"]]);
    const record = f.store.requestRecord(refused.request_id)!, job = gitJobOf(f, refused.request_id);
    assert.deepEqual([record.state, record.resultClass], ["FAILED", "PRECONDITION_FAILED"]);
    assert.deepEqual([job.state, job.resultClass], ["failed", "failed"]);
    const completion = JSON.parse(rows[2]!.evidence_json as string) as Record<string, unknown>;
    assert.deepEqual({ project: completion.project, worktree: completion.worktree, taskId: completion.taskId, jobId: completion.jobId }, { project: f.project, worktree, taskId: "task-1", jobId: job.jobId });
    assert.ok(Array.isArray(completion.scopes));
    // The failed job no longer pins the worktree or its project, and the failure row is readable by project.
    assert.equal(f.store.hasActiveWorktreeJobs(worktree, "job:git-preview"), false); assert.equal(f.store.hasActiveProjectJobs(worktree), false); assert.equal(f.store.hasActiveProjectJobs(f.project), false);
    const audit = data(await f.handle("mac_execution_audit", { project_root: f.project, limit: 100 })).events as { request_id: string; result: string; worktree?: string; task_id?: string }[];
    assert.deepEqual(audit.filter(event => event.request_id === refused.request_id).map(event => event.result), ["PRECONDITION_FAILED", "INTENT_RECORDED", "AUTHORIZED"]);
    const failureEvent = audit.find(event => event.request_id === refused.request_id && event.result === "PRECONDITION_FAILED");
    assert.deepEqual([failureEvent?.worktree, failureEvent?.task_id], [worktree, "task-1"]);
    // A stage refused before git ran (missing parent directory) settles the same way.
    const missingArgs = { project_root: worktree, paths: ["missing/file.txt"] };
    f.approve("mac_git_stage", missingArgs, worktree);
    const missing = failure(await f.handle("mac_git_stage", missingArgs));
    assert.equal(missing.result_class, "TARGET_NOT_FOUND"); assert.deepEqual([gitJobOf(f, missing.request_id).state, gitJobOf(f, missing.request_id).resultClass], ["failed", "failed"]);
    assert.equal(f.store.hasActiveWorktreeJobs(worktree, "job:git-preview"), false);
    // The next stage is admitted and the worktree can be removed without any unresolved job.
    const stageArgs = { project_root: worktree, paths: ["source.txt"] };
    f.approve("mac_git_stage", stageArgs, worktree); data(await f.handle("mac_git_stage", stageArgs));
    const removeArgs = { project_root: f.project, worktree, task_id: "task-1", idempotency_key: "remove-after-refusal" };
    f.approve("mac_git_worktree_remove", removeArgs); assert.equal(data(await f.handle("mac_git_worktree_remove", removeArgs)).removed, true);
    // The extra evidence keys must not make the ledger unreadable at startup.
    new BrokerStore(join(f.root, "broker.sqlite")).close();
  } finally { await f.close(); }
});

for (const [tool, error] of [
  ["mac_git_commit", new BrokerError("TIMEOUT", "Git process timed out")],
  ["mac_git_commit", new BrokerError("VERIFICATION_FAILED", "Git commit did not advance HEAD")],
  ["mac_git_commit", new Error("unexpected inspector failure")],
  ["mac_git_stage", new Error("unexpected inspector failure")]
] as const) {
  test(`V2 a ${tool} failure after the mutation boundary (${error instanceof BrokerError ? error.errorClass : "plain error"}) keeps its job unknown and the worktree pinned`, async () => {
    const crossing: GitWriteInspector = {
      async stage(_root, _paths, control) { control.beforeMutation?.(); throw error; },
      async commit(_root, _message, _digest, control) { control.beforeMutation?.(); throw error; }
    };
    const f = await setup(undefined, false, crossing); try {
      const worktree = (await f.create()).worktree as string;
      const args = tool === "mac_git_commit" ? { project_root: worktree, message: "May have committed" } : { project_root: worktree, paths: ["source.txt"] };
      f.approve(tool, args, worktree);
      const failed = failure(await f.handle(tool, args));
      assert.deepEqual([gitJobOf(f, failed.request_id).state, gitJobOf(f, failed.request_id).resultClass], ["unknown", "unknown"]);
      assert.equal(f.store.hasActiveWorktreeJobs(worktree, "job:git-preview"), true);
      const rows = requestRows(f, failed.request_id);
      assert.deepEqual(rows.map(row => row.event_type), ["decision", "intent", "completion"]);
      assert.equal(rows[2]!.result_class, failed.result_class);
      assert.equal((JSON.parse(rows[2]!.evidence_json as string) as Record<string, unknown>).worktree, worktree);
      const next = failure(await f.handle("mac_git_stage", { project_root: worktree, paths: ["source.txt"] }));
      assert.equal(next.result_class, "CONFLICT"); assert.match(next.error.message, /must wait for the worktree job to settle/u);
    } finally { await f.close(); }
  });
}

test("V2 a Git mutation whose authority is revoked before the spawn fails its job without having run git", async () => {
  let approvalId = "", reached = false;
  const revoking: GitWriteInspector = {
    async stage() { throw new Error("stage is not used"); },
    async commit(_root, _message, _digest, control) { f.store.revokeApproval(approvalId, "TEST_REVOKED", NOW); control.beforeMutation?.(); reached = true; throw new Error("unreachable after revocation"); }
  };
  const f = await setup(undefined, false, revoking); try {
    const worktree = (await f.create()).worktree as string;
    const args = { project_root: worktree, message: "Revoked before spawn" };
    approvalId = f.approve("mac_git_commit", args, worktree).approvalId;
    const cancelled = failure(await f.handle("mac_git_commit", args));
    assert.equal(cancelled.result_class, "CANCELLED"); assert.equal(reached, false);
    assert.deepEqual([gitJobOf(f, cancelled.request_id).state, gitJobOf(f, cancelled.request_id).resultClass], ["failed", "failed"]);
    assert.equal(f.store.requestRecord(cancelled.request_id)!.state, "CANCELLED");
    assert.equal(f.store.hasActiveWorktreeJobs(worktree, "job:git-preview"), false);
  } finally { await f.close(); }
});

test("V2 a pre-spawn Git failure whose failed write is rejected falls back to the unknown outcome", async () => {
  let worktree = "";
  const racing: GitWriteInspector = {
    async stage() { throw new Error("stage is not used"); },
    // A cancellation request bumps the job revision, so the failed write is rejected and only the unknown write is tolerated.
    async commit() { const pinned = f.store.projectPinningJobs([worktree], "principal-1").own[0]!; f.store.requestJobCancellation(pinned.jobId, "principal-1", "TEST_STOP", NOW); throw new BrokerError("PRECONDITION_FAILED", "Nothing is staged to commit; stage the intended paths with mac_git_stage first"); }
  };
  const f = await setup(undefined, false, racing); try {
    worktree = (await f.create()).worktree as string;
    const args = { project_root: worktree, message: "Cancelled while refused" };
    f.approve("mac_git_commit", args, worktree);
    const refused = failure(await f.handle("mac_git_commit", args));
    assert.equal(refused.result_class, "PRECONDITION_FAILED");
    assert.deepEqual([gitJobOf(f, refused.request_id).state, gitJobOf(f, refused.request_id).resultClass], ["unknown", "unknown"]);
    assert.equal(f.store.hasActiveWorktreeJobs(worktree, "job:git-preview"), true);
  } finally { await f.close(); }
});

const eventKey = (event: { request_id: string; result: string }) => `${event.request_id}:${event.result}`;

test("V2 mac_execution_audit pages older events through an opaque cursor and every page satisfies the contract", async () => {
  const f = await setup(); try {
    await f.create();
    for (let i = 0; i < 4; i++) data(await f.handle("mac_git_worktree_list", { project_root: f.project }));
    const firstResult = await f.handle("mac_execution_audit", { project_root: f.project, limit: 3 });
    const first = data(firstResult) as { events: { request_id: string; result: string }[]; truncated: boolean; next_cursor?: string };
    assert.equal(first.events.length, 3); assert.equal(first.truncated, true); assert.match(first.next_cursor!, /^[A-Za-z0-9_-]{1,64}$/u);
    const envelope = firstResult as unknown as { truncated: boolean; warnings: string[] };
    assert.equal(envelope.truncated, true); assert.ok(envelope.warnings.some(w => /limited to the newest 3/u.test(w) && /cursor=next_cursor/u.test(w)));
    // The cursor continues strictly before the last row of the page.
    const ledger = f.store.auditRows();
    const sequenceOf = (event: { request_id: string; result: string }) => ledger.find(row => row.request_id === event.request_id && row.result_class === event.result)!.sequence as number;
    assert.equal(decodeAuditCursor(first.next_cursor), sequenceOf(first.events[2]!));
    const contract = JSON.parse(await readFile(join(repositoryRoot, "tool-contracts", "mac_execution_audit.json"), "utf8"));
    const acceptsInput = ajv.compile(contract.input_schema);
    assert.equal(acceptsInput({ project_root: f.project, limit: 3, cursor: first.next_cursor }), true, ajv.errorsText(acceptsInput.errors));
    assert.equal(acceptsInput({ project_root: f.project, cursor: "MQ==" }), false); assert.equal(acceptsInput({ project_root: f.project, cursor: "" }), false);
    const newest = sequenceOf(first.events[0]!);
    const collected = [...first.events]; let cursor = first.next_cursor, last = first;
    for (let pages = 0; cursor !== undefined && pages < 40; pages++) {
      last = data(await f.handle("mac_execution_audit", { project_root: f.project, limit: 3, cursor })) as typeof first;
      collected.push(...last.events); cursor = last.next_cursor;
    }
    assert.equal(cursor, undefined); assert.equal(last.truncated, false); assert.equal("next_cursor" in last, false);
    const keys = collected.map(eventKey);
    assert.equal(new Set(keys).size, keys.length);
    const expected = f.store.executionAudit("principal-1", { project: f.project, limit: 100 }).filter(row => (row.sequence as number) <= newest).map(row => `${row.request_id}:${row.result_class}`);
    assert.deepEqual(keys, expected);
    assert.ok(collected.length > 3);
    // A page that ends exactly at the limit does not claim that more events exist.
    const everything = data(await f.handle("mac_execution_audit", { project_root: f.project, limit: 100 })) as typeof first;
    assert.equal(everything.truncated, false); assert.equal("next_cursor" in everything, false);
  } finally { await f.close(); }
});

test("V2 mac_execution_audit rejects malformed cursors and unknown arguments", async () => {
  const f = await setup(); try {
    const valid = encodeAuditCursor(5);
    assert.equal(decodeAuditCursor(valid), 5);
    for (const cursor of ["not*base64", "", "MA", "MDE", "MS41", "MQ==", encodeAuditCursor(2 ** 53), Buffer.from("12345678901234567").toString("base64url"), 7, null, {}]) {
      const refused = failure(await f.handle("mac_execution_audit", { project_root: f.project, cursor }));
      assert.equal(refused.result_class, "PRECONDITION_FAILED", String(cursor)); assert.match(refused.error.message, /cursor is malformed/u);
    }
    assert.equal(failure(await f.handle("mac_execution_audit", { project_root: f.project, cursor: valid, offset: 1 })).result_class, "PRECONDITION_FAILED");
    assert.equal(failure(await f.handle("mac_git_worktree_list", { project_root: f.project, cursor: valid })).result_class, "PRECONDITION_FAILED");
    data(await f.handle("mac_execution_audit", { project_root: f.project, cursor: valid }));
  } finally { await f.close(); }
});

async function settledRequest(f: Awaited<ReturnType<typeof setup>>, requestId: string) {
  for (let i = 0; i < 400; i++) { if (f.store.requestRecord(requestId)?.state !== "RUNNING") return f.store.requestRecord(requestId); await new Promise<void>(resolve => setTimeout(resolve, 5)); }
  assert.fail("Request did not settle");
}
async function runValidation(f: Awaited<ReturnType<typeof setup>>, worktree: string, task: string, key: string) {
  const args = { project_root: f.project, worktree, task_id: task, max_runtime: 500, idempotency_key: key };
  f.approve("mac_test_run", args); const started = await f.handle("mac_test_run", args); data(started);
  await settledRequest(f, started.request_id); return started.request_id;
}
async function laterProjectActivity(f: Awaited<ReturnType<typeof setup>>, after: string[]) {
  for (let i = 0; i < 60; i++) data(await f.handle("mac_git_status", { project_root: f.project }));
  for (let i = 0; i < 3; i++) data(await f.handle("mac_execution_audit", { project_root: f.project, limit: 100 }));
  // The newest-100 project view no longer reaches the runs, which is what used to blank the review evidence.
  const window = f.store.executionAudit("principal-1", { project: f.project, limit: 100 });
  for (const requestId of after) assert.equal(window.some(row => row.request_id === requestId), false, requestId);
}

test("V2 mac_pr_prepare keeps a finished run's test evidence after more than 100 later project rows and ignores other tasks", async () => {
  const f = await setup(); try {
    const worktree = (await f.create()).worktree as string; const other = (await f.create("task-2")).worktree as string;
    const first = await runValidation(f, worktree, "task-1", "evidence-1"); const otherRun = await runValidation(f, other, "task-2", "evidence-2");
    const second = await runValidation(f, worktree, "task-1", "evidence-3");
    await laterProjectActivity(f, [first, otherRun, second]);
    const review = data(await f.handle("mac_pr_prepare", { project_root: f.project, worktree }));
    assert.deepEqual(review.test_evidence, ["mac_test_run: SUCCEEDED", "mac_test_run: SUCCEEDED"]);
    assert.match(review.description as string, /Validation: mac_test_run: SUCCEEDED, mac_test_run: SUCCEEDED/u); assert.doesNotMatch(review.description as string, /No completed validation run recorded/u);
    assert.deepEqual(data(await f.handle("mac_pr_prepare", { project_root: f.project, worktree: other })).test_evidence, ["mac_test_run: SUCCEEDED"]);
    const untested = (await f.create("task-3")).worktree as string;
    const bare = data(await f.handle("mac_pr_prepare", { project_root: f.project, worktree: untested }));
    assert.deepEqual(bare.test_evidence, []); assert.match(bare.description as string, /No completed validation run recorded/u);
  } finally { await f.close(); }
});

for (const [state, resultClass, exitCode] of [["failed", "EXECUTION_FAILED", 1], ["timed_out", "TIMEOUT", null]] as const) {
  test(`V2 mac_pr_prepare keeps a ${resultClass} validation outcome after more than 100 later project rows`, async () => {
    const f = await setup(async () => ({ state, resultClass, exitCode, stdout: "", stderr: "synthetic outcome", truncated: false, durationMs: 1, verification: { status: "verified" as const } }));
    try {
      const worktree = (await f.create()).worktree as string;
      const run = await runValidation(f, worktree, "task-1", "evidence-failed");
      assert.equal(f.store.requestRecord(run)?.state === "SUCCEEDED", false);
      await laterProjectActivity(f, [run]);
      const review = data(await f.handle("mac_pr_prepare", { project_root: f.project, worktree }));
      assert.deepEqual(review.test_evidence, [`mac_test_run: ${resultClass}`]);
      assert.doesNotMatch(review.description as string, /No completed validation run recorded/u);
    } finally { await f.close(); }
  });
}
