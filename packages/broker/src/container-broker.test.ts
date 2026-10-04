import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { canonicalJson, sha256, signRequest, type BrokerResult, type Scope, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import type { ContainerTaskJobMetadata } from "./container-job-metadata.js";
import { ContainerTaskProfileRegistry } from "./container-task-profile.js";
import { createDefaultPolicy } from "./default-policy.js";
import { DevelopmentGateway, type CodingAgentProvider } from "./development-gateway.js";
import { DEVELOPMENT_TOOL_NAMES } from "./development-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import type { FilesystemRootPolicy } from "./filesystem-inspector.js";
import { ManagedWorktrees } from "./managed-worktrees.js";
import { BrokerStore } from "./persistence.js";
import type { ResolvedTaskProfile } from "./task-profile.js";
import { taskDescriptorDigest, type TaskExecutionControl, type TaskExecutionResult, type TaskRunner } from "./task-runner.js";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020").default;
const ajv = new Ajv2020({ strict: true, allErrors: true });
require("ajv-formats").default(ajv);
const validators = new Map<string, ReturnType<typeof ajv.compile>>();
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const NOW = 1_700_000_000_000;
const IMAGE = `sha256:${"a".repeat(64)}`;
const ENGINE = "container-broker-fixture";
const PROFILE = "fixture.test";
const scopes: Scope[] = ["mac.control.read", "mac.policy.explain", "mac.project.read", "mac.project.write", "mac.git.read", "mac.git.write", "mac.agent.read", "mac.agent.run", "mac.task.run", "mac.audit.read", "mac.job.read", "mac.job.cancel", "mac.files.read"];
const success = (): TaskExecutionResult => ({ state: "completed", resultClass: "SUCCEEDED", exitCode: 0, stdout: "fixture validation", stderr: "", truncated: false, durationMs: 1, verification: { status: "verified" }, containerCleanupVerified: true });
type RunContext = { store: BrokerStore; project: string; metadata: ContainerTaskJobMetadata; setClock: (ms: number) => void };
type FixtureOptions = {
  run?: (profile: ResolvedTaskProfile, control: TaskExecutionControl, context: RunContext) => Promise<TaskExecutionResult>;
  proofImage?: string;
  proofEngine?: string;
  recovery?: boolean;
  roots?: (root: string, project: string) => FilesystemRootPolicy[];
  /** Adds the mac.files.write, mac.files.search and mac.storage.read scopes and enables the two write tools the default policy keeps disabled. */
  ordinaryFileTools?: boolean;
};

function git(cwd: string, args: string[]): string {
  return execFileSync("/usr/bin/git", args, { cwd, encoding: "utf8", env: { GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null", GIT_TERMINAL_PROMPT: "0" } });
}

async function fixture(options: FixtureOptions = {}) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mac-container-broker-")));
  const project = join(root, "project"), state = join(root, "state"), trees = join(root, "trees");
  for (const path of [project, state, trees]) await mkdir(path, { mode: 0o700 });
  git(project, ["init", "-b", "main"]);
  git(project, ["config", "user.name", "Container Broker Fixture"]);
  git(project, ["config", "user.email", "fixture@example.invalid"]);
  const manifest = `${JSON.stringify({ name: "container-broker-fixture", scripts: { test: "node --test" } })}\n`;
  await writeFile(join(project, "package.json"), manifest);
  await writeFile(join(project, "source.txt"), "original\n");
  git(project, ["add", "--", "package.json", "source.txt"]);
  git(project, ["commit", "-m", "Fixture baseline"]);
  const primaryHead = git(project, ["rev-parse", "HEAD"]);
  const primaryIndex = await readFile(join(project, ".git", "index"));
  let registry: ManagedWorktrees;
  let gateway: DevelopmentGateway;
  let profiles: ContainerTaskProfileRegistry;
  let store = new BrokerStore(join(state, "broker.sqlite"));
  let calls = 0;
  // The Broker clock is mutable so a run can pass its token expiry. Keep any advance well under the 30 s job lease.
  let clock = NOW;
  const setClock = (ms: number): void => { clock = ms; };
  const recovered: ContainerTaskJobMetadata[] = [];
  const admitted: ContainerTaskJobMetadata[] = [];
  // This attestation is a protocol fixture, not evidence of real OS containment.
  const runner: TaskRunner = {
    available: true, publicEnablement: "production", mechanism: "docker-container",
    isolationProof: { schemaVersion: "0.1", sandboxMechanism: "docker-container", sandboxProfile: "docker-container", filesystem: "enforced", network: "enforced", credentials: "isolated", persistence: "isolated", credentialIsolation: "docker-container-no-host-credentials-v1", processTree: "owned", processTreePolicy: "owned_group", evidenceRef: "test://container-broker-protocol", containerImage: { imageId: options.proofImage ?? IMAGE, engineId: options.proofEngine ?? ENGINE } },
    async run(profile, control) {
      calls++;
      assert.equal(Object.isFrozen(profile), true);
      assert.equal(Object.isFrozen(profile.process), true);
      assert.deepEqual(profile.filesystemRoots, [profile.cwd]);
      assert.equal(profile.process.cwd, profile.cwd);
      assert.deepEqual(profile.process.environment, {});
      assert.equal(profile.networkPolicy, "none");
      assert.equal(profile.credentialPolicy, "none");
      const descriptor = profile.containerExecution;
      assert.ok(descriptor);
      const metadata: Omit<ContainerTaskJobMetadata, "taskDescriptorDigest"> = {
        schemaVersion: "0.1", containerId: sha256(`fixture-container-${calls}`), engineId: ENGINE, imageId: IMAGE,
        taskId: descriptor.taskId, owner: descriptor.owner, nonce: sha256(`fixture-nonce-${calls}`),
        recordedAtMs: NOW, deadlineAtMs: NOW + profile.process.timeoutMs, readonlyWorkspace: descriptor.readonlyWorkspace,
        maxRuntimeMs: profile.process.timeoutMs, memoryBytes: 512 * 1024 * 1024, nanoCpus: 1_000_000_000, pidsLimit: 128
      };
      assert.equal(typeof control.onContainerCreated, "function");
      control.onContainerCreated!(metadata);
      // The callback must finish durable admission before any task operation.
      const job = store.listUnresolvedTaskContainers().find(candidate => candidate.containerMetadata?.containerId === metadata.containerId);
      assert.ok(job?.containerMetadata);
      assert.equal(job.containerMetadata.taskDescriptorDigest, taskDescriptorDigest(profile));
      const admission = store.auditRows().find(row => row.request_id === `job-container-admit-${job.jobId}` && row.event_type === "completion");
      assert.equal(admission?.result_class, "CONTAINER_OWNERSHIP_RECORDED");
      const evidence = JSON.parse(admission!.evidence_json as string);
      assert.equal(evidence.metadataDigest, sha256(canonicalJson(job.containerMetadata)));
      admitted.push(structuredClone(job.containerMetadata));
      return options.run ? options.run(profile, control, { store, project, metadata: job.containerMetadata, setClock }) : success();
    },
    async recoverContainerTask(metadata) {
      assert.equal(metadata.engineId, ENGINE);
      assert.equal(metadata.imageId, IMAGE);
      recovered.push(structuredClone(metadata));
      return options.recovery !== false;
    }
  };
  const key = randomBytes(32);
  const roots = options.roots?.(root, project) ?? [{ rootId: "project", path: project, metadata: true, contentRead: true, write: true, denyRelativePaths: [] }];
  const callerScopes: Scope[] = options.ordinaryFileTools ? [...scopes, "mac.files.write", "mac.files.search", "mac.storage.read"] : scopes;
  const enabledTools = ["mac_task_run", "mac_git_stage", "mac_git_commit", ...(options.ordinaryFileTools ? ["mac_write_file_atomic", "mac_apply_patch"] : [])];
  const base = createDefaultPolicy("edge-1", true, callerScopes, ["edge-key-1"], roots, [], [], [project], [], [PROFILE]);
  const tools = new Map([...base.tools].map(([name, policy]) => [name, { ...policy, enabled: DEVELOPMENT_TOOL_NAMES.includes(name) || enabledTools.includes(name) ? true : policy.enabled }]));
  const policy = { ...base, tools, targetRules: [...base.targetRules, ...callerScopes.map((scope, index) => ({ ruleId: `container-project-${index}`, effect: "allow" as const, principalId: "principal-1", scope, target: { kind: "project" as const, reference: project } }))] };
  function buildBroker() {
    registry = new ManagedWorktrees(state, trees);
    profiles = new ContainerTaskProfileRegistry({ imageId: IMAGE, engineId: ENGINE,
      entries: [{ profile: PROFILE, projectRoot: project, manifestPath: "package.json", manifestSha256: sha256(manifest), scriptName: "test", scriptValue: "node --test", command: ["/usr/local/bin/node", "--test"], timeoutMs: 2000, outputCapBytes: 4096 }],
      async validateWorkspace(cwd, projectRoot, taskId) { registry.require(cwd, projectRoot, "principal-1", taskId); return { owner: "principal-1", isWorktree: true }; },
      async validateRuntime() { return true; },
      async preflight() { return { installed: true, version: "0.153.4", authentication: "authenticated", supportedModels: ["coding-test"], executableSha256: "b".repeat(64), catalogSha256: "c".repeat(64), reasonCodes: [] }; }
    });
    const provider: CodingAgentProvider = {
      readiness: { installed: true, version: "0.153.4", authentication: "ready", supportedModels: ["coding-test"], enforcedProfiles: ["readonly", "workspace-write", "test-only"], hostGitDenied: true, networkPolicies: ["none"] },
      async resolve(input, record) { return profiles.resolveAgent({ cwd: record.worktree, projectRoot: record.projectRoot, taskId: record.taskId, task: input.task as string, executionProfile: input.execution_profile as "readonly" | "workspace-write" | "test-only", maxRuntimeMs: input.max_runtime as number, ...(input.model === undefined ? {} : { model: input.model as string }), ...(input.allowed_paths === undefined ? {} : { allowedPaths: input.allowed_paths as string[] }) }); }
    };
    gateway = new DevelopmentGateway({ worktrees: registry, codingAgent: provider, commands: [{ projectRoot: project, type: "test", profile: PROFILE }] });
    return new Broker({ store, policy, developmentGateway: gateway, taskRunner: runner, taskProfileRegistry: profiles, now: () => clock,
      edgeAuthenticationKeys: new EdgeKeyring([{ edgeId: "edge-1", keyId: "edge-key-1", key, notBeforeMs: NOW - 1000, expiresAtMs: NOW + 120_000 }]) });
  }
  let broker = buildBroker();
  let index = 0;
  function request(tool: string, args: Record<string, unknown>, expiresAtMs = NOW + 60_000): UnsignedBrokerRequest {
    return { protocolVersion: "0.1", requestId: `container-request-${++index}`, contractVersion: "0.1", tool, arguments: args,
      principal: { principalId: "principal-1", sessionId: "session-1", issuer: "test-issuer", audience: "mac-operator-broker", scopes: callerScopes, issuedAtMs: NOW - 1000, expiresAtMs, edgeId: "edge-1" },
      timestampMs: clock, nonce: `container-nonce-${index}`, policyAudience: "mac-operator-broker", policyVersion: "policy-0.1", authenticationKeyId: "edge-key-1" };
  }
  function approve(tool: string, args: Record<string, unknown>) {
    const task = tool === "mac_task_run";
    store.issueApproval({ approvalId: `approval:container-${++index}`, approverPrincipalId: "operator-1", requestingPrincipalId: "principal-1", tool, contractVersion: "0.1", targetKind: task ? "task_profile" : "project", targetRef: task ? `task_profile:${PROFILE}` : `project:${project}`, payloadDigest: sha256(canonicalJson(args)), policyVersion: "policy-0.1", approvalClass: ["mac_test_run", "mac_build_run", "mac_codex_run", "mac_task_run"].includes(tool) ? "trusted_profile" : "trusted_write", unattended: false, issuedAtMs: NOW - 1000, expiresAtMs: NOW + 60_000 });
  }
  async function handle(tool: string, args: Record<string, unknown>, expiresAtMs?: number) { return broker.handle(signRequest(request(tool, args, expiresAtMs), key)); }
  async function create(task = "task-1") {
    const args = { project_root: project, branch_name: `codex/${task}`, base_ref: "HEAD", task_id: task, idempotency_key: `create-${task}` };
    approve("mac_git_worktree_create", args);
    return data(await handle("mac_git_worktree_create", args)).worktree as string;
  }
  async function validate(worktree: string, idempotency = "validate", task = "task-1") {
    const args = { project_root: project, worktree, task_id: task, max_runtime: 500, idempotency_key: idempotency };
    approve("mac_test_run", args);
    return { args, receipt: data(await handle("mac_test_run", args)) };
  }
  async function primaryUnchanged() {
    assert.equal(git(project, ["rev-parse", "HEAD"]), primaryHead);
    assert.deepEqual(await readFile(join(project, ".git", "index")), primaryIndex);
    assert.equal(await readFile(join(project, "source.txt"), "utf8"), "original\n");
    assert.equal(git(project, ["status", "--porcelain"]), "");
  }
  return { root, project, state, trees, handle, approve, create, validate, primaryUnchanged,
    get store() { return store; }, get broker() { return broker; }, get gateway() { return gateway; }, get profiles() { return profiles; },
    get calls() { return calls; }, admitted, recovered, setClock,
    async reopen() { await broker.close(); store.close(); store = new BrokerStore(join(state, "broker.sqlite")); broker = buildBroker(); },
    async close() { await broker.close(); store.close(); await rm(root, { recursive: true, force: true }); }
  };
}

function data(result: BrokerResult): Record<string, unknown> {
  assert.equal(result.ok, true, JSON.stringify(result));
  if (!result.ok) throw new Error("Expected successful receipt");
  return result.data as Record<string, unknown>;
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
async function settle(f: Fixture, receipt: Record<string, unknown>) {
  for (let count = 0; count < 300; count++) {
    const job = f.store.ownedJob(receipt.job_id as string, "principal-1");
    if (job && !["running", "queued"].includes(job.state)) return job;
    await new Promise<void>(resolve => setTimeout(resolve, 5));
  }
  assert.fail("Container job did not settle");
}
function sourceWrites(f: Fixture) { return f.store.auditRows().filter(row => row.result_class === "SOURCE_WRITE_INTENT" || row.result_class === "SOURCE_WRITE_VERIFIED"); }
/** Returns the warnings of a successful accept receipt after checking the whole receipt against the versioned tool contract. */
async function receiptWarnings(result: BrokerResult): Promise<string[]> {
  assert.equal(result.ok, true, JSON.stringify(result));
  if (!result.ok) throw new Error("Expected successful receipt");
  let validate = validators.get(result.tool);
  if (!validate) {
    const contract = JSON.parse(await readFile(join(repositoryRoot, "tool-contracts", `${result.tool}.json`), "utf8"));
    validate = ajv.compile(contract.output_schema);
    validators.set(result.tool, validate);
  }
  assert.equal(validate(result), true, `${result.tool}: ${ajv.errorsText(validate.errors)}`);
  return result.warnings;
}
const reuseWarning = (jobId: unknown, state: string) => `IDEMPOTENT_REUSE: ${jobId} is ${state}; nothing was run again. Use a new idempotency_key to run it again.`;
// Access token expiry used by the expiry tests: the stubbed run moves the clock just past it, within the 30 s job lease.
const EXPIRES_SOON = NOW + 10_000;
const expiringRun: FixtureOptions["run"] = async (_profile, control, context) => {
  context.setClock(EXPIRES_SOON + 1_000);
  assert.equal(control.shouldCancel(), true);
  return success();
};

test("Container Broker durably binds exact ownership before execution and clears it after verified cleanup", async () => {
  const f = await fixture();
  try {
    const worktree = await f.create();
    const { receipt } = await f.validate(worktree);
    assert.equal("stdout" in receipt, false);
    const job = await settle(f, receipt);
    assert.equal(job.state, "completed");
    assert.equal(job.containerMetadata, undefined);
    assert.equal(f.admitted.length, 1);
    assert.equal(f.admitted[0]!.taskId, "task-1");
    assert.equal(f.admitted[0]!.owner, "principal-1");
    assert.equal(f.admitted[0]!.imageId, IMAGE);
    assert.equal(f.admitted[0]!.engineId, ENGINE);
    assert.equal(f.store.listUnresolvedTaskContainers().length, 0);
    f.store.verifyAuditIntegrity();
    await f.primaryUnchanged();
  } finally { await f.close(); }
});

test("Container Broker requires cleanup proof before accepting a claimed terminal success", async () => {
  const f = await fixture({ async run() { const result = success(); delete result.containerCleanupVerified; return result; } });
  try {
    const worktree = await f.create();
    const { receipt } = await f.validate(worktree);
    const job = await settle(f, receipt);
    assert.equal(job.state, "unknown");
    assert.deepEqual(job.containerMetadata, f.admitted[0]);
    assert.equal(f.store.listUnresolvedTaskContainers().length, 1);
    await f.primaryUnchanged();
  } finally { await f.close(); }
});

test("Container Broker preserves per-path audits when a verified partial import later fails", async () => {
  const f = await fixture({ async run(profile, control) {
    control.onWorkspaceImport!("source.txt", "intent");
    await writeFile(join(profile.cwd, "source.txt"), "verified partial import\n");
    control.onWorkspaceImport!("source.txt", "verified");
    return { ...success(), state: "failed", resultClass: "EXECUTION_FAILED", exitCode: 1, changedPaths: ["source.txt"], verification: { status: "failed", summary: "A later fixture import failed" } };
  } });
  try {
    const worktree = await f.create();
    const { args, receipt } = await f.validate(worktree);
    const job = await settle(f, receipt);
    assert.equal(job.state, "failed");
    assert.equal(job.containerMetadata, undefined);
    assert.equal(await readFile(join(worktree, "source.txt"), "utf8"), "verified partial import\n");
    const rows = sourceWrites(f);
    assert.deepEqual(rows.map(row => row.result_class), ["SOURCE_WRITE_INTENT", "SOURCE_WRITE_VERIFIED"]);
    for (const row of rows) {
      const evidence = JSON.parse(row.evidence_json as string);
      assert.equal(row.principal_id, "principal-1");
      assert.equal(row.tool, "mac_test_run");
      assert.equal(row.target_ref, `project:${f.project}`);
      assert.equal(evidence.jobId, receipt.job_id);
      assert.equal(evidence.taskId, "task-1");
      assert.equal(evidence.worktree, worktree);
      assert.deepEqual(evidence.changedPaths, ["source.txt"]);
    }
    const repeated = data(await f.handle("mac_test_run", args));
    assert.equal(repeated.job_id, receipt.job_id);
    assert.equal(f.calls, 1);
    assert.equal(sourceWrites(f).length, 2);
    f.store.verifyAuditIntegrity();
    await f.primaryUnchanged();
  } finally { await f.close(); }
});

test("Container Broker retries pending and completed requests without replaying the task", async () => {
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  const f = await fixture({ async run() { await pending; return success(); } });
  try {
    const worktree = await f.create();
    const { args, receipt } = await f.validate(worktree);
    const pendingRetry = data(await f.handle("mac_test_run", args));
    assert.equal(pendingRetry.job_id, receipt.job_id);
    release();
    assert.equal((await settle(f, receipt)).state, "completed");
    const completedRetry = data(await f.handle("mac_test_run", args));
    assert.equal(completedRetry.job_id, receipt.job_id);
    assert.equal(f.calls, 1);
    assert.equal(f.admitted.length, 1);
    await f.primaryUnchanged();
  } finally { release(); await f.close(); }
});

for (const mismatch of ["image", "engine"] as const) {
  test(`Container Broker rejects isolation proof with another ${mismatch} before task execution`, async () => {
    const f = await fixture(mismatch === "image" ? { proofImage: `sha256:${"f".repeat(64)}` } : { proofEngine: "other-engine" });
    try {
      const worktree = await f.create();
      const args = { project_root: f.project, worktree, task_id: "task-1", max_runtime: 500, idempotency_key: `forged-${mismatch}` };
      f.approve("mac_test_run", args);
      const result = await f.handle("mac_test_run", args);
      if (result.ok) assert.notEqual((await settle(f, data(result))).state, "completed");
      assert.equal(f.calls, 0);
      assert.equal(f.admitted.length, 0);
      await f.primaryUnchanged();
    } finally { await f.close(); }
  });
}

test("Container Broker restart recovery uses exact durable metadata and records failed cleanup without replay", async () => {
  const f = await fixture({ async run() { return { ...success(), state: "unknown", resultClass: "UNKNOWN_OUTCOME", exitCode: null, verification: { status: "unknown" }, containerCleanupVerified: false }; } });
  try {
    const worktree = await f.create();
    const { args, receipt } = await f.validate(worktree);
    const before = await settle(f, receipt);
    assert.equal(before.state, "unknown");
    const metadata = structuredClone(before.containerMetadata);
    assert.ok(metadata);
    await f.reopen();
    assert.deepEqual(f.store.ownedJob(receipt.job_id as string, "principal-1")?.containerMetadata, metadata);
    assert.deepEqual(await f.broker.reconcileRestartedContainerTasks(), { inspected: 1, cleaned: 1, unresolved: 0 });
    assert.deepEqual(f.recovered, [metadata]);
    const recoveredJob = f.store.ownedJob(receipt.job_id as string, "principal-1");
    assert.equal(recoveredJob?.state, "failed");
    assert.equal(recoveredJob?.containerMetadata, undefined);
    assert.equal(f.calls, 1);
    assert.equal(data(await f.handle("mac_test_run", args)).job_id, receipt.job_id);
    assert.equal(f.calls, 1);
    assert.ok(f.store.auditRows().some(row => row.tool === "internal_container_recovery" && row.result_class === "CONTAINER_CLEANUP_VERIFIED"));
    f.store.verifyAuditIntegrity();
    await f.primaryUnchanged();
  } finally { await f.close(); }
});

test("Container Broker keeps unknown ownership when restart cleanup cannot be verified", async () => {
  const f = await fixture({ recovery: false, async run() { return { ...success(), state: "unknown", resultClass: "UNKNOWN_OUTCOME", verification: { status: "unknown" }, containerCleanupVerified: false }; } });
  try {
    const worktree = await f.create();
    const { receipt } = await f.validate(worktree);
    const before = await settle(f, receipt);
    await f.reopen();
    assert.deepEqual(await f.broker.reconcileRestartedContainerTasks(), { inspected: 1, cleaned: 0, unresolved: 1 });
    const job = f.store.ownedJob(receipt.job_id as string, "principal-1");
    assert.equal(job?.state, "unknown");
    assert.deepEqual(job?.containerMetadata, before.containerMetadata);
    assert.equal(f.calls, 1);
  } finally { await f.close(); }
});

test("Container Broker named tasks retain unresolved worktree ownership across restart and idempotent replay", async () => {
  const f = await fixture({ recovery: false, async run() {
    return { ...success(), state: "unknown", resultClass: "UNKNOWN_OUTCOME", verification: { status: "unknown" }, containerCleanupVerified: false };
  } });
  try {
    const worktree = await f.create();
    const args = { profile: PROFILE, cwd: worktree, task_id: "task-1", max_runtime: 500, idempotency_key: "unresolved-task" };
    f.approve("mac_task_run", args);
    const receipt = data(await f.handle("mac_task_run", args));
    const before = await settle(f, receipt);
    assert.equal(before.state, "unknown");
    assert.ok(before.containerMetadata);
    await f.reopen();
    assert.deepEqual(await f.broker.reconcileRestartedContainerTasks(), { inspected: 1, cleaned: 0, unresolved: 1 });

    const replay = data(await f.handle("mac_task_run", args));
    assert.equal(replay.job_id, receipt.job_id);
    assert.equal(replay.reused, true);
    assert.equal(f.calls, 1);

    const differentTask = { ...args, idempotency_key: "different-task-on-unresolved-worktree" };
    f.approve("mac_task_run", differentTask);
    const denied = await f.handle("mac_task_run", differentTask);
    assert.equal(denied.ok, false);
    assert.equal(denied.result_class, "CONFLICT");
    assert.equal(f.calls, 1);
    assert.equal(f.store.listUnresolvedTaskContainers().length, 1);
    assert.deepEqual(f.store.ownedJob(receipt.job_id as string, "principal-1")?.containerMetadata, before.containerMetadata);
    f.store.verifyAuditIntegrity();
    await f.primaryUnchanged();
  } finally { await f.close(); }
});

test("Container Broker named task intent keeps the original project and isolated worktree in its audit evidence", async () => {
  const f = await fixture();
  try {
    const worktree = await f.create();
    const args = { profile: PROFILE, cwd: worktree, task_id: "task-1", max_runtime: 500, idempotency_key: "project-audit" };
    f.approve("mac_task_run", args);
    const receipt = data(await f.handle("mac_task_run", args));
    const job = await settle(f, receipt);
    assert.equal(job.state, "completed");
    const intent = f.store.auditRows().find(row => row.tool === "mac_task_run" && row.event_type === "intent");
    assert.ok(intent);
    const evidence = JSON.parse(intent.evidence_json as string);
    assert.equal(evidence.project, f.project);
    assert.equal(evidence.worktree, worktree);
    assert.equal(evidence.taskId, "task-1");
    assert.equal(evidence.jobId, receipt.job_id);
    const projected = f.store.executionAudit("principal-1", { project: f.project, limit: 100 });
    assert.ok(projected.some(row => row.tool === "mac_task_run" && row.request_id === intent.request_id && row.result_class === "INTENT_RECORDED"));
    f.store.verifyAuditIntegrity();
    await f.primaryUnchanged();
  } finally { await f.close(); }
});

test("Container Broker named task profiles require the exact owned worktree and task", async () => {
  const f = await fixture();
  try {
    const worktree = await f.create();
    const unowned = join(f.root, "unowned");
    await mkdir(unowned);
    await writeFile(join(unowned, "package.json"), await readFile(join(f.project, "package.json")));
    for (const [cwd, taskId] of [[f.project, "task-1"], [unowned, "task-1"], [worktree, "another-task"]]) {
      const args = { profile: PROFILE, cwd, args: [], async: true, task_id: taskId, max_runtime: 500, idempotency_key: `blocked-${sha256(`${cwd}:${taskId}`).slice(0, 16)}` };
      f.approve("mac_task_run", args);
      const result = await f.handle("mac_task_run", args);
      if (result.ok) assert.notEqual((await settle(f, data(result))).state, "completed");
      assert.equal(f.calls, 0);
    }
    const args = { profile: PROFILE, cwd: worktree, args: [], async: true, task_id: "task-1", max_runtime: 500, idempotency_key: "owned-task" };
    f.approve("mac_task_run", args);
    const receipt = data(await f.handle("mac_task_run", args));
    assert.equal((await settle(f, receipt)).state, "completed");
    assert.equal(f.calls, 1);
    await f.primaryUnchanged();
  } finally { await f.close(); }
});

for (const executionProfile of ["readonly", "workspace-write", "test-only"] as const) {
  test(`Container Broker ${executionProfile} coding profile locks the descriptor to one managed worktree`, async () => {
    const f = await fixture({ async run(profile) {
      assert.equal(profile.containerExecution?.readonlyWorkspace, executionProfile !== "workspace-write");
      assert.equal(profile.containerExecution?.agent?.executionProfile, executionProfile);
      assert.deepEqual(profile.containerExecution?.agent?.allowedPaths, ["source.txt"]);
      return success();
    } });
    try {
      const worktree = await f.create();
      const args = { project_root: f.project, worktree, task: "Synthetic protocol fixture", task_id: "task-1", execution_profile: executionProfile, max_runtime: 500, idempotency_key: `agent-${executionProfile}`, network_policy: "none", model: "coding-test", allowed_paths: ["source.txt"] };
      f.approve("mac_codex_run", args);
      const receipt = data(await f.handle("mac_codex_run", args));
      assert.equal((await settle(f, receipt)).state, "completed");
      assert.equal(f.calls, 1);
      await f.primaryUnchanged();
    } finally { await f.close(); }
  });
}

test("Container Broker permits an ancestor filesystem root only when state and all-worktree storage are explicitly denied", async () => {
  const f = await fixture({ roots(root) { return [{ rootId: "ancestor", path: root, metadata: true, contentRead: true, write: true, denyRelativePaths: ["state", "trees"] }]; } });
  try {
    assert.doesNotThrow(() => f.gateway.assertProtectedStorage([{ path: f.root, denyRelativePaths: ["state", "trees"] }]));
    for (const denied of [[], ["state"], ["trees"], ["state/broker.sqlite", "trees/task-1"]]) {
      assert.throws(() => f.gateway.assertProtectedStorage([{ path: f.root, denyRelativePaths: denied }]), /ordinary filesystem roots/u);
    }
    const worktree = await f.create();
    const { receipt } = await f.validate(worktree);
    assert.equal((await settle(f, receipt)).state, "completed");
    const ordinaryRead = data(await f.handle("mac_read_file", { path: join(f.project, "source.txt") }));
    assert.equal(ordinaryRead.content, "original\n");
    for (const path of [join(f.state, "broker.sqlite"), join(worktree, "source.txt")]) {
      const denied = await f.handle("mac_read_file", { path });
      assert.equal(denied.ok, false);
      assert.equal(denied.result_class, "POLICY_DENIED");
    }
    await f.primaryUnchanged();
  } finally { await f.close(); }
});

test("Container Broker cancellation preserves verified write audit and refuses to report success", async () => {
  const f = await fixture({ async run(profile, control, context) {
    control.onWorkspaceImport!("source.txt", "intent");
    await writeFile(join(profile.cwd, "source.txt"), "write before cancellation\n");
    const job = context.store.listUnresolvedTaskContainers()[0]!;
    context.store.requestJobCancellation(job.jobId, "principal-1", "fixture cancellation", NOW);
    assert.equal(control.shouldCancel(), true);
    control.onWorkspaceImport!("source.txt", "verified");
    return { ...success(), state: "cancelled", resultClass: "CANCELLED", exitCode: null, changedPaths: ["source.txt"], verification: { status: "not_run" } };
  } });
  try {
    const worktree = await f.create();
    const { receipt } = await f.validate(worktree);
    const job = await settle(f, receipt);
    assert.equal(job.state, "cancelled");
    assert.equal(job.cancelRequested, true);
    assert.equal(job.containerMetadata, undefined);
    assert.equal(sourceWrites(f).length, 2);
    f.store.verifyAuditIntegrity();
    await f.primaryUnchanged();
  } finally { await f.close(); }
});

test("Container Broker authority revocation cannot erase evidence of a verified earlier write", async () => {
  const f = await fixture({ async run(profile, control, context) {
    control.onWorkspaceImport!("source.txt", "intent");
    await writeFile(join(profile.cwd, "source.txt"), "write before revocation\n");
    context.store.revoke("session", "session-1", "fixture revocation", NOW);
    assert.equal(control.shouldCancel(), true);
    control.onWorkspaceImport!("source.txt", "verified");
    return { ...success(), state: "failed", resultClass: "EXECUTION_FAILED", exitCode: null, changedPaths: ["source.txt"], verification: { status: "not_run" } };
  } });
  try {
    const worktree = await f.create();
    const { receipt } = await f.validate(worktree);
    const job = await settle(f, receipt);
    assert.equal(job.state, "cancelled");
    assert.equal(job.containerMetadata, undefined);
    assert.match(job.stderr, /authority was revoked or the policy changed/u);
    assert.match(job.stderr, /NEW idempotency_key/u);
    assert.equal(sourceWrites(f).length, 2);
    assert.equal(await readFile(join(worktree, "source.txt"), "utf8"), "write before revocation\n");
    f.store.verifyAuditIntegrity();
    await f.primaryUnchanged();
  } finally { await f.close(); }
});

test("Container Broker authority revocation without verified cleanup preserves unknown ownership", async () => {
  const f = await fixture({ async run(_profile, control, context) {
    context.store.revoke("session", "session-1", "fixture revocation", NOW);
    assert.equal(control.shouldCancel(), true);
    return { ...success(), containerCleanupVerified: false };
  } });
  try {
    const worktree = await f.create();
    const { receipt } = await f.validate(worktree);
    const job = await settle(f, receipt);
    assert.equal(job.state, "unknown");
    assert.deepEqual(job.containerMetadata, f.admitted[0]);
    assert.equal(f.calls, 1);
    f.store.verifyAuditIntegrity();
    await f.primaryUnchanged();
  } finally { await f.close(); }
});

test("Container Broker cancellation racing with a claimed success retains verified cleanup without success", async () => {
  const f = await fixture({ async run(_profile, _control, context) {
    const job = context.store.listUnresolvedTaskContainers()[0]!;
    context.store.requestJobCancellation(job.jobId, "principal-1", "fixture cancellation race", NOW);
    return success();
  } });
  try {
    const worktree = await f.create();
    const { receipt } = await f.validate(worktree);
    const job = await settle(f, receipt);
    assert.equal(job.state, "cancelled");
    assert.equal(job.cancelRequested, true);
    assert.equal(job.containerMetadata, undefined);
    f.store.verifyAuditIntegrity();
    await f.primaryUnchanged();
  } finally { await f.close(); }
});

test("Container Broker cancels a run whose access token expires and tells the client what to do next", async () => {
  const f = await fixture({ run: expiringRun });
  try {
    const worktree = await f.create();
    const args = { project_root: f.project, worktree, task_id: "task-1", max_runtime: 500, idempotency_key: "token-expiry" };
    f.approve("mac_test_run", args);
    const receipt = data(await f.handle("mac_test_run", args, EXPIRES_SOON));
    const job = await settle(f, receipt);
    assert.equal(job.state, "cancelled");
    assert.equal(job.containerMetadata, undefined);
    assert.equal(f.store.listUnresolvedTaskContainers().length, 0);
    assert.equal(f.calls, 1);
    assert.match(job.stderr, /access token that authorized it expired at/u);
    assert.ok(job.stderr.includes(new Date(EXPIRES_SOON).toISOString()), job.stderr);
    assert.match(job.stderr, /NEW idempotency_key/u);
    // The client reads the same text through mac_job_status.
    const status = data(await f.handle("mac_job_status", { job_id: receipt.job_id }));
    assert.equal(status.state, "cancelled");
    assert.equal(status.stderr, job.stderr);
    f.store.verifyAuditIntegrity();
    await f.primaryUnchanged();
  } finally { await f.close(); }
});

test("Container Broker returns the cancelled job for the same key after an expiry cancel and says nothing was run again", async () => {
  const f = await fixture({ run: expiringRun });
  try {
    const worktree = await f.create();
    const args = { project_root: f.project, worktree, task_id: "task-1", max_runtime: 500, idempotency_key: "token-expiry-retry" };
    f.approve("mac_test_run", args);
    const first = await f.handle("mac_test_run", args, EXPIRES_SOON);
    assert.deepEqual(await receiptWarnings(first), []);
    const receipt = data(first);
    assert.equal((await settle(f, receipt)).state, "cancelled");
    // The client refreshed its token, but kept the idempotency key: the recorded outcome comes back and no run starts.
    const retry = await f.handle("mac_test_run", args);
    const retried = data(retry);
    assert.equal(retried.job_id, receipt.job_id);
    assert.equal(retried.state, "cancelled");
    assert.deepEqual(await receiptWarnings(retry), [reuseWarning(receipt.job_id, "cancelled")]);
    assert.equal(f.calls, 1);
    assert.equal(f.admitted.length, 1);
    await f.primaryUnchanged();
  } finally { await f.close(); }
});

test("Container Broker accept receipts warn only when the token expires before max_runtime and flag idempotent reuse", async () => {
  const f = await fixture();
  try {
    const worktree = await f.create();
    const base = { project_root: f.project, worktree, task_id: "task-1" };
    const tokenWarning = /^The access token authorizing this task expires in 1s but the task may run up to 2s; a task still running at expiry is cancelled, and a re-run needs a NEW idempotency_key because the same key returns the cancelled job$/u;

    // The default token outlives a 500 ms budget: no warning on a fresh admission, only the reuse note on a replay.
    const quick = { ...base, max_runtime: 500, idempotency_key: "warn-quick" };
    f.approve("mac_test_run", quick);
    const quickFresh = await f.handle("mac_test_run", quick);
    assert.deepEqual(await receiptWarnings(quickFresh), []);
    const quickReceipt = data(quickFresh);
    assert.equal((await settle(f, quickReceipt)).state, "completed");
    assert.deepEqual(await receiptWarnings(await f.handle("mac_test_run", quick)), [reuseWarning(quickReceipt.job_id, "completed")]);

    // A token with 1 s left against a 1.5 s budget warns, and a replay carries both notes.
    const long = { ...base, max_runtime: 1500, idempotency_key: "warn-long" };
    f.approve("mac_test_run", long);
    const longFresh = await receiptWarnings(await f.handle("mac_test_run", long, NOW + 1_000));
    assert.equal(longFresh.length, 1);
    assert.match(longFresh[0]!, tokenWarning);
    assert.doesNotMatch(longFresh[0]!, /authority ended/u);
    const longReceipt = data(await f.handle("mac_test_run", long, NOW + 1_000));
    assert.equal((await settle(f, longReceipt)).state, "completed");
    const longReplay = await receiptWarnings(await f.handle("mac_test_run", long, NOW + 1_000));
    assert.equal(longReplay.length, 2);
    assert.equal(longReplay[0], reuseWarning(longReceipt.job_id, "completed"));
    assert.match(longReplay[1]!, tokenWarning);
    assert.equal(f.calls, 2);
    await f.primaryUnchanged();
  } finally { await f.close(); }
});

test("Container Broker labels a task cancelled by Broker shutdown separately from revoked authority", async () => {
  let f!: Fixture;
  f = await fixture({ async run(_profile, control) {
    // close() fences the Broker synchronously; it settles once this run has returned.
    void f.broker.close();
    assert.equal(control.shouldCancel(), true);
    return success();
  } });
  try {
    const worktree = await f.create();
    const { receipt } = await f.validate(worktree);
    const job = await settle(f, receipt);
    assert.equal(job.state, "cancelled");
    assert.equal(job.containerMetadata, undefined);
    assert.match(job.stderr, /Broker was shutting down/u);
    assert.doesNotMatch(job.stderr, /revoked/u);
    assert.match(job.stderr, /NEW idempotency_key/u);
  } finally { await f.close(); }
});

/** Mirrors the MBA layout: a project write root plus a read-only ancestor root that denies gateway state and all-task storage. */
const mbaLikeRoots = (root: string, project: string): FilesystemRootPolicy[] => [
  { rootId: "project", path: project, metadata: true, contentRead: true, write: true, denyRelativePaths: [] },
  { rootId: "ancestor", path: root, metadata: true, contentRead: true, write: false, denyRelativePaths: ["state", "trees"] }
];
const GENERIC_ZONE_DENIAL = "Filesystem path is inside a denied zone";
const GENERIC_WRITE_DENIAL = /^Filesystem root does not grant write for this path/u;
const gatewayControl = { timeoutMs: 30_000, shouldCancel: () => false };

/** Returns the message of a POLICY_DENIED failure after checking the whole envelope against the versioned failure schema. */
async function denialMessage(result: BrokerResult): Promise<string> {
  assert.equal(result.ok, false, JSON.stringify(result));
  if (result.ok) throw new Error("Expected a denial");
  let validate = validators.get("broker-failure");
  if (!validate) {
    validate = ajv.compile(JSON.parse(await readFile(join(repositoryRoot, "schemas", "broker-failure.schema.json"), "utf8")));
    validators.set("broker-failure", validate);
  }
  assert.equal(validate(result), true, ajv.errorsText(validate.errors));
  assert.equal(result.result_class, "POLICY_DENIED");
  return result.error.message;
}

async function explainDenial(f: Fixture, proposedTool: string, path: string): Promise<unknown> {
  const result = await f.handle("mac_policy_explain", { proposed_tool: proposedTool, target: { kind: "path", reference: path } });
  await receiptWarnings(result);
  const explanation = data(result);
  assert.equal(explanation.decision, "deny");
  return explanation.reason_codes;
}

test("Container Broker names the managed worktree when every ordinary path tool is denied inside it", async () => {
  const f = await fixture({ ordinaryFileTools: true, roots: mbaLikeRoots });
  try {
    const worktree = await f.create();
    const file = join(worktree, "source.txt");
    const patch = "--- a/source.txt\n+++ b/source.txt\n@@ -1 +1 @@\n-original\n+changed\n";
    const calls: Array<[string, Record<string, unknown>]> = [
      ["mac_list_directory", { path: worktree }],
      ["mac_directory_tree", { path: worktree }],
      ["mac_read_file", { path: file }],
      ["mac_stat_path", { path: file }],
      ["mac_write_file_atomic", { path: file, content: "changed\n", idempotency_key: "worktree-write" }],
      ["mac_apply_patch", { project_root: worktree, patch }],
      ["mac_find_files", { roots: [worktree], query: "source" }],
      ["mac_recent_files", { roots: [worktree], since_seconds: 3600 }],
      ["mac_search_text", { roots: [worktree], query: "original" }],
      ["mac_project_discover", { roots: [worktree] }],
      ["mac_project_summary", { project_root: worktree }],
      ["mac_storage_analysis", { roots: [worktree] }]
    ];
    for (const [tool, args] of calls) {
      const message = await denialMessage(await f.handle(tool, args));
      assert.match(message, /managed worktree/u, tool);
      assert.match(message, /mac_codex_run/u, tool);
    }
    // The explanation carries the same stable reason code for a content-read denial and for a write denial.
    for (const tool of ["mac_list_directory", "mac_write_file_atomic"]) {
      assert.deepEqual(await explainDenial(f, tool, file), ["POLICY_DENIED", "MANAGED_WORKTREE_PATH"]);
    }
    assert.equal(await readFile(file, "utf8"), "original\n");
    await f.primaryUnchanged();
  } finally { await f.close(); }
});

test("Container Broker keeps the generic path denial outside the caller's own active managed worktree", async () => {
  const f = await fixture({ ordinaryFileTools: true, roots: mbaLikeRoots });
  try {
    const worktree = await f.create();
    const removed = await f.create("task-removed");
    const removeArgs = { project_root: f.project, worktree: removed, task_id: "task-removed", idempotency_key: "remove-task-removed" };
    f.approve("mac_git_worktree_remove", removeArgs);
    assert.equal(data(await f.handle("mac_git_worktree_remove", removeArgs)).removed, true);
    const other = await f.gateway.worktrees.create({ projectRoot: f.project, branchName: "codex/other", baseRef: "HEAD", taskId: "other",
      idempotencyKey: "other-key", owner: "principal-2" }, gatewayControl, () => undefined);
    const outside = [
      join(f.trees, "unknown-task", "source.txt"),
      join(f.state, "broker.sqlite"),
      join(removed, "source.txt"),
      join(other.record.worktree, "source.txt")
    ];
    for (const path of outside) {
      assert.equal(await denialMessage(await f.handle("mac_read_file", { path })), GENERIC_ZONE_DENIAL, path);
      assert.match(await denialMessage(await f.handle("mac_write_file_atomic", { path, content: "x\n", idempotency_key: "outside-write" })), GENERIC_WRITE_DENIAL, path);
      assert.deepEqual(await explainDenial(f, "mac_list_directory", path), ["POLICY_DENIED", "DENIED_ZONE"], path);
      assert.deepEqual(await explainDenial(f, "mac_write_file_atomic", path), ["POLICY_DENIED", "ROOT_CAPABILITY_NOT_GRANTED"], path);
    }
    // A secret path keeps its own denial even inside the caller's worktree.
    const secret = join(worktree, ".env");
    assert.equal(await denialMessage(await f.handle("mac_read_file", { path: secret })), "Filesystem content is inside a protected secret zone");
    assert.deepEqual(await explainDenial(f, "mac_read_file", secret), ["POLICY_DENIED", "SECRET_PATH_ACCESS"]);
    // The primary project is an ordinary write root and still works.
    assert.equal(data(await f.handle("mac_read_file", { path: join(f.project, "source.txt") })).content, "original\n");
    await f.primaryUnchanged();
  } finally { await f.close(); }
});
