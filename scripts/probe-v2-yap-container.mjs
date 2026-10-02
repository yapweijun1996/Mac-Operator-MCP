import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { canonicalJson, sha256, signRequest } from "../packages/contracts/dist/index.js";
import { Broker, BrokerStore, createDefaultPolicy, EdgeKeyring, CODEX_CONTROLLER_EXECUTABLE_SHA256, CODEX_CONTROLLER_VERSION } from "../packages/broker/dist/index.js";
import { createPersonalDevelopmentRuntime } from "../packages/auth/dist/personal-development-runtime.js";

// Explicit operator-only synthetic probe; never selected by an MCP argument.
if (process.argv[2] !== "--synthetic") throw new Error("Explicit --synthetic required");
const root = resolve(process.argv[3]);
const project = "/Users/yapweijun/Documents/GitHub/cloudflare-tunnel-server-001";
const taskId = "v2-yap-e2e-20261002-final";
const branch = "codex/mac-operator-v2-e2e-20261002-final";
const profile = "yap.test-isolation", buildProfile = "yap.site-build";
const imageId = "sha256:540f2d2753dc5674d05ec0cb7963a1fbb75b77f1fdeaa63c48a3825660aa01c4";
const engineId = "f8fbb9ed-402f-4ff7-b672-fc10a3401347";
const git = (cwd, args) => execFileSync("/usr/bin/git", args, { cwd, encoding: "utf8", timeout: 10000, maxBuffer: 65536, shell: false, env: { GIT_CONFIG_NOSYSTEM: "1", GIT_NO_LAZY_FETCH: "1", GIT_ALLOW_PROTOCOL: "", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null", GIT_TERMINAL_PROMPT: "0" } }).trim();
const primaryState = async () => ({ head: git(project, ["rev-parse", "HEAD"]), status: git(project, ["status", "--porcelain"]), index: sha256(await readFile(join(project, ".git/index"))), source: sha256(await readFile(join(project, "scripts/test-isolation.test.js"))) });
const before = await primaryState(); assert.equal(git(project, ["diff", "--name-only"]), ""); assert.equal(git(project, ["diff", "--cached", "--name-only"]), "");
await mkdir(root, { recursive: true, mode: 0o700 });
const entries = [];
for (const [name, manifestPath, scriptName, type, command] of [[profile, "package.json", "test:isolation", "test", ["/usr/local/bin/node", "scripts/test-isolation/run.js", "scripts/test-isolation.test.js"]], [buildProfile, "site/package.json", "build", "build", ["/usr/local/bin/node", "/opt/mac-operator/run-site-build.cjs"]]]) {
  const bytes = await readFile(join(project, manifestPath));
  entries.push({ profile: name, projectRoot: project, manifestPath, manifestSha256: sha256(bytes), scriptName, scriptValue: JSON.parse(bytes).scripts[scriptName], command, type, timeoutMs: 600000, outputCapBytes: 65536 });
}
const config = { schemaVersion: "0.1", ownerProjectRoot: "/Users/yapweijun/Documents/GitHub/Mac-Operator-MCP", developmentProjects: [project],
  stateRoot: join(root, "control"), worktreeRoot: "/Users/yapweijun/Library/Application Support/DevelopmentWorktrees/MacOperator-v2-yap-canary", taskProfiles: [profile, buildProfile], socketPath: "/Users/yapweijun/.docker/run/docker.sock", engineId, imageId,
  codexExecutable: "/opt/homebrew/lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex", codexExecutableSha256: CODEX_CONTROLLER_EXECUTABLE_SHA256, codexVersion: CODEX_CONTROLLER_VERSION,
  evidencePath: join(root, "acceptance.json"), evidenceSha256: "0".repeat(64), snapshotExcludedPaths: ["portal", "mcp-connector", "sample", "docs", "output", "tmp"], entries };
// This private, non-listening acceptance probe cannot expand production authority.
const runtime = await createPersonalDevelopmentRuntime(config, "principal-1");
const scopes = ["mac.control.read", "mac.policy.explain", "mac.files.read", "mac.files.search", "mac.files.hash", "mac.project.read", "mac.project.write", "mac.git.read", "mac.git.write", "mac.agent.read", "mac.agent.run", "mac.task.run", "mac.audit.read", "mac.job.read", "mac.job.cancel"];
const roots = [{ rootId: "yap-project", path: project, metadata: true, contentRead: true, write: false, denyRelativePaths: [] }];
const base = createDefaultPolicy("edge-1", true, scopes, ["edge-key-1"], roots, [], [], [project], [], config.taskProfiles);
const names = ["mac_git_worktree_create", "mac_git_worktree_list", "mac_git_worktree_remove", "mac_codex_preflight", "mac_codex_run", "mac_test_run", "mac_build_run", "mac_task_run", "mac_git_stage", "mac_git_commit", "mac_pr_prepare", "mac_execution_audit"];
const policy = { ...base, tools: new Map([...base.tools].map(([name, rule]) => [name, { ...rule, enabled: names.includes(name) || rule.enabled }])),
  targetRules: [...base.targetRules, ...scopes.map((scope, index) => ({ ruleId: `v2-yap-${index}`, effect: "allow", principalId: "principal-1", scope, target: { kind: "project", reference: project } }))] };
const store = new BrokerStore(join(root, "ledger.sqlite"), { runtimeFence: true });
const key = randomBytes(32), started = Date.now(), events = [];
const broker = new Broker({ store, policy, developmentGateway: runtime.gateway, taskRunner: runtime.runner, taskProfileRegistry: runtime.profiles,
  edgeAuthenticationKeys: new EdgeKeyring([{ edgeId: "edge-1", keyId: "edge-key-1", key, notBeforeMs: started - 1000, expiresAtMs: started + 3600000 }]),
  authorizeDevelopment: async operation => { store.issueApproval({ approvalId: `approval:${randomUUID()}`, approverPrincipalId: "synthetic-probe-operator", requestingPrincipalId: operation.principalId, tool: operation.tool, contractVersion: operation.contractVersion, targetKind: operation.targetKind, targetRef: operation.targetRef, payloadDigest: operation.payloadDigest, policyVersion: operation.policyVersion, approvalClass: operation.approvalClass, unattended: false, issuedAtMs: Date.now(), expiresAtMs: operation.expiresAtMs }); return false; } });
await broker.reconcileRestartedContainerTasks();
const call = async (tool, args) => {
  const now = Date.now();
  const result = await broker.handle(signRequest({ protocolVersion: "0.1", requestId: `yap-${randomUUID()}`, tool, contractVersion: "0.1", arguments: args,
    principal: { principalId: "principal-1", sessionId: "yap-e2e-session", issuer: "test-issuer", audience: "mac-operator-broker", scopes, issuedAtMs: started - 1000, expiresAtMs: started + 3600000, edgeId: "edge-1" }, timestampMs: now, nonce: randomUUID(), policyAudience: "mac-operator-broker", policyVersion: "policy-0.1", authenticationKeyId: "edge-key-1" }, key));
  events.push({ tool, ok: result.ok, resultClass: result.result_class, ...(result.ok ? {} : { error: result.error }) });
  await writeFile(join(root, "progress.json"), JSON.stringify(events, null, 2), { mode: 0o600 });
  assert.equal(result.ok, true, JSON.stringify(result)); return result.data;
};
const settle = async (receipt) => { for (let i = 0; i < 6000; i++) { const job = store.ownedJob(receipt.job_id, "principal-1"); if (!["queued", "running"].includes(job.state)) { const result = await call("mac_job_status", { job_id: job.jobId, tail_bytes: 8192 }); await writeFile(join(root, `${job.jobId}.json`), JSON.stringify(result, null, 2), { mode: 0o600 }); assert.equal(job.state, "completed", JSON.stringify(result)); return job; } await new Promise(resolve => setTimeout(resolve, 100)); } throw new Error("Job did not settle"); };
try {
  await call("mac_project_discover", { roots: [project], max_results: 10 });
  await call("mac_project_summary", { project_root: project });
  await call("mac_git_status", { project_root: project });
  const createArgs = { project_root: project, branch_name: branch, base_ref: "main", task_id: taskId, idempotency_key: "v2-yap-create-final-image" };
  const created = await call("mac_git_worktree_create", createArgs), worktree = created.worktree;
  const duplicate = await call("mac_git_worktree_create", createArgs); assert.equal(duplicate.worktree, worktree);
  const preflight = await call("mac_codex_preflight", { project_root: project, worktree }); assert.equal(preflight.permission, "allow");
  await writeFile(join(root, "preflight.json"), JSON.stringify(preflight, null, 2), { mode: 0o600 });
  const common = { project_root: project, worktree, task_id: taskId, network_policy: "none", max_runtime: 600000 };
  await settle(await call("mac_codex_run", { ...common, execution_profile: "readonly", idempotency_key: "v2-yap-readonly-correction-verified-final-image", task: "Use only gateway tools to read scripts/test-isolation.test.js and briefly describe its environment filtering test. Do not modify files, execute commands or access host data.", allowed_paths: ["scripts/test-isolation.test.js"] }));
  await settle(await call("mac_codex_run", { ...common, execution_profile: "workspace-write", idempotency_key: "v2-yap-write-profile-corrected-final-image", task: "Synthetic acceptance task: modify only scripts/test-isolation.test.js. Add one concise Node test asserting cleanEnvironment excludes an extra synthetic credential-like field named SYNTHETIC_SERVICE_CREDENTIAL with an innocuous fixture marker and retains PATH. Preserve all existing tests. Use the supplied read_file then edit_file or write_file tool; this workspace-write profile authorizes changes through those gateway tools. do not change production helpers, manifests or other files. Do not execute commands or access host data.", allowed_paths: ["scripts/test-isolation.test.js"] }));
  const diff = await call("mac_git_diff", { project_root: worktree }); await writeFile(join(root, "diff.json"), JSON.stringify(diff, null, 2), { mode: 0o600 });
  assert.equal(git(worktree, ["diff", "--name-only"]), "scripts/test-isolation.test.js");
  await settle(await call("mac_test_run", { project_root: project, worktree, task_id: taskId, max_runtime: 600000, idempotency_key: "v2-yap-test-final-image" }));
  await settle(await call("mac_task_run", { profile, cwd: worktree, task_id: taskId, max_runtime: 600000, idempotency_key: "v2-yap-task-final-image" }));
  await settle(await call("mac_build_run", { project_root: project, worktree, task_id: taskId, max_runtime: 600000, idempotency_key: "v2-yap-build-final-image" }));
  const staged = await call("mac_git_stage", { project_root: worktree, paths: ["scripts/test-isolation.test.js"] });
  const committed = await call("mac_git_commit", { project_root: worktree, message: "test: verify synthetic credential environment isolation", expected_staged_diff_sha256: staged.staged_diff_sha256 });
  const review = await call("mac_pr_prepare", { project_root: project, worktree });
  const audit = await call("mac_execution_audit", { project_root: project, limit: 100 });
  assert.deepEqual(await primaryState(), before);
  const evidence = { schemaVersion: "0.1", imageId, engineId, codexExecutableSha256: CODEX_CONTROLLER_EXECUTABLE_SHA256, codexVersion: CODEX_CONTROLLER_VERSION, project, taskId, worktree, branch, commit: committed.commit_id, primaryBefore: before, primaryAfter: await primaryState(), durationMs: Date.now() - started, events, review, audit, checks: ["codex_readonly", "codex_workspace_write", "workspace_write", "registered_test_success", "registered_build", "primary_unchanged"].map(name => ({ name, status: "pass" })) };
  await writeFile(join(root, "e2e.json"), JSON.stringify(evidence, null, 2), { mode: 0o600 });
  await writeFile(join(root, "runtime-template.json"), JSON.stringify(config, null, 2), { mode: 0o600 });
  console.log(JSON.stringify({ status: "pass", taskId, worktree, branch, commit: committed.commit_id, events: events.length, primaryUnchanged: true }));
} finally { await broker.close(); store.close(); }
