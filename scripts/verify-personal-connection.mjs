import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { parseEnv } from "node:util";
import { resolve, join } from "node:path";
import { homedir } from "node:os";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import { existsSync } from "node:fs";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { readAuthFile } from "../packages/auth/dist/cli.js";
import { AuthStore } from "../packages/auth/dist/store.js";
import { configSchema, V2_TOOLS, O1_TOOLS, READ_SCOPES, READ_TOOLS, W1_READ_SCOPES, W1_SCOPES, W1_TOOLS, scopesForGrantProfile } from "../packages/auth/dist/contracts.js";
import { configureIssuerNetwork } from "../packages/auth/dist/issuer-network.js";
import { decodeJwt } from "jose";
import { DatabaseSync } from "node:sqlite";
import { PLANNED_TOOL_NAMES } from "../packages/contracts/dist/catalog.js";
import { DEVELOPMENT_TOOL_NAMES } from "../packages/broker/dist/development-policy.js";

// Values from .env and bearer responses are never emitted or written to disk.
const root = resolve(process.argv[2] ?? "");
const envPath = resolve(process.argv[3] ?? "");
let credentials; let clientId; let refreshToken; let oauthStore;
let client; let transport; let network; let terminalDirectory;
async function run() {
  if (process.argv.length !== 4 && !(process.argv.length === 5 && process.argv[4] === "--owner-terminal")) throw new Error("Expected protected root, env path and optional --owner-terminal");
  const config = configSchema.parse(JSON.parse(readAuthFile(`${root}/auth/auth-config.json`).toString()));
  if (!["r1", "w1", "g1", "o1", "v2"].includes(config.grantProfile)) throw new Error("Unsupported personal verification profile");
  const writeProfile = config.grantProfile !== "r1";
  const terminalProbe = process.argv[4] === "--owner-terminal";
  if (terminalProbe && config.grantProfile !== "o1") throw new Error("Owner terminal verification requires O1");
  const developmentProbe = config.grantProfile === "v2" && process.env.MOPS_VERIFY_DEVELOPMENT === "1";
  const guiProfile = config.grantProfile === "g1" || config.grantProfile === "o1" || config.grantProfile === "v2";
  const metadataScopes = scopesForGrantProfile(config.grantProfile);
  const expectedScopes = developmentProbe ? metadataScopes : terminalProbe ? metadataScopes : guiProfile ? W1_READ_SCOPES : writeProfile ? W1_SCOPES : READ_SCOPES;
  let expectedTools = developmentProbe ? V2_TOOLS.filter(tool => tool !== "mac_terminal_exec") : terminalProbe ? O1_TOOLS : guiProfile ? READ_TOOLS.filter(tool => !tool.startsWith("mac_docker_")) : writeProfile ? W1_TOOLS : READ_TOOLS;
  if (config.grantProfile === "v2" && !developmentProbe) {
    const additiveReads = [];
    for (const name of DEVELOPMENT_TOOL_NAMES) {
      if (!V2_TOOLS.includes(name)) continue;
      const contract = JSON.parse(await readFile(new URL(`../tool-contracts/${name}.json`, import.meta.url), "utf8"));
      if (contract.required_scopes.every(scope => expectedScopes.includes(scope))) additiveReads.push(name);
    }
    expectedTools = [...new Set([...expectedTools, ...additiveReads])];
  }
  const profileLabel = config.grantProfile.toUpperCase();
  network = configureIssuerNetwork(new URL(config.issuer).hostname);
  const bytes = readAuthFile(envPath, 8192, false);
  try { credentials = parseEnv(bytes.toString()); } finally { bytes.fill(0); }
  const endpoint = path => new URL(path, config.issuer);
  const request = (path, init = {}) => fetch(endpoint(path), { ...init, redirect: "manual", signal: AbortSignal.timeout(30000) });
  const form = (path, body, cookie) => request(path, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", origin: new URL(config.issuer).origin, ...(cookie ? { cookie } : {}) }, body: new URLSearchParams(body) });
  const cookieOf = response => response.headers.get("set-cookie")?.split(";")[0];
  const csrfOf = async response => { assert.equal(response.status, 200); const value = /name="csrf" value="([a-f0-9]{64})"/u.exec(await response.text())?.[1]; assert.ok(value); return value; };
  const challengeResponse = await request("/mcp");
  assert.equal(challengeResponse.status, 401); assert.ok(challengeResponse.headers.get("www-authenticate")?.includes("resource_metadata="));
  const metadata = await (await request("/.well-known/oauth-protected-resource/mcp")).json();
  const rootMetadata = await request("/.well-known/oauth-protected-resource");
  assert.equal(rootMetadata.status, 200);
  assert.deepEqual(await rootMetadata.json(), metadata);
  assert.deepEqual(metadata.scopes_supported, [...metadataScopes]);
  console.log("Public OAuth discovery and unauthenticated MCP challenge verified.");
  const registered = await request("/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Mac Operator deployment verification", redirect_uris: [config.allowedRedirectUris[0]], token_endpoint_auth_method: "none" }) });
  assert.equal(registered.status, 201); clientId = (await registered.json()).client_id;
  const verifier = randomBytes(32).toString("base64url");
  const query = new URLSearchParams({ client_id: clientId, redirect_uri: config.allowedRedirectUris[0], response_type: "code", state: randomBytes(20).toString("hex"), code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", resource: config.resource, scope: expectedScopes.join(" ") });
  const authorization = await request(`/authorize?${query}`); assert.equal(authorization.status, 303);
  let cookie = cookieOf(authorization); assert.ok(cookie);
  let csrf = await csrfOf(await request("/oauth/login", { headers: { cookie } }));
  const login = await form("/oauth/login", { csrf, username: credentials.MAC_OPERATOR_USERNAME, password: credentials.MAC_OPERATOR_PASSWORD }, cookie);
  credentials = undefined; assert.equal(login.status, 303); cookie = cookieOf(login); assert.ok(cookie);
  csrf = await csrfOf(await request("/oauth/consent", { headers: { cookie } }));
  const consent = await form("/oauth/consent", { csrf, decision: "allow" }, cookie); assert.equal(consent.status, 303);
  const callback = new URL(consent.headers.get("location"));
  assert.equal(callback.searchParams.get("state"), query.get("state")); assert.equal(callback.searchParams.get("iss"), config.issuer);
  const exchanged = await form("/token", { grant_type: "authorization_code", client_id: clientId, code: callback.searchParams.get("code"), code_verifier: verifier, redirect_uri: config.allowedRedirectUris[0], resource: config.resource });
  assert.equal(exchanged.status, 200); const tokens = await exchanged.json(); refreshToken = tokens.refresh_token;
  const claims = decodeJwt(tokens.access_token);
  const nowSeconds = Math.floor(Date.now() / 1_000);
  const claimScope = typeof claims.scope === "string" ? claims.scope.split(" ").filter(Boolean) : [];
  assert.deepEqual([...claimScope].sort(), [...expectedScopes].sort());
  console.log(`Access-token claim boundary: issuer_match=${claims.iss === config.issuer} audience_match=${claims.aud === config.resource} subject_match=${claims.sub === config.principalId} required_scope_count=${expectedScopes.filter(scope => claimScope.includes(scope)).length}/${expectedScopes.length} has_sid=${typeof claims.sid === "string"} has_azp=${typeof claims.azp === "string"} has_jti=${typeof claims.jti === "string"} age_seconds=${typeof claims.iat === "number" ? nowSeconds - claims.iat : "invalid"} remaining_seconds=${typeof claims.exp === "number" ? claims.exp - nowSeconds : "invalid"}`);
  console.log("Real owner login, explicit consent and S256 token exchange verified over public HTTPS.");
  client = new Client({ name: "mac-operator-live-verifier", version: "1.0.0" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
  const diagnosticFetch = async (input, init = {}) => {
    const headers = new Headers(init.headers);
    let rpcMethod = "unknown";
    if (typeof init.body === "string") {
      try {
        const parsed = JSON.parse(init.body);
        rpcMethod = Array.isArray(parsed) ? "batch" : typeof parsed?.method === "string" ? parsed.method : "notification";
      } catch {
        rpcMethod = "invalid-json";
      }
    }
    const response = await fetch(input, init);
    const challenge = response.headers.get("www-authenticate") ?? "";
    const challengeError = /error="([a-z_]+)"/u.exec(challenge)?.[1] ?? "none";
    console.log(`MCP HTTP diagnostic: method=${String(init.method ?? "GET").toUpperCase()} rpc=${rpcMethod} status=${response.status} authorization=${headers.has("authorization")} session=${headers.has("mcp-session-id")} challenge=${challengeError}`);
    return response;
  };
  transport = new StreamableHTTPClientTransport(new URL(config.resource), { authProvider: { token: async () => tokens.access_token }, fetch: diagnosticFetch, onInsufficientScope: "throw" });
  try {
    await client.connect(transport);
  } catch (error) {
    const rawHandshake = await request("/mcp", {
      method: "POST",
      headers: { authorization: `Bearer ${tokens.access_token}`, "content-type": "application/json", "mcp-protocol-version": "2026-07-28", "mcp-method": "initialize" },
      body: JSON.stringify({ jsonrpc: "2.0", id: "r1-diagnostic", method: "initialize", params: { protocolVersion: "2026-07-28", capabilities: {}, clientInfo: { name: "mac-operator-r1-diagnostic", version: "1.0.0" } } })
    });
    console.log(`Raw MCP initialize authorization probe: status=${rawHandshake.status}`);
    throw error;
  }
  const listed = await client.listTools(); assert.deepEqual(listed.tools.map(t => t.name).sort(), [...expectedTools].sort());
  const call = async (name, argumentsValue) => {
    const result = await client.callTool({ name, arguments: argumentsValue });
    const text = result.content.find(item => item.type === "text")?.text;
    assert.ok(text); const payload = JSON.parse(text); assert.equal(payload.ok, true, `${name} failed: ${payload.result_class ?? "unknown"} ${payload.error?.message ?? ""}`); return payload.data;
  };
  const projectRoot = resolve(process.env.MOPS_VERIFY_PROJECT_ROOT ?? process.cwd());
  const homeRoot = homedir();
  if (expectedScopes.includes("mac.files.write")) {
    const outsidePath = join(homeRoot, `.mac-operator-w1-denied-${randomBytes(8).toString("hex")}.txt`);
    assert.equal(existsSync(outsidePath), false);
    const denied = await client.callTool({ name: "mac_write_file_atomic", arguments: {
      path: outsidePath, content: "denied-probe", idempotency_key: `w1-denied-${randomBytes(8).toString("hex")}`, create_only: true
    } });
    const deniedText = denied.content.find(item => item.type === "text")?.text;
    assert.ok(deniedText);
    const deniedPayload = JSON.parse(deniedText);
    assert.equal(deniedPayload.ok, false);
    assert.equal(deniedPayload.result_class, "POLICY_DENIED");
    assert.equal(existsSync(outsidePath), false);
    console.log("W1 out-of-project write denied before approval or file creation.");
  }
  let containerId;
  if (!writeProfile) {
    const dockerStatus = await call("mac_docker_status", { include_images: false, include_storage: false });
    containerId = dockerStatus.containers?.[0]?.id;
    assert.ok(containerId, "R1 Docker verification requires one observed container");
  }
  const verificationCalls = new Map([
    ["mac_app_list", { running_only: true, include_installed: false }],
    ["mac_capabilities", {}],
    ["mac_directory_tree", { path: projectRoot, depth: 1, max_entries: 50 }],
    ["mac_docker_inspect", { object_type: "container", id: containerId }],
    ["mac_docker_logs", { container_id: containerId, tail: 5, since_seconds: 60 }],
    ["mac_find_files", { roots: [projectRoot], query: "README", max_results: 20 }],
    ["mac_git_branch_list", { project_root: projectRoot, include_remote: false }],
    ["mac_git_diff", { project_root: projectRoot, paths: [], staged: false, max_bytes: 1024 }],
    ["mac_git_log", { project_root: projectRoot, limit: 5 }],
    ["mac_git_status", { project_root: projectRoot, include_untracked: false }],
    ["mac_hash_file", { path: join(projectRoot, "README.md"), algorithm: "sha256" }],
    ["mac_health", { include_components: false }],
    ["mac_list_directory", { path: projectRoot, limit: 50, include_hidden: false }],
    ["mac_log_tail", { source: "system", lines: 5, since_seconds: 60 }],
    ["mac_network_status", { include_listeners: false }],
    ["mac_package_inspect", { project_root: projectRoot, manager: "auto", check_outdated: false }],
    ["mac_policy_explain", { proposed_tool: "mac_system_summary", target: { kind: "host", reference: "broker" } }],
    ["mac_process_inspect", { pid: process.pid }],
    ["mac_process_list", { limit: 10, sort: "pid" }],
    ["mac_project_discover", { roots: [projectRoot], max_results: 10 }],
    ["mac_project_summary", { project_root: projectRoot, include_tree: false }],
    ["mac_read_file", { path: join(projectRoot, "README.md"), max_bytes: 1024, encoding: "utf8" }],
    ["mac_recent_files", { roots: [projectRoot], since_seconds: 86400, limit: 20 }],
    ["mac_search_text", { roots: [projectRoot], query: "Mac-Operator-MCP", max_results: 20 }],
    ["mac_service_status", { service_id: "system/com.apple.logd" }],
    ["mac_stat_path", { path: projectRoot, follow_symlink: false }],
    ["mac_storage_analysis", { roots: [projectRoot], top_n: 3, max_depth: 2 }],
    ["mac_system_summary", { include_load: false }]
  ]);
  if (writeProfile) {
    verificationCalls.delete("mac_docker_inspect");
    verificationCalls.delete("mac_docker_logs");
  }
  for (const [name, argumentsValue] of verificationCalls) {
    console.log(`${profileLabel} call start: ${name}`);
    const data = await call(name, argumentsValue);
    if (name === "mac_capabilities") {
      assert.deepEqual(data.capabilities.map(capability => capability.name).sort(), [...PLANNED_TOOL_NAMES].sort());
      for (const disabledTool of config.grantProfile === "v2" ? ["mac_git_push"] : [...DEVELOPMENT_TOOL_NAMES, "mac_task_run"]) {
        assert.equal(data.capabilities.find(capability => capability.name === disabledTool)?.enabled, false,
          `Personal deployment unexpectedly enabled ${disabledTool}`);
      }
      console.log(`Personal capability boundary: ${data.capabilities.length} contracts; ${config.grantProfile === "v2" ? "approved development enabled; push denied" : "V2/task execution disabled"}.`);
    }
    console.log(`${profileLabel} call passed: ${name}`);
  }
  assert.equal(READ_TOOLS.includes("mac_job_status"), true);
  console.log(`${profileLabel} tool discovery verified: ${listed.tools.length} tools listed; ${verificationCalls.size + (writeProfile ? 0 : 1)} real read calls succeeded. mac_job_status remains available for owner-owned Job readback only.`);
  if (developmentProbe) {
    const runtime = JSON.parse(readAuthFile(join(root, "personal/development-runtime.json")).toString());
    const developmentProject = runtime.developmentProjects[0];
    const syntheticPath = "scripts/test-isolation.test.js";
    const primaryFingerprint = async () => ({
      git: await call("mac_git_status", { project_root: developmentProject }),
      indexSha256: createHash("sha256").update(await readFile(join(developmentProject, ".git/index"))).digest("hex"),
      sourceSha256: createHash("sha256").update(await readFile(join(developmentProject, syntheticPath))).digest("hex")
    });
    const primaryBefore = await primaryFingerprint();
    const taskId = `public-v2-${randomBytes(8).toString("hex")}`;
    const branch = `codex/${taskId}`;
    const createArgs = { project_root: developmentProject, task_id: taskId, branch_name: branch, base_ref: "main", idempotency_key: `${taskId}-create` };
    const treesBefore = await call("mac_git_worktree_list", { project_root: developmentProject });
    const explained = await call("mac_policy_explain", { proposed_tool: "mac_git_worktree_create", target: { kind: "project", reference: developmentProject }, proposed_arguments: createArgs });
    assert.equal(explained.decision, "allow");
    assert.deepEqual(await call("mac_git_worktree_list", { project_root: developmentProject }), treesBefore);
    const created = await call("mac_git_worktree_create", createArgs);
    assert.equal((await call("mac_git_worktree_create", createArgs)).worktree, created.worktree);
    const worktree = created.worktree;
    const preflight = await call("mac_codex_preflight", { project_root: developmentProject, worktree });
    assert.equal(preflight.permission, "allow");
    const settle = async receipt => {
      assert.ok(receipt.job_id);
      for (let attempt = 0; attempt < 1200; attempt += 1) {
        const job = await call("mac_job_status", { job_id: receipt.job_id, tail_bytes: 1024 });
        if (!["queued", "running"].includes(job.state)) {
          assert.equal(job.state, "completed", `${receipt.job_id} ended ${job.state}: ${job.result_class}`);
          assert.equal(job.exit_code, 0);
          return { jobId: receipt.job_id, state: job.state, exitCode: job.exit_code };
        }
        await delay(500);
      }
      throw new Error("Public development job did not settle within its runtime budget");
    };
    const entry = runtime.entries.find(value => value.type === "test" && value.projectRoot === developmentProject);
    assert.ok(entry);
    const args = { profile: entry.profile, cwd: worktree, task_id: taskId, max_runtime: 600000, idempotency_key: `${taskId}-task` };
    const receipt = await call("mac_task_run", args);
    assert.equal((await call("mac_task_run", args)).job_id, receipt.job_id);
    const task = await settle(receipt);
    const readonly = await settle(await call("mac_codex_run", { project_root: developmentProject, worktree, task_id: taskId,
      execution_profile: "readonly", network_policy: "none", max_runtime: 600000, idempotency_key: `${taskId}-readonly`,
      allowed_paths: ["scripts/test-isolation.test.js"],
      task: "Use only the supplied read_file tool to read scripts/test-isolation.test.js. Briefly describe its environment filtering test. Do not modify files or execute commands." }));
    const written = await settle(await call("mac_codex_run", { project_root: developmentProject, worktree, task_id: taskId,
      execution_profile: "workspace-write", network_policy: "none", max_runtime: 600000, idempotency_key: `${taskId}-write`,
      allowed_paths: [syntheticPath],
      task: "Synthetic acceptance task: modify only scripts/test-isolation.test.js. Add one concise Node test asserting cleanEnvironment excludes an extra synthetic credential-like field named SYNTHETIC_SERVICE_CREDENTIAL with an innocuous fixture marker and retains PATH. Preserve all existing tests. Use the supplied read_file then edit_file or write_file tool; this workspace-write profile authorizes changes through those gateway tools. Do not change production helpers, manifests or other files. Do not execute commands or access host data." }));
    const diff = await call("mac_git_diff", { project_root: worktree });
    assert.deepEqual(diff.changed_paths, [syntheticPath]);
    const common = { project_root: developmentProject, worktree, task_id: taskId, max_runtime: 600000 };
    const tested = await settle(await call("mac_test_run", { ...common, idempotency_key: `${taskId}-test` }));
    const built = await settle(await call("mac_build_run", { ...common, idempotency_key: `${taskId}-build` }));
    const staged = await call("mac_git_stage", { project_root: worktree, paths: [syntheticPath] });
    const committed = await call("mac_git_commit", { project_root: worktree, message: "test: verify public synthetic credential environment isolation",
      expected_staged_diff_sha256: staged.staged_diff_sha256 });
    const review = await call("mac_pr_prepare", { project_root: developmentProject, worktree });
    assert.deepEqual(review.changed_files, [syntheticPath]);
    const status = await call("mac_git_status", { project_root: worktree });
    assert.equal(status.dirty, false);
    const primaryAfter = await primaryFingerprint();
    assert.deepEqual(primaryAfter, primaryBefore);
    const push = await call("mac_policy_explain", { proposed_tool: "mac_git_push", target: { kind: "project", reference: developmentProject }, proposed_arguments: { project_root: developmentProject,
      worktree, remote: "origin", branch_name: branch, approval_id: "public-probe-denied", idempotency_key: `${taskId}-push-denied` } });
    assert.equal(push.decision, "deny");
    const audit = await call("mac_execution_audit", { project_root: developmentProject, limit: 100 });
    assert.ok(audit);
    const removed = await call("mac_git_worktree_remove", { project_root: developmentProject, worktree, task_id: taskId, idempotency_key: `${taskId}-remove` });
    assert.equal(removed.removed, true);
    await writeFile(join(root, "personal/public-development-evidence.json"), `${JSON.stringify({ schemaVersion: "0.1", status: "pass",
      verifiedAt: new Date().toISOString(), taskId, project: developmentProject, worktree, branch,
      scopes: expectedScopes.length, tools: listed.tools.length, readCalls: verificationCalls.size,
      task, readonly, written, tested, built, commit: committed.commit_id, review, primaryBefore, primaryAfter,
      primaryUnchanged: true, policyExplainDidNotCreateWorktree: true, duplicateRequestReused: true, worktreeClean: true,
      removed: true, pushDenied: true, auditRead: true, terminalScopeAbsent: !claimScope.includes("mac.terminal.exec") }, null, 2)}\n`, { mode: 0o600 });
    console.log("Public V2 accepted: exact scoped approvals, worktree lifecycle, Codex read/write, named task, tests, build, local commit, review, primary unchanged, idempotency, audit and push denial.");
  }
  if (terminalProbe) {
    terminalDirectory = await mkdtemp("/tmp/mop-owner-live-");
    const command = "printf once >> counter && sleep 31 && pwd && git --version && node --version && if command -v codex >/dev/null; then codex --version; fi && curl -fsS --max-time 10 -o /dev/null https://mac.yapweijun1996.com/.well-known/oauth-protected-resource/mcp && printf '\nnetwork-ok'";
    const args = { command, cwd: terminalDirectory, idempotency_key: `owner-live-${randomBytes(8).toString("hex")}`, timeout_ms: 45000 };
    const first = await call("mac_terminal_exec", args);
    assert.equal(first.state, "completed"); assert.equal(first.exit_code, 0);
    assert.match(first.stdout, /git version/u); assert.match(first.stdout, /^v[0-9]+\./mu); assert.match(first.stdout, /network-ok/u);
    const replay = await call("mac_terminal_exec", args);
    assert.equal(replay.reused, true);
    assert.equal(await readFile(join(terminalDirectory, "counter"), "utf8"), "once");
    const status = await call("mac_job_status", { job_id: first.job_id, tail_bytes: 1024 });
    assert.equal(status.state, "completed");
    const timeout = await client.callTool({ name: "mac_terminal_exec", arguments: {
      command: "sleep 5; printf late > timed-out-marker", cwd: terminalDirectory,
      idempotency_key: `owner-timeout-${randomBytes(8).toString("hex")}`, timeout_ms: 150
    } });
    const timeoutPayload = JSON.parse(timeout.content.find(item => item.type === "text").text);
    assert.equal(timeoutPayload.ok, false); assert.equal(timeoutPayload.result_class, "TIMEOUT");
    assert.equal(existsSync(join(terminalDirectory, "timed-out-marker")), false);
    console.log("Owner terminal verified over public OAuth: 31-second shell, local CLI, network, file write/read, idempotency, Job status and timeout.");
    const revokedKey = `owner-revoke-${randomBytes(8).toString("hex")}`;
    const active = client.callTool({ name: "mac_terminal_exec", arguments: {
      command: "printf started > revocation-started; sleep 20; printf late > revoked-marker", cwd: terminalDirectory,
      idempotency_key: revokedKey, timeout_ms: 30000
    } }).then(value => value, () => undefined);
    for (let attempt = 0; attempt < 100 && !existsSync(join(terminalDirectory, "revocation-started")); attempt += 1) await delay(100);
    assert.equal(existsSync(join(terminalDirectory, "revocation-started")), true);
    const revoked = await form("/revoke", { client_id: clientId, token: refreshToken }); assert.equal(revoked.status, 200);
    refreshToken = undefined;
    const ended = await active;
    assert.ok(ended);
    const cancelled = JSON.parse(ended.content.find(item => item.type === "text").text);
    assert.equal(cancelled.ok, false); assert.equal(cancelled.result_class, "CANCELLED");
    const brokerDatabase = new DatabaseSync(join(root, "personal/broker.sqlite"), { readOnly: true });
    try {
      const job = brokerDatabase.prepare("SELECT state, cancel_requested, process_metadata_json FROM jobs WHERE idempotency_key = ?").get(revokedKey);
      assert.equal(job?.state, "cancelled"); assert.equal(job?.cancel_requested, 1); assert.equal(job?.process_metadata_json, "");
    } finally { brokerDatabase.close(); }
    assert.equal(existsSync(join(terminalDirectory, "revoked-marker")), false);
    console.log("Active terminal command stopped after its owner OAuth grant was revoked; durable cancellation and cleared process ownership verified.");
  }
  if (refreshToken) { const revoked = await form("/revoke", { client_id: clientId, token: refreshToken }); assert.equal(revoked.status, 200); }
  assert.equal((await request("/mcp", { headers: { authorization: `Bearer ${tokens.access_token}` } })).status, 401);
  refreshToken = undefined;
  console.log("Grant revocation rejects the next MCP request.");
}
try { await run(); }
catch (error) {
  const message = error instanceof Error ? error.message.slice(0, 240) : "unknown verification error";
  console.error(`Live verification failed (${message}); no credentials or response payloads were printed.`);
  process.exitCode = 1;
}
finally {
  credentials = undefined;
  await client?.close().catch(() => {}); await transport?.close().catch(() => {});
  await network?.close();
  if (terminalDirectory) await rm(terminalDirectory, { recursive: true, force: true });
  if (clientId) {
    try {
      oauthStore = new AuthStore(`${root}/auth`);
      if (refreshToken) {
        const key = createHash("sha256").update(refreshToken).digest("hex");
        const record = oauthStore.get("refresh", key); if (record) oauthStore.revoke(record.grantId, clientId);
      }
      oauthStore.delete("client", clientId);
    } finally { oauthStore?.close(); }
  }
}
