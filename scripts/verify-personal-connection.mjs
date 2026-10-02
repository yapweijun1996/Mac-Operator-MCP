import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { parseEnv } from "node:util";
import { resolve, join } from "node:path";
import { homedir } from "node:os";
import { existsSync } from "node:fs";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { readAuthFile } from "../packages/auth/dist/cli.js";
import { AuthStore } from "../packages/auth/dist/store.js";
import { configSchema, READ_SCOPES, READ_TOOLS, W1_SCOPES, W1_TOOLS } from "../packages/auth/dist/contracts.js";
import { configureIssuerNetwork } from "../packages/auth/dist/issuer-network.js";
import { decodeJwt } from "jose";

// Values from .env and bearer responses are never emitted or written to disk.
const root = resolve(process.argv[2] ?? "");
const envPath = resolve(process.argv[3] ?? "");
let credentials; let clientId; let refreshToken; let oauthStore;
let client; let transport; let network;
async function run() {
  if (process.argv.length !== 4) throw new Error("Expected protected root and env path");
  const config = configSchema.parse(JSON.parse(readAuthFile(`${root}/auth/auth-config.json`).toString()));
  if (config.grantProfile !== "r1" && config.grantProfile !== "w1") throw new Error("Unsupported personal verification profile");
  const writeProfile = config.grantProfile === "w1";
  const expectedScopes = writeProfile ? W1_SCOPES : READ_SCOPES;
  const expectedTools = writeProfile ? W1_TOOLS : READ_TOOLS;
  const profileLabel = writeProfile ? "W1" : "R1";
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
  assert.deepEqual(metadata.scopes_supported, [...expectedScopes]);
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
  if (writeProfile) {
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
    await call(name, argumentsValue);
    console.log(`${profileLabel} call passed: ${name}`);
  }
  assert.equal(READ_TOOLS.includes("mac_job_status"), true);
  console.log(`${profileLabel} tool discovery verified: ${listed.tools.length} tools listed; ${verificationCalls.size + (writeProfile ? 0 : 1)} real read calls succeeded. mac_job_status remains available for owner-owned Job readback only.`);
  const revoked = await form("/revoke", { client_id: clientId, token: refreshToken }); assert.equal(revoked.status, 200);
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
