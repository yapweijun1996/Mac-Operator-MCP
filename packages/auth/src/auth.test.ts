import assert from "node:assert/strict";
import { promisify } from "node:util";
import { execFile } from "node:child_process";
import test, { type TestContext } from "node:test";
import { generateKeyPairSync, randomBytes, createHash } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, realpath, rm, readFile, unlink, writeFile, symlink } from "node:fs/promises";
import { homedir, tmpdir, cpus, totalmem } from "node:os";
import { join } from "node:path";
import https from "node:https";
import { once } from "node:events";
import { setTimeout as delay } from "node:timers/promises";
import { request as httpRequest, type Server } from "node:http";
import { decodeJwt } from "jose";
import { Client, StreamableHTTPClientTransport, type FetchLike } from "@modelcontextprotocol/client";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { AuthenticatedIpcBrokerGateway, BrokerIpcClient, createHttpsMcpEdge, createJwtAccessTokenVerifier, createOAuthGrantRevocationCheck, EdgeRequestFactory, projectPrincipal, ToolContractRegistry } from "@mac-operator/edge";
import {
  Broker,
  BrokerStore,
  BrokerIpcServer,
  createAppSandboxTaskRunnerFromStartup,
  createDefaultPolicy,
  createUserServiceControlRuntime,
  DescriptorSnapshotAttestationSigner,
  DescriptorSnapshotAttestationVerifier,
  EdgeKeyring,
  loadNativePeerAdapter,
  MacOsPeerCredentialVerifier,
  SandboxExecTaskRunner,
  TaskProfileRegistry
} from "@mac-operator/broker";
import { createAuthApp } from "./app.js";
import { AuthStore, type GrantRevocationListener } from "./store.js";
import { createPassword } from "./password.js";
import { configSchema, ownerTerminalAuthConfig, O1_SCOPES, V2_CODING_SCOPES, D1_SCOPES, READ_SCOPES, READ_TOOLS, W1_SCOPES, W1_TOOLS, type GrantProfile } from "./contracts.js";
import { fingerprint } from "./provider.js";
import { readAuthFile, runAuthCli } from "./cli.js";
import type { ApprovalBrowserBridge, ApprovalBrowserPreview } from "./approval-browser-bridge.js";

const password = "test-only-long-owner-passphrase";
const passwordRecord = await createPassword(password);
const issuer = "https://mac.example.test/";
const resource = new URL("/mcp", issuer);
const redirectUri = "https://client.example.test/callback";
const verifier = randomBytes(32).toString("base64url");
const challenge = createHash("sha256").update(verifier).digest("base64url");
const execFileAsync = promisify(execFile);
const contracts = await ToolContractRegistry.load(join(process.cwd(), "tool-contracts"));

// Route test traffic to loopback while preserving the public Host boundary.
async function localFetch(url: string, init: RequestInit): Promise<Response> {
  return new Promise((resolveResponse, reject) => {
    const request = httpRequest(url, { method: init.method, headers: Object.fromEntries(new Headers(init.headers)), agent: false }, response => {
      const chunks: Buffer[] = [];
      response.on("data", chunk => chunks.push(Buffer.from(chunk)));
      response.on("end", () => {
        const headers = new Headers();
        for (const [key, value] of Object.entries(response.headers)) if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(", ") : value);
        resolveResponse(new Response(Buffer.concat(chunks), { status: response.statusCode!, headers }));
      });
    });
    request.on("error", reject);
    request.setTimeout(5000, () => request.destroy(new Error("Test request timeout")));
    request.end(init.body?.toString());
  });
}

type CanaryProcessIdentity = { pid: number; startTimeMicros: number; parentPid: number; processGroupId: number };
type CanaryNativeProcessAdapter = ReturnType<typeof loadNativePeerAdapter>;

function parseCanaryProcessIdentity(value: unknown): CanaryProcessIdentity | undefined {
  if (value === null || typeof value !== "object") return undefined;
  const identity = value as Record<string, unknown>;
  if (!Number.isSafeInteger(identity.pid) || !Number.isSafeInteger(identity.startTimeMicros) ||
      !Number.isSafeInteger(identity.parentPid) || !Number.isSafeInteger(identity.processGroupId) ||
      (identity.pid as number) < 1 || (identity.startTimeMicros as number) < 1) return undefined;
  return {
    pid: identity.pid as number,
    startTimeMicros: identity.startTimeMicros as number,
    parentPid: identity.parentPid as number,
    processGroupId: identity.processGroupId as number
  };
}

async function terminateExactCanaryProcess(native: CanaryNativeProcessAdapter, identity: CanaryProcessIdentity): Promise<void> {
  const alive = native.isProcessIdentityAlive(identity.pid, identity.startTimeMicros);
  if (typeof alive !== "boolean") throw new TypeError("Canary process identity readback was not boolean");
  if (alive) {
    const current = parseCanaryProcessIdentity(native.getProcessIdentity(identity.pid));
    if (current?.pid !== identity.pid || current.startTimeMicros !== identity.startTimeMicros) {
      throw new Error("Canary process identity changed before targeted cleanup");
    }
    process.kill(identity.pid, "SIGKILL");
  }
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    const remainsAlive = native.isProcessIdentityAlive(identity.pid, identity.startTimeMicros);
    if (typeof remainsAlive !== "boolean") throw new TypeError("Canary process identity readback was not boolean");
    if (!remainsAlive) return;
    await delay(10);
  }
  throw new Error("Exact canary process identity remained alive after targeted cleanup");
}

async function fixture(t: TestContext, approvalBridge?: ApprovalBrowserBridge, grantProfile: GrantProfile = "r1", onGrantRevoked?: GrantRevocationListener, ownerTerminalConnection = false, callbackUri = redirectUri) {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mac-auth-")));
  const redirectUri = callbackUri;
  const config = configSchema.parse({ version: 1, issuer, resource: resource.href, issuerId: "mac-operator-auth", principalId: "owner-1", keyId: "key-1", port: 3444, allowedRedirectUris: [redirectUri], grantProfile, ...(ownerTerminalConnection ? { ownerTerminalConnection } : {}) });
  let store = new AuthStore(directory, true);
  store.put("account", "owner", { username: "owner", ...passwordRecord, principalId: config.principalId });
  const signingKey = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
  const statusKey = randomBytes(32);
  let server: Server;
  let port = 0;
  const start = async () => {
    const assembly = await createAuthApp({ config, store, signingKey, statusKey,
      ...(approvalBridge === undefined ? {} : { approvalBridge }), ...(onGrantRevoked === undefined ? {} : { onGrantRevoked }) });
    server = assembly.app.listen(0, "127.0.0.1");
    await new Promise<void>(resolve => server.once("listening", resolve));
    const address = server.address();
    assert.ok(address && typeof address === "object"); port = address.port;
    return assembly.provider;
  };
  const stop = async () => { server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); };
  let provider = await start();
  t.after(async () => { await stop(); store.close(); statusKey.fill(0); await rm(directory, { recursive: true, force: true }); });
  const request = async (path: string, body?: Record<string, string>, cookie?: string, extra: Record<string, string> = {}) => localFetch(`http://127.0.0.1:${port}${path}`, {
    method: body ? "POST" : "GET", redirect: "manual",
    headers: { host: "mac.example.test", ...(body ? { "content-type": "application/x-www-form-urlencoded" } : {}), ...(cookie ? { cookie } : {}), ...extra },
    ...(body ? { body: new URLSearchParams(body) } : {})
  });
  const registerResponse = (callback = redirectUri, prefix = "") => localFetch(`http://127.0.0.1:${port}${prefix}/register`, {
    method: "POST", headers: { host: "mac.example.test", "content-type": "application/json" },
    body: JSON.stringify({ client_name: "ChatGPT test <script>", redirect_uris: [callback], token_endpoint_auth_method: "none" }) });
  const register = async (prefix = "") => {
    const response = await registerResponse(redirectUri, prefix);
    assert.equal(response.status, 201); return (await response.json() as { client_id: string }).client_id;
  };
  const begin = async (clientId: string, overrides: Record<string, string> = {}) => request(`/authorize?${new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri,
    response_type: "code", scope: READ_SCOPES.join(" "), state: "client-state", code_challenge: challenge, code_challenge_method: "S256", resource: resource.href, ...overrides })}`);
  const cookieFrom = (response: Response) => response.headers.get("set-cookie")!.split(";")[0]!;
  const csrfFrom = async (response: Response) => {
    const html = await response.text();
    const token = /name="csrf" value="([a-f0-9]{64})"/u.exec(html)?.[1];
    assert.ok(token); return token;
  };
  const login = async (clientId: string, scope = READ_SCOPES.join(" ")) => {
    const initial = await begin(clientId, { scope }); assert.equal(initial.status, 303);
    const cookie = cookieFrom(initial);
    const csrf = await csrfFrom(await request("/oauth/login", undefined, cookie));
    const response = await request("/oauth/login", { username: "owner", password, csrf }, cookie, { origin: new URL(issuer).origin });
    assert.equal(response.status, 303); const loggedInCookie = cookieFrom(response);
    assert.notEqual(loggedInCookie, cookie);
    return { cookie: loggedInCookie, csrf: await csrfFrom(await request("/oauth/consent", undefined, loggedInCookie)) };
  };
  const authorize = async (clientId: string, scope = READ_SCOPES.join(" ")) => {
    const session = await login(clientId, scope);
    const response = await request("/oauth/consent", { csrf: session.csrf, decision: "allow" }, session.cookie, { origin: new URL(issuer).origin });
    assert.equal(response.status, 303);
    const location = new URL(response.headers.get("location")!);
    assert.equal(location.searchParams.get("state"), "client-state");
    assert.equal(location.searchParams.get("iss"), issuer);
    const code = location.searchParams.get("code"); assert.ok(code); return code;
  };
  const exchange = (clientId: string, code: string, codeVerifier = verifier) => request("/token", { grant_type: "authorization_code", client_id: clientId, code,
    code_verifier: codeVerifier, redirect_uri: redirectUri, resource: resource.href });
  const issue = async (scope = READ_SCOPES.join(" ")) => {
    const clientId = await register(); const code = await authorize(clientId, scope);
    const response = await exchange(clientId, code);
    if (response.status !== 200) assert.fail(`Token exchange failed: ${await response.text()}`);
    return { clientId, code, ...await response.json() as { access_token: string; refresh_token: string } };
  };
  const edgeVerifier = async () => createJwtAccessTokenVerifier({ issuer: new URL(issuer), issuerId: config.issuerId, resourceServerUrl: resource,
    jwks: await (await request("/jwks")).json(),
    revocationCheck: createOAuthGrantRevocationCheck({ url: new URL("/oauth/status", issuer), key: statusKey,
      fetch: async (_url, init) => request("/oauth/status", JSON.parse(String(init?.body)), undefined, { authorization: String((init?.headers as Record<string, string>).authorization) }) })
  });
  return { directory, statusKey, signingKey, request, register, registerResponse, begin, login, authorize, exchange, issue, cookieFrom, csrfFrom, edgeVerifier, config,
    store: () => store, provider: () => provider,
    restart: async () => { await stop(); store.close(); store = new AuthStore(directory); provider = await start(); } };
}

test("owner login and explicit consent issue JWTs accepted by Edge and the bounded R1 read tools", async t => {
  const f = await fixture(t);
  const tokens = await f.issue();
  const edge = await f.edgeVerifier();
  const auth = await edge.verifyAccessToken(tokens.access_token);
  assert.deepEqual(auth.scopes, [...READ_SCOPES]);
  const principal = projectPrincipal(auth, { edgeId: "edge-1", brokerAudience: "mac-operator-broker", resourceServerUrl: resource });
  const policy = createDefaultPolicy("edge-1", true, auth.scopes, ["edge-key-1"], [{ rootId: "test-home", path: f.directory, metadata: true, contentRead: true, write: false, denyRelativePaths: [] }], ["system/com.apple.logd"], ["system"], [f.directory], ["contract-container"]);
  policy.principalGrants = new Map([["owner-1", { principalId: "owner-1", issuer: f.config.issuerId, scopes: [...auth.scopes], enabled: true }]]);
  policy.targetRules = policy.targetRules.map(rule => ({ ...rule, principalId: "owner-1" }));
  for (const tool of policy.tools.values()) tool.enabled = (READ_TOOLS as readonly string[]).includes(tool.tool);
  const brokerStore = new BrokerStore(join(f.directory, "broker.sqlite"));
  const key = randomBytes(32);
  const broker = new Broker({ policy, store: brokerStore, edgeAuthenticationKeys: new EdgeKeyring([{ edgeId: "edge-1", keyId: "edge-key-1", key, notBeforeMs: Date.now() - 1000, expiresAtMs: Date.now() + 300000 }]) });
  const requests = new EdgeRequestFactory({ authenticationKey: key, authenticationKeyId: "edge-key-1", brokerAudience: "mac-operator-broker", policyVersion: () => policy.version });
  try {
    assert.deepEqual([...broker.enabledRuntimeCapabilityNames()].sort(), READ_TOOLS);
    const summary = await broker.handle(requests.create("mac_system_summary", {}, principal));
    assert.equal(summary.ok, true);
    if (summary.ok) {
      const data = summary.data as { cpu_count: number; memory_bytes: number };
      assert.equal(data.cpu_count, cpus().length); assert.equal(data.memory_bytes, totalmem());
    }
    for (const tool of ["mac_task_run", "mac_ui_action", "mac_priv_power"]) {
      assert.equal((await broker.handle(requests.create(tool, {}, principal))).ok, false);
    }
    assert.ok(brokerStore.auditRows().length > 0);
    const audit = JSON.stringify(brokerStore.auditRows());
    assert.equal(audit.includes(tokens.access_token), false); assert.equal(audit.includes(password), false);
  } finally { await broker.close(); requests.dispose(); key.fill(0); brokerStore.close(); }
  const database = await readFile(join(f.directory, "auth.sqlite"));
  for (const secret of [password, tokens.access_token, tokens.refresh_token, tokens.code]) assert.equal(database.includes(Buffer.from(secret)), false);
});

test("discovery, host checks, redirect allowlist and S256 scope/resource boundaries", async t => {
  const f = await fixture(t);
  const metadata = await (await f.request("/.well-known/oauth-authorization-server")).json();
  assert.deepEqual(metadata.code_challenge_methods_supported, ["S256"]);
  assert.equal(metadata.authorization_response_iss_parameter_supported, true);
  assert.equal((await f.request("/jwks", undefined, undefined, { host: "attacker.test" })).status, 403);
  const client = await f.register();
  for (const overrides of [{ redirect_uri: "https://attacker.test/callback" }, { code_challenge_method: "plain" },
    { scope: "mac.control.read mac.files.write" }, { resource: "https://other.test/mcp" }, { state: "" }]) {
    assert.equal((await f.begin(client, overrides)).status, 400);
  }
  assert.equal((await f.request("/token", { grant_type: "password", username: "owner", password })).status, 400);
});

test("native loopback callbacks require a canonical explicit port and preserve HTTPS issuer/resource", async t => {
  const callback = "http://127.0.0.1:61989/callback";
  const f = await fixture(t, undefined, "r1", undefined, false, callback);
  for (const uri of ["http://127.0.0.1/callback", "http://127.0.0.1:80/callback", "http://127.0.0.1:1023/callback",
    "http://localhost:61989/callback", "http://[::1]:61989/callback", "http://192.168.1.1:61989/callback",
    "http://127.0.0.1.attacker.test:61989/callback", "http://2130706433:61989/callback", "http://127.1:61989/callback",
    "http://user@127.0.0.1:61989/callback", "http://127.0.0.1:61989/callback?next=other", "http://127.0.0.1:61989/callback#fragment",
    "http://127.0.0.1:61989/callback?", "http://127.0.0.1:61989/callback#"]) {
    assert.equal(configSchema.safeParse({ ...f.config, allowedRedirectUris: [uri] }).success, false, uri);
  }
  assert.equal(configSchema.safeParse({ ...f.config, issuer: "http://127.0.0.1:61989/", resource: "http://127.0.0.1:61989/mcp" }).success, false);
  assert.equal(configSchema.safeParse({ ...f.config, resource: callback }).success, false);
  const httpsOnly = await fixture(t);
  assert.equal((await httpsOnly.registerResponse(callback)).status, 400);
});

test("native loopback login survives restart while redirect and S256 exchange remain exact", async t => {
  const callback = "http://127.0.0.1:61989/callback";
  const f = await fixture(t, undefined, "r1", undefined, false, callback);
  for (const uri of [redirectUri, "http://127.0.0.1:61990/callback", "http://127.0.0.1:61989/other", "http://localhost:61989/callback"]) {
    const registered = await f.registerResponse(uri);
    assert.equal(registered.status, 400);
  }
  const clientId = await f.register();
  for (const uri of ["http://127.0.0.1:61990/callback", "http://127.0.0.1:61989/other"]) {
    assert.equal((await f.begin(clientId, { redirect_uri: uri })).status, 400);
  }
  const session = await f.login(clientId);
  await f.restart();
  const consent = await f.request("/oauth/consent", { csrf: session.csrf, decision: "allow" }, session.cookie, { origin: new URL(issuer).origin });
  assert.equal(consent.status, 303);
  const location = new URL(consent.headers.get("location")!);
  assert.equal(location.origin + location.pathname, callback);
  assert.equal(location.searchParams.get("iss"), issuer);
  const code = location.searchParams.get("code")!;
  await f.restart();
  const exchanged = await f.exchange(clientId, code);
  assert.equal(exchanged.status, 200);
  const tokens = await exchanged.json() as { access_token: string };
  assert.deepEqual((await (await f.edgeVerifier()).verifyAccessToken(tokens.access_token)).scopes, [...READ_SCOPES]);
  const wrongRedirectCode = await f.authorize(clientId);
  assert.equal((await f.request("/token", { grant_type: "authorization_code", client_id: clientId, code: wrongRedirectCode,
    code_verifier: verifier, redirect_uri: "http://127.0.0.1:61990/callback", resource: resource.href })).status, 400);
  assert.equal((await f.exchange(clientId, wrongRedirectCode)).status, 400);
  const wrongVerifierCode = await f.authorize(clientId);
  assert.equal((await f.exchange(clientId, wrongVerifierCode, "b".repeat(43))).status, 400);
  assert.equal((await f.exchange(clientId, wrongVerifierCode)).status, 400);
});

test("D1 staging grant profile exposes only its explicit scope set", async t => {
  const f = await fixture(t, undefined, "d1");
  const metadata = await (await f.request("/.well-known/oauth-authorization-server")).json() as { scopes_supported: string[] };
  assert.deepEqual(metadata.scopes_supported, [...D1_SCOPES]);
  const client = await f.register();
  assert.equal((await f.begin(client, { scope: D1_SCOPES.join(" ") })).status, 303);
  assert.equal((await f.begin(client, { scope: "mac.control.read mac.priv.service" })).status, 400);
  const session = await f.login(client);
  const consent = await f.request("/oauth/consent", undefined, session.cookie);
  assert.equal(consent.status, 200);
  assert.match(await consent.text(), /separate Broker owner approval/u);
});

test("W1 owner grant exposes project writes without task or service control", async t => {
  const f = await fixture(t, undefined, "w1");
  const metadata = await (await f.request("/.well-known/oauth-authorization-server")).json() as { scopes_supported: string[] };
  assert.deepEqual(metadata.scopes_supported, [...W1_SCOPES]);
  const client = await f.register();
  assert.equal((await f.begin(client, { scope: W1_SCOPES.join(" ") })).status, 303);
  for (const scope of ["mac.task.run", "mac.service.control", "mac.gui.control", "mac.priv.service"]) {
    assert.equal((await f.begin(client, { scope: `mac.control.read ${scope}` })).status, 400);
  }
  const tokens = await f.issue(W1_SCOPES.join(" "));
  const auth = await (await f.edgeVerifier()).verifyAccessToken(tokens.access_token);
  assert.deepEqual(auth.scopes, [...W1_SCOPES]);
});

test("isolated D1 canary binds the Auth grant to Edge tools/list and owner-approved write", async t => {
  const f = await fixture(t, undefined, "d1");
  const tokens = await f.issue(D1_SCOPES.join(" "));
  const tokenVerifier = await f.edgeVerifier();
  const auth = await tokenVerifier.verifyAccessToken(tokens.access_token);
  assert.deepEqual(auth.scopes, [...D1_SCOPES]);
  const d1Scopes = [...D1_SCOPES];
  const root = { rootId: "d1-canary", path: f.directory, metadata: true, contentRead: true, write: true, denyRelativePaths: [] } as const;
  const gitRoot = await realpath(await mkdtemp(join(f.directory, "d1-canary-git-")));
  const gitPath = join(gitRoot, "README.md");
  await runCanaryGit(gitRoot, ["init", "-q", "--initial-branch=main"]);
  await runCanaryGit(gitRoot, ["config", "user.name", "D1 Canary"]);
  await runCanaryGit(gitRoot, ["config", "user.email", "d1-canary@example.invalid"]);
  await writeFile(gitPath, "d1-canary-before\n", { mode: 0o600 });
  await runCanaryGit(gitRoot, ["add", "--", "README.md"]);
  await runCanaryGit(gitRoot, ["commit", "--no-verify", "--no-gpg-sign", "-m", "d1 initial"]);
  await writeFile(gitPath, "d1-canary-after\n", { mode: 0o600 });
  const taskRoot = await realpath(await mkdtemp(join(f.directory, "d1-canary-task-")));
  const appSandboxTaskCanaryEnabled = process.platform === "darwin" && process.env.MOPS_REAL_APP_SANDBOX === "1";
  const appSandboxHostileCanaryEnabled = appSandboxTaskCanaryEnabled && process.env.MOPS_REAL_APP_SANDBOX_HOSTILE === "1";
  if (process.env.MOPS_REAL_APP_SANDBOX_HOSTILE === "1" && !appSandboxTaskCanaryEnabled) {
    throw new Error("The hostile quarantine canary requires MOPS_REAL_APP_SANDBOX=1 on macOS");
  }
  const taskCanaryEnabled = process.platform === "darwin" && (process.env.MOPS_REAL_SANDBOX === "1" || appSandboxTaskCanaryEnabled);
  if (appSandboxTaskCanaryEnabled && process.env.MOPS_REAL_SANDBOX === "1") {
    throw new Error("Choose exactly one physical task canary runner");
  }
  const printfProfile = {
    schemaVersion: "0.1" as const,
    profile: "d1.printf",
    executable: "/usr/bin/printf",
    executableContentSha256: createHash("sha256").update(await readFile("/usr/bin/printf")).digest("hex"),
    fixedArgs: ["d1-auth-task"],
    allowedCwdRoots: [taskRoot],
    maxArguments: 0,
    environment: { LANG: "C" },
    filesystemRoots: [taskRoot],
    networkPolicy: "none" as const,
    credentialPolicy: "none" as const,
    processTreePolicy: "single_process" as const,
    sandboxProfile: "deny-default-v0.1",
    timeoutMs: 5_000,
    outputCapBytes: 1_024,
    verificationStrategy: "exit_status_and_declared_task_verification" as const,
    enabled: true
  };
  const sleepProfile = {
    ...printfProfile,
    profile: "d1.sleep",
    executable: "/bin/sleep",
    executableContentSha256: createHash("sha256").update(await readFile("/bin/sleep")).digest("hex"),
    fixedArgs: ["30"],
    timeoutMs: 60_000
  };
  const appSandboxScriptPath = join(taskRoot, "d1-app-sandbox-task.sh");
  const appSandboxScript = "#!/bin/sh\nset -eu\nprintf 'd1-auth-app-sandbox-task'\n";
  const appSandboxHostileScriptPath = join(taskRoot, "d1-app-sandbox-hostile-task.sh");
  const appSandboxHostileScript = `#!/bin/sh
set -eu
exec /usr/bin/perl -MPOSIX -e '
my $child = fork();
die "first fork failed" unless defined $child;
if ($child == 0) {
  my $session = POSIX::setsid();
  die "first setsid failed" unless defined $session;
  my $grandchild = fork();
  die "second fork failed" unless defined $grandchild;
  if ($grandchild == 0) {
    my $grandchild_session = POSIX::setsid();
    die "second setsid failed" unless defined $grandchild_session;
    $| = 1;
    print STDOUT "MOP_D1_DETACHED_GRANDCHILD pid=$$ parent=", getppid(), " process_group=", getpgrp(0), "\\n";
    select(undef, undef, undef, 1.5);
    exit 0;
  }
  waitpid($grandchild, 0);
  exit 0;
}
waitpid($child, 0);
'`;
  if (appSandboxTaskCanaryEnabled) await writeFile(appSandboxScriptPath, appSandboxScript, { mode: 0o700 });
  if (appSandboxHostileCanaryEnabled) await writeFile(appSandboxHostileScriptPath, appSandboxHostileScript, { mode: 0o700 });
  const appSandboxProfile = {
    schemaVersion: "0.1" as const,
    profile: "d1.app_sandbox",
    executable: "/bin/sh",
    executableContentSha256: createHash("sha256").update(await readFile("/bin/sh")).digest("hex"),
    executionKind: "posix-sh-script" as const,
    scriptPath: appSandboxScriptPath,
    fixedArgs: [],
    allowedCwdRoots: [taskRoot],
    maxArguments: 0,
    environment: { LANG: "C" },
    filesystemRoots: [taskRoot],
    networkPolicy: "none" as const,
    credentialPolicy: "none" as const,
    processTreePolicy: "single_process" as const,
    sandboxProfile: "app-sandbox-deny-default-v0.1",
    timeoutMs: 5_000,
    outputCapBytes: 1_024,
    verificationStrategy: "exit_status_and_declared_task_verification" as const,
    enabled: true
  };
  const appSandboxHostileProfile = {
    ...appSandboxProfile,
    profile: "d1.app_sandbox_hostile",
    scriptPath: appSandboxHostileScriptPath
  };
  const appSandboxSignerAndVerifier = appSandboxTaskCanaryEnabled
    ? (() => {
      const keyPair = generateKeyPairSync("ed25519");
      const signer = new DescriptorSnapshotAttestationSigner({ keyId: "d1-app-sandbox-canary", privateKey: keyPair.privateKey });
      return {
        signer,
        verifier: DescriptorSnapshotAttestationVerifier.create({
          trustedKeys: [{ keyId: signer.keyId, publicKey: keyPair.publicKey }]
        })
      };
    })()
    : undefined;
  const appSandboxHelperPath = join(process.cwd(), "packages/broker/dist/AppSandboxHelper.app/Contents/MacOS/app_sandbox_helper");
  const appSandboxHelperContentSha256 = appSandboxTaskCanaryEnabled
    ? createHash("sha256").update(await readFile(appSandboxHelperPath)).digest("hex")
    : undefined;
  const createAppSandboxAssembly = () => createAppSandboxTaskRunnerFromStartup({
      enabled: true,
      hostEvidenceAccepted: true,
      releaseMode: "development-probe",
      isolationProof: {
        schemaVersion: "0.1",
        sandboxMechanism: "app-sandbox",
        sandboxProfile: "app-sandbox-deny-default-v0.1",
        filesystem: "enforced",
        network: "enforced",
        credentials: "isolated",
        persistence: "isolated",
        credentialIsolation: "app-sandbox-container-no-host-credentials-v1",
        processTree: "observer-only",
        processTreePolicy: "single_process",
        evidenceRef: "evidence://2026-09-22-d1-app-sandbox-auth-edge-broker",
        executableSelection: "app-sandbox-helper-v1"
      },
      signer: appSandboxSignerAndVerifier!.signer,
      verifier: appSandboxSignerAndVerifier!.verifier,
      helperPath: appSandboxHelperPath,
      containerRoot: join(homedir(), "Library/Containers/com.macoperator.mopappsandboxhelper/Data"),
      helperContentSha256: appSandboxHelperContentSha256!,
      evidenceRef: "evidence://2026-09-22-d1-app-sandbox-auth-edge-broker"
    });
  const appSandboxAssembly = appSandboxTaskCanaryEnabled ? createAppSandboxAssembly() : undefined;
  const taskProfiles = appSandboxTaskCanaryEnabled
    ? [appSandboxProfile, ...(appSandboxHostileCanaryEnabled ? [appSandboxHostileProfile] : [])]
    : taskCanaryEnabled ? [printfProfile, sleepProfile] : [printfProfile];
  const taskRunner = appSandboxAssembly?.taskRunner ?? (taskCanaryEnabled ? new SandboxExecTaskRunner({
    enabled: true,
    hostEvidenceAccepted: true,
    executionBoundary: "system-published",
    systemPublishedExecutableAllowlist: ["/usr/bin/printf", "/bin/sleep"],
    systemPublishedExecutablePathAccepted: true,
    allowedEnvironmentKeys: ["LANG"],
    protectedFilesystemRoots: [f.directory],
    isolationProof: {
      schemaVersion: "0.1",
      sandboxMechanism: "sandbox-exec",
      sandboxProfile: "deny-default-v0.1",
      filesystem: "enforced",
      network: "enforced",
      credentials: "isolated",
      persistence: "isolated",
      credentialIsolation: "sandbox-exec-empty-env-deny-secret-zones-v1",
      processTree: "owned",
      processTreePolicy: "single_process",
      evidenceRef: "evidence://2026-09-21-d1-task-boundary",
      executableSelection: "system-published-root-owned-v1"
    }
  }) : undefined);
  if (taskCanaryEnabled) assert.equal(taskRunner?.available, true);
  const taskProfileName = appSandboxTaskCanaryEnabled ? "d1.app_sandbox" : "d1.printf";
  const taskExpectedStdout = appSandboxTaskCanaryEnabled ? "d1-auth-app-sandbox-task" : "d1-auth-task";
  const brokerStorePath = join(f.directory, "d1-canary-broker.sqlite");
  let brokerStore = new BrokerStore(brokerStorePath);
  let brokerStoreOpen = true;
  const userServiceCanary = process.platform === "darwin" && process.env.MOPS_REAL_USER_SERVICE === "1"
    ? await setupD1UserServiceCanary(brokerStore)
    : undefined;
  const policy = createDefaultPolicy("edge-1", true, d1Scopes, ["edge-key-1"], [root], [], [], [f.directory, gitRoot], [], taskProfiles.map(profile => profile.profile));
  policy.principalGrants = new Map([["owner-1", { principalId: "owner-1", issuer: f.config.issuerId, scopes: d1Scopes, enabled: true }]]);
  policy.targetRules = policy.targetRules.map(rule => ({ ...rule, principalId: "owner-1" }));
  if (userServiceCanary !== undefined) {
    policy.targetRules = [...policy.targetRules, {
      ruleId: "d1-user-service-canary",
      effect: "allow",
      principalId: "owner-1",
      scope: "mac.service.control",
      target: { kind: "service", reference: userServiceCanary.serviceId }
    }];
  }
  const enabledTools = new Set([
    "mac_capabilities", "mac_health", "mac_job_status", "mac_job_cancel",
    "mac_write_file_atomic", "mac_apply_patch", "mac_git_stage", "mac_git_commit",
    ...(taskCanaryEnabled ? ["mac_task_run"] : []),
    ...(userServiceCanary === undefined ? [] : ["mac_service_control"])
  ]);
  for (const tool of policy.tools.values()) tool.enabled = enabledTools.has(tool.tool);

  const key = randomBytes(32);
  const requestFactory = new EdgeRequestFactory({ authenticationKey: key, authenticationKeyId: "edge-key-1", brokerAudience: "mac-operator-broker", policyVersion: () => policy.version });
  const createCanaryBroker = (runner: typeof taskRunner) => new Broker({
      policy,
      store: brokerStore,
      edgeAuthenticationKeys: new EdgeKeyring([{ edgeId: "edge-1", keyId: "edge-key-1", key, notBeforeMs: Date.now() - 1_000, expiresAtMs: Date.now() + 300_000 }]),
      ...(runner === undefined ? {} : { taskProfileRegistry: new TaskProfileRegistry(taskProfiles), taskRunner: runner }),
      ...(userServiceCanary === undefined ? {} : {
        userServiceControlCandidate: {
          adapter: userServiceCanary.runtime.adapter,
          executor: userServiceCanary.runtime.executor,
          authorizedPrincipalIds: ["owner-1"],
          enabled: true
        }
      })
    });
  let broker = createCanaryBroker(taskRunner);
  const gateway = {
    execute: (tool: string, argumentsValue: Readonly<Record<string, unknown>>, principal: Parameters<typeof requestFactory.create>[2]) =>
      broker.handle(requestFactory.create(tool, argumentsValue, principal))
  };
  const tlsDirectory = join(f.directory, "d1-canary-tls");
  await mkdir(tlsDirectory, { mode: 0o700 });
  const tls = await createCanaryCertificate(tlsDirectory);
  const edge = createHttpsMcpEdge({
    edgeId: "edge-1", brokerAudience: "mac-operator-broker", resourceServerUrl: resource, contracts, gateway,
    bindHost: "127.0.0.1", allowedHosts: ["mac.example.test"], allowedOrigins: ["client.example.test"],
    tlsCertificate: await readFile(tls.certificatePath), tlsPrivateKey: await readFile(tls.keyPath), oauthIssuer: new URL(issuer),
    tokenVerifier, requiredScopes: ["mac.control.read", "mac.files.write"],
    oauthMetadata: {
      issuer, authorization_endpoint: `${issuer}authorize`, token_endpoint: `${issuer}token`, response_types_supported: ["code"],
      scopes_supported: [...D1_SCOPES]
    }
  });
  const client = new Client({ name: "mac-operator-d1-canary", version: "1.0.0" }, { capabilities: {}, versionNegotiation: { mode: { pin: "2026-07-28" } } });
  let transport: StreamableHTTPClientTransport | undefined;
  const nativeProcessAdapter = appSandboxHostileCanaryEnabled ? loadNativePeerAdapter() : undefined;
  let hostileProcessIdentity: { pid: number; startTimeMicros: number; parentPid: number; processGroupId: number } | undefined;
  const mutationPath = join(f.directory, "d1-canary.txt");
  const mutationArguments = { path: mutationPath, content: "d1-canary-approved", idempotency_key: "d1-canary-write", encoding: "utf8", create_only: true };
  const patchPath = join(f.directory, "d1-canary-patch.txt");
  const patchText = ["*** Begin Patch", "*** Update File: d1-canary-patch.txt", "@@", "-before", "+after", "*** End Patch", ""].join("\n");
  const patchArguments = { project_root: f.directory, patch: patchText };
  const stageArguments = { project_root: gitRoot, paths: ["README.md"] };
  const mismatchCommitArguments = { project_root: gitRoot, message: "d1 mismatch must not commit", expected_staged_diff_sha256: "0".repeat(64) };
  const cancelJobId = "job:d1-canary-cancel";
  await writeFile(patchPath, "before\n", { mode: 0o600 });
  try {
    edge.server.listen(0, "127.0.0.1");
    await once(edge.server, "listening");
    const address = edge.server.address();
    assert.ok(address && typeof address === "object");
    transport = new StreamableHTTPClientTransport(new URL(`https://mac.example.test:${address.port}${resource.pathname}`), {
      authProvider: { token: async () => tokens.access_token }, fetch: createCanaryFetch(address.port), onInsufficientScope: "throw"
    });
    await client.connect(transport);
    assert.deepEqual(client.getServerVersion(), { name: "Mac-Operator-MCP", version: "0.1.0" });
    assert.deepEqual((await client.listTools()).tools.map(tool => tool.name).sort(), [...enabledTools].sort());

    const denied = await client.callTool({ name: "mac_write_file_atomic", arguments: mutationArguments });
    const deniedText = denied.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
    assert.ok(deniedText);
    assert.equal((JSON.parse(deniedText.text) as { result_class: string }).result_class, "POLICY_DENIED");
    assert.equal(await readFile(mutationPath).catch(() => undefined), undefined);
    const deniedPayload = JSON.parse(deniedText.text) as { request_id: string };
    assert.ok(brokerStore.approvalPreview(deniedPayload.request_id, Date.now()));

    brokerStore.issueApproval({
      approvalId: "approval:d1-canary-write", approverPrincipalId: "owner-1", requestingPrincipalId: "owner-1",
      tool: "mac_write_file_atomic", contractVersion: "0.1", targetKind: "path", targetRef: "path:d1-canary",
      payloadDigest: sha256(canonicalJson(mutationArguments)), policyVersion: policy.version, approvalClass: "trusted_write",
      unattended: false, issuedAtMs: Date.now() - 1_000, expiresAtMs: Date.now() + 60_000
    });
    const approved = await client.callTool({ name: "mac_write_file_atomic", arguments: mutationArguments });
    const approvedText = approved.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
    assert.ok(approvedText);
    assert.equal((JSON.parse(approvedText.text) as { ok: boolean }).ok, true);
    assert.equal((await readFile(mutationPath, "utf8")), mutationArguments.content);

    const patchDenied = await client.callTool({ name: "mac_apply_patch", arguments: patchArguments });
    const patchDeniedText = patchDenied.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
    assert.ok(patchDeniedText);
    assert.equal((JSON.parse(patchDeniedText.text) as { result_class: string }).result_class, "POLICY_DENIED");
    assert.equal(await readFile(patchPath, "utf8"), "before\n");
    const patchDeniedPayload = JSON.parse(patchDeniedText.text) as { request_id: string };
    assert.ok(brokerStore.approvalPreview(patchDeniedPayload.request_id, Date.now()));
    brokerStore.issueApproval({
      approvalId: "approval:d1-canary-patch", approverPrincipalId: "owner-1", requestingPrincipalId: "owner-1",
      tool: "mac_apply_patch", contractVersion: "0.1", targetKind: "project", targetRef: `project:${f.directory}`,
      payloadDigest: sha256(canonicalJson(patchArguments)), policyVersion: policy.version, approvalClass: "trusted_write",
      unattended: false, issuedAtMs: Date.now() - 1_000, expiresAtMs: Date.now() + 60_000
    });
    const patchApproved = await client.callTool({ name: "mac_apply_patch", arguments: patchArguments });
    const patchApprovedText = patchApproved.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
    assert.ok(patchApprovedText);
    const patchResult = JSON.parse(patchApprovedText.text) as { ok: boolean; data?: { changed_paths: string[] }; verification?: { status: string } };
    assert.equal(patchResult.ok, true);
    assert.deepEqual(patchResult.data?.changed_paths, ["d1-canary-patch.txt"]);
    assert.equal(patchResult.verification?.status, "verified");
    assert.equal(await readFile(patchPath, "utf8"), "after\n");

    const stageDenied = await client.callTool({ name: "mac_git_stage", arguments: stageArguments });
    const stageDeniedText = stageDenied.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
    assert.ok(stageDeniedText);
    assert.equal((JSON.parse(stageDeniedText.text) as { result_class: string }).result_class, "POLICY_DENIED");
    assert.equal((await runCanaryGit(gitRoot, ["diff", "--cached", "--name-only"])).stdout.trim(), "");
    const stageDeniedPayload = JSON.parse(stageDeniedText.text) as { request_id: string };
    assert.ok(brokerStore.approvalPreview(stageDeniedPayload.request_id, Date.now()));
    brokerStore.issueApproval({
      approvalId: "approval:d1-canary-stage", approverPrincipalId: "owner-1", requestingPrincipalId: "owner-1",
      tool: "mac_git_stage", contractVersion: "0.1", targetKind: "project", targetRef: `project:${gitRoot}`,
      payloadDigest: sha256(canonicalJson(stageArguments)), policyVersion: policy.version, approvalClass: "trusted_write",
      unattended: false, issuedAtMs: Date.now() - 1_000, expiresAtMs: Date.now() + 60_000
    });
    const stageApproved = await client.callTool({ name: "mac_git_stage", arguments: stageArguments });
    const stageApprovedText = stageApproved.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
    assert.ok(stageApprovedText);
    const stageResult = JSON.parse(stageApprovedText.text) as { ok: boolean; request_id: string; data?: { staged_paths: string[]; staged_diff_sha256: string } };
    assert.equal(stageResult.ok, true);
    assert.deepEqual(stageResult.data?.staged_paths, ["README.md"]);
    assert.match(stageResult.data?.staged_diff_sha256 ?? "", /^[a-f0-9]{64}$/u);
    const stageJobId = brokerStore.requestRecord(stageResult.request_id)?.jobId;
    assert.ok(stageJobId);
    const stageJob = brokerStore.ownedJob(stageJobId, "owner-1");
    assert.equal(stageJob?.state, "completed");
    assert.equal((await runCanaryGit(gitRoot, ["diff", "--cached", "--name-only"])).stdout.trim(), "README.md");

    brokerStore.issueApproval({
      approvalId: "approval:d1-canary-commit-mismatch", approverPrincipalId: "owner-1", requestingPrincipalId: "owner-1",
      tool: "mac_git_commit", contractVersion: "0.1", targetKind: "project", targetRef: `project:${gitRoot}`,
      payloadDigest: sha256(canonicalJson(mismatchCommitArguments)), policyVersion: policy.version, approvalClass: "trusted_write",
      unattended: false, issuedAtMs: Date.now() - 1_000, expiresAtMs: Date.now() + 60_000
    });
    const mismatch = await client.callTool({ name: "mac_git_commit", arguments: mismatchCommitArguments });
    const mismatchText = mismatch.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
    assert.ok(mismatchText);
    const mismatchResult = JSON.parse(mismatchText.text) as { request_id: string; result_class: string };
    assert.equal(mismatchResult.result_class, "PRECONDITION_FAILED");
    const mismatchJobId = brokerStore.requestRecord(mismatchResult.request_id)?.jobId;
    assert.ok(mismatchJobId);
    const mismatchJob = brokerStore.ownedJob(mismatchJobId, "owner-1");
    assert.equal(mismatchJob?.state, "unknown");
    assert.equal((await runCanaryGit(gitRoot, ["rev-parse", "HEAD"])).stdout.trim().length, 40);
    assert.equal((await runCanaryGit(gitRoot, ["diff", "--cached", "--name-only"])).stdout.trim(), "README.md");

    const commitArguments = { project_root: gitRoot, message: "d1 canary verified local commit", expected_staged_diff_sha256: stageResult.data!.staged_diff_sha256 };
    brokerStore.issueApproval({
      approvalId: "approval:d1-canary-commit", approverPrincipalId: "owner-1", requestingPrincipalId: "owner-1",
      tool: "mac_git_commit", contractVersion: "0.1", targetKind: "project", targetRef: `project:${gitRoot}`,
      payloadDigest: sha256(canonicalJson(commitArguments)), policyVersion: policy.version, approvalClass: "trusted_write",
      unattended: false, issuedAtMs: Date.now() - 1_000, expiresAtMs: Date.now() + 60_000
    });
    const commitApproved = await client.callTool({ name: "mac_git_commit", arguments: commitArguments });
    const commitApprovedText = commitApproved.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
    assert.ok(commitApprovedText);
    const commitResult = JSON.parse(commitApprovedText.text) as { ok: boolean; request_id: string; data?: { commit_id: string; precondition: { matched: boolean }; working_tree_state: string } };
    assert.equal(commitResult.ok, true);
    assert.match(commitResult.data?.commit_id ?? "", /^[a-f0-9]{40,64}$/u);
    assert.equal(commitResult.data?.precondition.matched, true);
    assert.equal(commitResult.data?.working_tree_state, "clean");
    const commitJobId = brokerStore.requestRecord(commitResult.request_id)?.jobId;
    assert.ok(commitJobId);
    const commitJob = brokerStore.ownedJob(commitJobId, "owner-1");
    assert.equal(commitJob?.state, "completed");
    assert.equal((await runCanaryGit(gitRoot, ["rev-parse", "HEAD"])).stdout.trim(), commitResult.data!.commit_id);
    assert.equal((await runCanaryGit(gitRoot, ["diff", "--cached", "--name-only"])).stdout.trim(), "");
    assert.equal((await runCanaryGit(gitRoot, ["status", "--porcelain"])).stdout.trim(), "");
    assert.equal((await runCanaryGit(gitRoot, ["remote"])).stdout.trim(), "");
    assert.equal(await readFile(gitPath, "utf8"), "d1-canary-after\n");

    if (taskCanaryEnabled) {
      const taskArguments = { profile: taskProfileName, cwd: taskRoot, args: [], async: false };
      const taskDenied = await client.callTool({ name: "mac_task_run", arguments: taskArguments });
      const taskDeniedText = taskDenied.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
      assert.ok(taskDeniedText);
      assert.equal((JSON.parse(taskDeniedText.text) as { result_class: string }).result_class, "POLICY_DENIED");
      const taskDeniedPayload = JSON.parse(taskDeniedText.text) as { request_id: string };
      assert.ok(brokerStore.approvalPreview(taskDeniedPayload.request_id, Date.now()));
      brokerStore.issueApproval({
        approvalId: "approval:d1-canary-task", approverPrincipalId: "owner-1", requestingPrincipalId: "owner-1",
        tool: "mac_task_run", contractVersion: "0.1", targetKind: "task_profile", targetRef: `task_profile:${taskProfileName}`,
        payloadDigest: sha256(canonicalJson(taskArguments)), policyVersion: policy.version, approvalClass: "trusted_profile",
        unattended: false, issuedAtMs: Date.now() - 1_000, expiresAtMs: Date.now() + 60_000
      });
      const taskApproved = await client.callTool({ name: "mac_task_run", arguments: taskArguments });
      const taskApprovedText = taskApproved.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
      assert.ok(taskApprovedText);
      const taskResult = JSON.parse(taskApprovedText.text) as { ok: boolean; request_id: string; data?: { stdout: string; state: string; job_id?: string }; verification?: { status: string } };
      assert.equal(taskResult.ok, true);
      assert.equal(taskResult.data?.stdout, taskExpectedStdout);
      assert.equal(taskResult.data?.state, "completed");
      assert.equal(taskResult.verification?.status, "verified");
      const taskJobId = brokerStore.requestRecord(taskResult.request_id)?.jobId;
      assert.ok(taskJobId);
      assert.equal(brokerStore.ownedJob(taskJobId, "owner-1")?.state, "completed");
      assert.equal(brokerStore.ownedJob(taskJobId, "owner-1")?.processMetadata, undefined);
      const taskStatus = await client.callTool({ name: "mac_job_status", arguments: { job_id: taskJobId, tail_bytes: 1_024 } });
      const taskStatusText = taskStatus.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
      assert.ok(taskStatusText);
      assert.equal((JSON.parse(taskStatusText.text) as { data?: { state: string } }).data?.state, "completed");

      if (appSandboxHostileCanaryEnabled) {
        const hostileArguments = { profile: "d1.app_sandbox_hostile", cwd: taskRoot, args: [], async: false };
        const hostileDenied = await client.callTool({ name: "mac_task_run", arguments: hostileArguments });
        const hostileDeniedText = hostileDenied.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
        assert.ok(hostileDeniedText);
        assert.equal((JSON.parse(hostileDeniedText.text) as { result_class: string }).result_class, "POLICY_DENIED");
        const hostileDeniedPayload = JSON.parse(hostileDeniedText.text) as { request_id: string };
        assert.ok(brokerStore.approvalPreview(hostileDeniedPayload.request_id, Date.now()));
        brokerStore.issueApproval({
          approvalId: "approval:d1-canary-hostile-task", approverPrincipalId: "owner-1", requestingPrincipalId: "owner-1",
          tool: "mac_task_run", contractVersion: "0.1", targetKind: "task_profile", targetRef: "task_profile:d1.app_sandbox_hostile",
          payloadDigest: sha256(canonicalJson(hostileArguments)), policyVersion: policy.version, approvalClass: "trusted_profile",
          unattended: false, issuedAtMs: Date.now() - 1_000, expiresAtMs: Date.now() + 60_000
        });
        const hostileCall = await client.callTool({ name: "mac_task_run", arguments: hostileArguments });
        const hostileCallText = hostileCall.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
        assert.ok(hostileCallText);
        const hostileResult = JSON.parse(hostileCallText.text) as { ok: boolean; request_id: string; result_class: string };
        assert.equal(hostileResult.ok, false);
        assert.equal(hostileResult.result_class, "UNKNOWN_OUTCOME");
        assert.equal(brokerStore.approvalRecord("approval:d1-canary-hostile-task")?.usedCount, 1);
        const hostileJobId = brokerStore.requestRecord(hostileResult.request_id)?.jobId;
        assert.ok(hostileJobId);
        const hostileJob = brokerStore.ownedJob(hostileJobId, "owner-1");
        assert.equal(hostileJob?.state, "unknown");
        assert.equal(hostileJob?.resultClass, "unknown");
        assert.equal(hostileJob?.processMetadata?.ownershipProof, undefined);
        assert.ok(hostileJob?.processMetadata);
        const detachedMarker = /MOP_D1_DETACHED_GRANDCHILD pid=(\d+) parent=(\d+) process_group=(\d+)/u.exec(hostileJob.stdout);
        assert.ok(detachedMarker, "the Broker Job must retain the bounded hostile-task identity marker");
        const detachedIdentity = parseCanaryProcessIdentity(nativeProcessAdapter!.getProcessIdentity(Number(detachedMarker[1])));
        assert.ok(detachedIdentity, "the detached child must have a native PID/start-time identity");
        hostileProcessIdentity = detachedIdentity;
        assert.equal(detachedIdentity.parentPid, Number(detachedMarker[2]));
        assert.equal(detachedIdentity.processGroupId, Number(detachedMarker[3]));
        assert.notEqual(detachedIdentity.parentPid, hostileJob.processMetadata.pid);
        assert.notEqual(detachedIdentity.processGroupId, hostileJob.processMetadata.processGroupId);
        assert.equal(nativeProcessAdapter!.isProcessIdentityAlive(detachedIdentity.pid, detachedIdentity.startTimeMicros), true);
        assert.equal(brokerStore.hasUnresolvedHostTaskExecution(), true);
        assert.equal(broker.enabledRuntimeCapabilityNames().includes("mac_task_run"), false);

        await terminateExactCanaryProcess(nativeProcessAdapter!, detachedIdentity);
        assert.equal(nativeProcessAdapter!.isProcessIdentityAlive(detachedIdentity.pid, detachedIdentity.startTimeMicros), false);

        await broker.close();
        brokerStore.close();
        brokerStoreOpen = false;
        brokerStore = new BrokerStore(brokerStorePath);
        brokerStoreOpen = true;
        const restartedAssembly = createAppSandboxAssembly();
        assert.equal(restartedAssembly.taskRunner.available, true);
        broker = createCanaryBroker(restartedAssembly.taskRunner);
        assert.equal(broker.enabledRuntimeCapabilityNames().includes("mac_task_run"), false);

        const capabilitiesCall = await client.callTool({ name: "mac_capabilities", arguments: {} });
        const capabilitiesText = capabilitiesCall.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
        assert.ok(capabilitiesText);
        const capabilities = JSON.parse(capabilitiesText.text) as {
          data?: { capabilities: Array<{ name: string; enabled: boolean; reason: string }> };
        };
        const taskCapability = capabilities.data?.capabilities.find(capability => capability.name === "mac_task_run");
        assert.equal(taskCapability?.enabled, false);
        assert.equal(taskCapability?.reason, "runtime_unavailable");

        brokerStore.issueApproval({
          approvalId: "approval:d1-canary-after-quarantine", approverPrincipalId: "owner-1", requestingPrincipalId: "owner-1",
          tool: "mac_task_run", contractVersion: "0.1", targetKind: "task_profile", targetRef: "task_profile:d1.app_sandbox_hostile",
          payloadDigest: sha256(canonicalJson(hostileArguments)), policyVersion: policy.version, approvalClass: "trusted_profile",
          unattended: false, issuedAtMs: Date.now() - 1_000, expiresAtMs: Date.now() + 60_000
        });
        const afterQuarantine = await client.callTool({ name: "mac_task_run", arguments: hostileArguments });
        const afterQuarantineText = afterQuarantine.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
        assert.ok(afterQuarantineText);
        const afterQuarantineResult = JSON.parse(afterQuarantineText.text) as { request_id: string; result_class: string };
        assert.equal(afterQuarantineResult.result_class, "POLICY_DENIED");
        assert.equal(brokerStore.approvalRecord("approval:d1-canary-after-quarantine")?.usedCount, 0);
        assert.equal(brokerStore.requestRecord(afterQuarantineResult.request_id)?.jobId ?? null, null);
        assert.equal(brokerStore.hasUnresolvedHostTaskExecution(), true);
      }

      if (!appSandboxTaskCanaryEnabled) {
        const sleepArguments = { profile: "d1.sleep", cwd: taskRoot, args: [], async: false };
        const sleepDenied = await client.callTool({ name: "mac_task_run", arguments: sleepArguments });
        const sleepDeniedText = sleepDenied.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
        assert.ok(sleepDeniedText);
        assert.equal((JSON.parse(sleepDeniedText.text) as { result_class: string }).result_class, "POLICY_DENIED");
        const sleepDeniedPayload = JSON.parse(sleepDeniedText.text) as { request_id: string };
        assert.ok(brokerStore.approvalPreview(sleepDeniedPayload.request_id, Date.now()));
        brokerStore.issueApproval({
          approvalId: "approval:d1-canary-sleep", approverPrincipalId: "owner-1", requestingPrincipalId: "owner-1",
          tool: "mac_task_run", contractVersion: "0.1", targetKind: "task_profile", targetRef: "task_profile:d1.sleep",
          payloadDigest: sha256(canonicalJson(sleepArguments)), policyVersion: policy.version, approvalClass: "trusted_profile",
          unattended: false, issuedAtMs: Date.now() - 1_000, expiresAtMs: Date.now() + 60_000
        });
        const sleepPromise = client.callTool({ name: "mac_task_run", arguments: sleepArguments });
        const runningSleepJob = await waitForCanaryRunningTask(brokerStore, "task_profile:d1.sleep");
        assert.equal(runningSleepJob.processMetadata?.ownershipProof, "sandbox-exec-no-fork-v1");
        const activeCancelArguments = { job_id: runningSleepJob.jobId, reason: "d1-auth task cancellation" };
        brokerStore.issueApproval({
          approvalId: "approval:d1-canary-active-cancel", approverPrincipalId: "owner-1", requestingPrincipalId: "owner-1",
          tool: "mac_job_cancel", contractVersion: "0.1", targetKind: "job", targetRef: `job:${runningSleepJob.jobId}`,
          payloadDigest: sha256(canonicalJson(activeCancelArguments)), policyVersion: policy.version, approvalClass: "trusted_write",
          unattended: false, issuedAtMs: Date.now() - 1_000, expiresAtMs: Date.now() + 60_000
        });
        const activeCancel = await client.callTool({ name: "mac_job_cancel", arguments: activeCancelArguments });
        const activeCancelText = activeCancel.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
        assert.ok(activeCancelText);
        const activeCancelResult = JSON.parse(activeCancelText.text) as {
          ok: boolean;
          data?: { new_state: string; cancel_requested: boolean; termination_observed: boolean };
        };
        assert.equal(activeCancelResult.ok, true);
        assert.equal(activeCancelResult.data?.new_state, "running");
        assert.equal(activeCancelResult.data?.cancel_requested, true);
        assert.equal(activeCancelResult.data?.termination_observed, false);
        const sleepResult = await sleepPromise;
        const sleepResultText = sleepResult.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
        assert.ok(sleepResultText);
        const sleepResultPayload = JSON.parse(sleepResultText.text) as { ok: boolean; result_class: string };
        assert.equal(sleepResultPayload.ok, false);
        assert.ok(["CANCELLED", "CONFLICT"].includes(sleepResultPayload.result_class));
        const cancelledSleepJob = brokerStore.ownedJob(runningSleepJob.jobId, "owner-1");
        assert.equal(cancelledSleepJob?.state, "cancelled");
        assert.equal(cancelledSleepJob?.processMetadata, undefined);
        const cancelledStatus = await client.callTool({ name: "mac_job_status", arguments: { job_id: runningSleepJob.jobId, tail_bytes: 1_024 } });
        const cancelledStatusText = cancelledStatus.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
        assert.ok(cancelledStatusText);
        const cancelledStatusPayload = JSON.parse(cancelledStatusText.text) as { data?: { state: string; result_class: string } };
        assert.equal(cancelledStatusPayload.data?.state, "cancelled");
        assert.equal(cancelledStatusPayload.data?.result_class, "denied");
      }
    }

    if (userServiceCanary !== undefined) {
      const serviceArguments = {
        service_id: userServiceCanary.serviceId,
        action: "start",
        expected_state: "running",
        idempotency_key: "d1-auth-service-start"
      };
      const serviceDenied = await client.callTool({ name: "mac_service_control", arguments: serviceArguments });
      const serviceDeniedText = serviceDenied.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
      assert.ok(serviceDeniedText);
      const serviceDeniedPayload = JSON.parse(serviceDeniedText.text) as { result_class: string; request_id: string };
      assert.equal(serviceDeniedPayload.result_class, "POLICY_DENIED");
      assert.ok(brokerStore.approvalPreview(serviceDeniedPayload.request_id, Date.now()));
      brokerStore.issueApproval({
        approvalId: "approval:d1-auth-service-start", approverPrincipalId: "owner-1", requestingPrincipalId: "owner-1",
        tool: "mac_service_control", contractVersion: "0.1", targetKind: "service", targetRef: `service:${userServiceCanary.serviceId}`,
        payloadDigest: sha256(canonicalJson(serviceArguments)), policyVersion: policy.version, approvalClass: "trusted_write",
        unattended: false, issuedAtMs: Date.now() - 1_000, expiresAtMs: Date.now() + 60_000
      });
      const serviceApproved = await client.callTool({ name: "mac_service_control", arguments: serviceArguments });
      const serviceApprovedText = serviceApproved.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
      assert.ok(serviceApprovedText);
      const serviceResult = JSON.parse(serviceApprovedText.text) as {
        ok: boolean;
        request_id: string;
        data?: { service_id: string; post_state: string; rollback_status: string };
        verification?: { status: string };
      };
      assert.equal(serviceResult.ok, true);
      assert.equal(serviceResult.data?.service_id, userServiceCanary.serviceId);
      assert.equal(serviceResult.data?.post_state, "running");
      assert.equal(serviceResult.data?.rollback_status, "not_needed");
      assert.equal(serviceResult.verification?.status, "verified");
      const stopArguments = { ...serviceArguments, action: "stop", expected_state: "stopped", idempotency_key: "d1-auth-service-stop" };
      brokerStore.issueApproval({
        approvalId: "approval:d1-auth-service-stop", approverPrincipalId: "owner-1", requestingPrincipalId: "owner-1",
        tool: "mac_service_control", contractVersion: "0.1", targetKind: "service", targetRef: `service:${userServiceCanary.serviceId}`,
        payloadDigest: sha256(canonicalJson(stopArguments)), policyVersion: policy.version, approvalClass: "trusted_write",
        unattended: false, issuedAtMs: Date.now() - 1_000, expiresAtMs: Date.now() + 60_000
      });
      const serviceStopped = await client.callTool({ name: "mac_service_control", arguments: stopArguments });
      const serviceStoppedText = serviceStopped.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
      assert.ok(serviceStoppedText);
      const stopResult = JSON.parse(serviceStoppedText.text) as { ok: boolean; data?: { post_state: string }; verification?: { status: string } };
      assert.equal(stopResult.ok, true);
      assert.equal(stopResult.data?.post_state, "stopped");
      assert.equal(stopResult.verification?.status, "verified");
    }

    brokerStore.createJob({
      jobId: cancelJobId, ownerPrincipalId: "owner-1", ownerSessionId: "d1-canary-session", tool: "mac_task_run",
      targetRef: "task:d1-canary", policyVersion: policy.version, payloadDigest: "a".repeat(64),
      idempotencyKey: "d1-canary-job", createdAtMs: Date.now()
    });
    const cancelArguments = { job_id: cancelJobId, reason: "d1-canary" };
    const cancelDenied = await client.callTool({ name: "mac_job_cancel", arguments: cancelArguments });
    const cancelDeniedText = cancelDenied.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
    assert.ok(cancelDeniedText);
    assert.equal((JSON.parse(cancelDeniedText.text) as { result_class: string }).result_class, "POLICY_DENIED");
    assert.equal(brokerStore.ownedJob(cancelJobId, "owner-1")?.state, "queued");
    const cancelDeniedPayload = JSON.parse(cancelDeniedText.text) as { request_id: string };
    assert.ok(brokerStore.approvalPreview(cancelDeniedPayload.request_id, Date.now()));
    brokerStore.issueApproval({
      approvalId: "approval:d1-canary-cancel", approverPrincipalId: "owner-1", requestingPrincipalId: "owner-1",
      tool: "mac_job_cancel", contractVersion: "0.1", targetKind: "job", targetRef: `job:${cancelJobId}`,
      payloadDigest: sha256(canonicalJson(cancelArguments)), policyVersion: policy.version, approvalClass: "trusted_write",
      unattended: false, issuedAtMs: Date.now() - 1_000, expiresAtMs: Date.now() + 60_000
    });
    const cancelApproved = await client.callTool({ name: "mac_job_cancel", arguments: cancelArguments });
    const cancelApprovedText = cancelApproved.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
    assert.ok(cancelApprovedText);
    assert.equal((JSON.parse(cancelApprovedText.text) as { ok: boolean }).ok, true);
    assert.equal(brokerStore.ownedJob(cancelJobId, "owner-1")?.state, "cancelled");
    if (taskCanaryEnabled && !appSandboxTaskCanaryEnabled) {
      const edgeRevocationArguments = { profile: "d1.sleep", cwd: taskRoot, args: [], async: false };
      brokerStore.issueApproval({
        approvalId: "approval:d1-canary-edge-revocation", approverPrincipalId: "owner-1", requestingPrincipalId: "owner-1",
        tool: "mac_task_run", contractVersion: "0.1", targetKind: "task_profile", targetRef: "task_profile:d1.sleep",
        payloadDigest: sha256(canonicalJson(edgeRevocationArguments)), policyVersion: policy.version, approvalClass: "trusted_profile",
        unattended: false, issuedAtMs: Date.now() - 1_000, expiresAtMs: Date.now() + 60_000
      });
      const edgeRevocationPromise = client.callTool({ name: "mac_task_run", arguments: edgeRevocationArguments });
      const runningEdgeRevocationJob = await waitForCanaryRunningTask(brokerStore, "task_profile:d1.sleep");
      assert.equal(runningEdgeRevocationJob.processMetadata?.ownershipProof, "sandbox-exec-no-fork-v1");
      broker.revokeEdge("edge-1", "d1 active Edge revocation", Date.now());
      const edgeRevocationResult = await edgeRevocationPromise;
      const edgeRevocationText = edgeRevocationResult.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
      assert.ok(edgeRevocationText);
      assert.equal((JSON.parse(edgeRevocationText.text) as { result_class: string }).result_class, "CANCELLED");
      assert.equal(brokerStore.isRevoked("edge", "edge-1"), true);
      const unresolvedEdgeRevocationJob = brokerStore.ownedJob(runningEdgeRevocationJob.jobId, "owner-1");
      assert.equal(unresolvedEdgeRevocationJob?.state, "unknown");
      assert.equal(unresolvedEdgeRevocationJob?.resultClass, "unknown");
      assert.equal(unresolvedEdgeRevocationJob?.processMetadata?.pid, runningEdgeRevocationJob.processMetadata?.pid);
      assert.equal(unresolvedEdgeRevocationJob?.processMetadata?.ownershipProof, "sandbox-exec-no-fork-v1");
    }
    const auditText = JSON.stringify(brokerStore.auditRows());
    assert.equal(auditText.includes(tokens.access_token), false);
    assert.equal(auditText.includes("d1 canary verified local commit"), false);
    if (taskCanaryEnabled) {
      assert.equal(auditText.includes(taskExpectedStdout), false);
      if (!appSandboxTaskCanaryEnabled) assert.equal(auditText.includes("d1 active Edge revocation"), false);
    }
  } finally {
    if (hostileProcessIdentity !== undefined) await terminateExactCanaryProcess(nativeProcessAdapter!, hostileProcessIdentity);
    await client.close().catch(() => undefined);
    await transport?.close().catch(() => undefined);
    await edge.close().catch(() => undefined);
    await broker.close().catch(() => undefined);
    await userServiceCanary?.cleanup();
    requestFactory.dispose();
    key.fill(0);
    if (brokerStoreOpen) brokerStore.close();
  }
});

test("wrong passwords, CSRF and consent bypass fail; session rotates after login", async t => {
  const f = await fixture(t); const client = await f.register();
  const initial = await f.begin(client); const cookie = f.cookieFrom(initial);
  const csrf = await f.csrfFrom(await f.request("/oauth/login", undefined, cookie));
  assert.equal((await f.request("/oauth/consent", { csrf, decision: "allow" }, cookie)).status, 403);
  assert.equal((await f.request("/oauth/login", { csrf: "0".repeat(64), username: "owner", password }, cookie)).status, 400);
  assert.equal((await f.request("/oauth/login", { csrf, username: "owner", password }, cookie, { origin: "https://attacker.test" })).status, 400);
  const wrong = await f.request("/oauth/login", { csrf, username: "owner", password: "wrong" }, cookie);
  assert.equal(wrong.status, 401); assert.ok((await wrong.text()).includes("Unable to sign in"));
  const response = await f.request("/oauth/login", { csrf, username: "owner", password }, cookie);
  assert.equal(response.status, 303); assert.notEqual(f.cookieFrom(response), cookie);
  assert.equal((await f.request("/oauth/login", undefined, cookie)).status, 400);
});

test("consent denial returns access_denied and unsafe client names are escaped", async t => {
  const f = await fixture(t); const client = await f.register(); const session = await f.login(client);
  const html = await (await f.request("/oauth/consent", undefined, session.cookie)).text();
  assert.ok(html.includes("&lt;script&gt;")); assert.ok(!html.includes("<script>"));
  const denied = await f.request("/oauth/consent", { csrf: session.csrf, decision: "deny" }, session.cookie);
  assert.equal(new URL(denied.headers.get("location")!).searchParams.get("error"), "access_denied");
  assert.equal(new URL(denied.headers.get("location")!).searchParams.get("iss"), issuer);
  assert.equal((await f.request("/oauth/consent", { csrf: session.csrf, decision: "allow" }, session.cookie)).status, 400);
});

test("authorization code is single use, expires, and consumes on incorrect PKCE", async t => {
  const f = await fixture(t); const client = await f.register(); const code = await f.authorize(client);
  assert.equal((await f.exchange(client, code, "x".repeat(43))).status, 400);
  assert.equal((await f.exchange(client, code)).status, 400);
  const expired = await f.authorize(client);
  const record = f.store().get("code", fingerprint(expired))!;
  f.store().put("code", fingerprint(expired), { ...record, expiresAt: Date.now() - 1 });
  assert.equal((await f.exchange(client, expired)).status, 400);
  const tokens = await f.issue(); assert.equal((await f.exchange(tokens.clientId, tokens.code)).status, 400);
});

test("refresh rotation survives restart and replay revokes the entire grant", async t => {
  const f = await fixture(t); const tokens = await f.issue();
  const refresh = await f.request("/token", { grant_type: "refresh_token", client_id: tokens.clientId, refresh_token: tokens.refresh_token });
  assert.equal(refresh.status, 200); const next = await refresh.json();
  assert.notEqual(next.refresh_token, tokens.refresh_token);
  await f.restart();
  const edge = await f.edgeVerifier(); await edge.verifyAccessToken(next.access_token);
  assert.equal((await f.request("/token", { grant_type: "refresh_token", client_id: tokens.clientId, refresh_token: tokens.refresh_token })).status, 400);
  await assert.rejects(edge.verifyAccessToken(next.access_token));
  await f.restart(); await assert.rejects((await f.edgeVerifier()).verifyAccessToken(next.access_token));
});

test("revocation checks reject subsequent Edge calls and reset invalidates sessions/codes", async t => {
  const f = await fixture(t); const tokens = await f.issue(); const edge = await f.edgeVerifier();
  await edge.verifyAccessToken(tokens.access_token);
  await f.request("/revoke", { client_id: "wrong-client", token: tokens.refresh_token });
  await edge.verifyAccessToken(tokens.access_token);
  await f.request("/revoke", { client_id: tokens.clientId, token: tokens.refresh_token });
  await assert.rejects(edge.verifyAccessToken(tokens.access_token));
  const pending = await f.authorize(tokens.clientId);
  f.store().transaction(() => f.store().revokeAll());
  assert.equal((await f.exchange(tokens.clientId, pending)).status, 400);
});

test("grant revocation emits a bounded non-secret notice after durable state change", async t => {
  const notices: Array<{ grantId: string; principalId: string; scopes: readonly string[]; expiresAtMs: number }> = [];
  const f = await fixture(t, undefined, "r1", notice => { notices.push(notice); });
  const tokens = await f.issue();
  const grantId = String(decodeJwt(tokens.access_token).sid);
  assert.ok(grantId);
  assert.equal((await f.request("/revoke", { client_id: tokens.clientId, token: tokens.refresh_token })).status, 200);
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  assert.equal(notices.length, 1);
  assert.deepEqual(notices[0], {
    grantId,
    principalId: "owner-1",
    scopes: [...READ_SCOPES],
    expiresAtMs: f.store().get("grant", grantId)!.expiresAt
  });
});

test("durable AuthStore revocation propagates through authenticated Broker IPC", async t => {
  if (process.platform !== "darwin") {
    t.skip("Native peer-authenticated IPC is a macOS boundary");
    return;
  }
  let gateway: AuthenticatedIpcBrokerGateway | undefined;
  const f = await fixture(t, undefined, "r1", async notice => {
    if (gateway === undefined) throw new Error("Revocation gateway is unavailable");
    await gateway.revokeSession("edge-1", notice.principalId, notice.grantId);
  });
  const brokerStore = new BrokerStore(join(f.directory, "broker.sqlite"));
  const key = randomBytes(32);
  const now = Date.now();
  const broker = new Broker({
    store: brokerStore,
    policy: createDefaultPolicy("edge-1", true, ["mac.control.read"]),
    edgeAuthenticationKeys: new EdgeKeyring([{
      edgeId: "edge-1", keyId: "edge-key-1", key,
      notBeforeMs: now - 60_000, expiresAtMs: now + 300_000
    }]),
    now: () => now
  });
  const socketPath = join(f.directory, "revocation-broker.sock");
  const server = new BrokerIpcServer({ socketPath, broker, peerCredentialVerifier: currentProcessVerifier() });
  const requestFactory = new EdgeRequestFactory({
    authenticationKey: key,
    authenticationKeyId: "edge-key-1",
    brokerAudience: "mac-operator-broker",
    policyVersion: () => "policy-0.1",
    now: () => now,
    randomId: (() => {
      let sequence = 0;
      return () => `auth-revoke-${String(++sequence).padStart(16, "0")}`;
    })()
  });
  await server.listen();
  gateway = new AuthenticatedIpcBrokerGateway(requestFactory, new BrokerIpcClient(
    socketPath,
    (request, response) => requestFactory.verifyResponse(request, response)
  ));
  try {
    const tokens = await f.issue();
    const grantId = String(decodeJwt(tokens.access_token).sid);
    assert.equal((await f.request("/revoke", { client_id: tokens.clientId, token: tokens.refresh_token })).status, 200);
    for (let attempt = 0; attempt < 50 && !brokerStore.isRevoked("session", grantId); attempt += 1) {
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(brokerStore.isRevoked("session", grantId), true);
    assert.equal(brokerStore.auditRows().some(row => row.event_type === "intent" && row.tool === "internal_authority_revoke"), true);
  } finally {
    await server.close();
    await broker.close();
    requestFactory.dispose();
    key.fill(0);
    brokerStore.close();
  }
});

test("long refresh chains stay within capacity and old replays still revoke the grant", async t => {
  const f = await fixture(t); const tokens = await f.issue();
  const chain = [tokens.refresh_token];
  for (let index = 0; index < 8; index++) {
    const response = await f.request("/token", { grant_type: "refresh_token", client_id: tokens.clientId, refresh_token: chain.at(-1)! });
    assert.equal(response.status, 200); chain.push((await response.json()).refresh_token);
  }
  const consumed = chain.slice(0, -1).filter(token => f.store().get("refresh", fingerprint(token))?.consumed === true);
  assert.equal(consumed.length, 3, "only the newest consumed hashes are retained");
  // The latest predecessor is still retained, so replaying it revokes the whole grant.
  assert.equal((await f.request("/token", { grant_type: "refresh_token", client_id: tokens.clientId, refresh_token: chain.at(-2)! })).status, 400);
  assert.equal((await f.request("/token", { grant_type: "refresh_token", client_id: tokens.clientId, refresh_token: chain.at(-1)! })).status, 400);
});

test("refresh cannot escalate scopes and narrowed grants reject older broader tokens", async t => {
  const f = await fixture(t); const tokens = await f.issue();
  assert.equal((await f.request("/token", { grant_type: "refresh_token", client_id: tokens.clientId, refresh_token: tokens.refresh_token, scope: "mac.files.write" })).status, 400);
  const response = await f.request("/token", { grant_type: "refresh_token", client_id: tokens.clientId, refresh_token: tokens.refresh_token, scope: "mac.control.read" });
  assert.equal(response.status, 200); const narrowed = await response.json();
  const edge = await f.edgeVerifier(); await edge.verifyAccessToken(narrowed.access_token);
  await assert.rejects(edge.verifyAccessToken(tokens.access_token));
  const claims = decodeJwt(narrowed.access_token); assert.equal(claims.scope, "mac.control.read");
});

test("grant status authentication, endpoint failure and malformed responses fail closed", async t => {
  const f = await fixture(t); const tokens = await f.issue();
  assert.equal((await f.request("/oauth/status", { sessionId: String(decodeJwt(tokens.access_token).sid), subject: "owner-1" })).status, 401);
  const context = { issuerId: "mac-operator-auth", subject: "owner-1", sessionId: "1".repeat(64), tokenId: "token-1", expiresAt: 9999999999, scopes: ["mac.control.read"] };
  for (const body of [{ active: true }, { active: false, scopes: ["mac.control.read"] }, { active: true, scopes: [] }]) {
    const check = createOAuthGrantRevocationCheck({ url: new URL("/oauth/status", issuer), key: randomBytes(32), fetch: async () => Response.json(body) });
    assert.equal(await check(context), true);
  }
  assert.equal(await createOAuthGrantRevocationCheck({ url: new URL("/oauth/status", issuer), key: randomBytes(32), fetch: async () => { throw new Error("offline"); } })(context), true);
});

test("concurrent refresh exchanges revoke the family and never extend absolute expiry", async t => {
  const f = await fixture(t); const tokens = await f.issue();
  const grantId = String(decodeJwt(tokens.access_token).sid);
  const original = f.store().get("grant", grantId)!;
  const expiresAt = Date.now() + 30_000;
  f.store().put("grant", grantId, { ...original, expiresAt });
  const body = { grant_type: "refresh_token", client_id: tokens.clientId, refresh_token: tokens.refresh_token };
  const results = await Promise.all([f.request("/token", body), f.request("/token", body)]);
  assert.deepEqual(results.map(response => response.status).sort(), [200, 400]);
  const accepted = await results.find(response => response.status === 200)!.json();
  assert.ok(accepted.expires_in <= 30);
  assert.ok(Number(decodeJwt(accepted.access_token).exp) * 1000 <= expiresAt);
  assert.equal(f.store().get("refresh", fingerprint(accepted.refresh_token))!.expiresAt, expiresAt);
  assert.equal(f.store().get("grant", grantId)!.revoked, true);
  await assert.rejects((await f.edgeVerifier()).verifyAccessToken(accepted.access_token));
});

test("login rate limits cannot be bypassed by forwarded addresses", async t => {
  const f = await fixture(t); const client = await f.register();
  const initial = await f.begin(client); const cookie = f.cookieFrom(initial);
  const csrf = await f.csrfFrom(await f.request("/oauth/login", undefined, cookie));
  for (let index = 0; index < 10; index++) {
    assert.equal((await f.request("/oauth/login", { csrf, username: "unknown", password: "wrong" }, cookie,
      { "x-forwarded-for": `192.0.2.${index}` })).status, 401);
  }
  const locked = await f.request("/oauth/login", { csrf, username: "owner", password }, cookie);
  assert.equal(locked.status, 429);
  assert.equal(locked.headers.get("retry-after"), "120");
  const stillLocked = await f.request("/oauth/login", { csrf, username: "owner", password }, cookie);
  assert.equal(stillLocked.status, 429);
  assert.ok(Number(stillLocked.headers.get("retry-after")) <= 120);
});

test("only failed password checks count toward the login lockout", async t => {
  const f = await fixture(t); const client = await f.register();
  // Twelve successful logins in one window would exceed the old per-attempt limit of ten.
  for (let index = 0; index < 12; index++) await f.login(client);
  const initial = await f.begin(client); const cookie = f.cookieFrom(initial);
  const csrf = await f.csrfFrom(await f.request("/oauth/login", undefined, cookie));
  for (let index = 0; index < 9; index++) assert.equal((await f.request("/oauth/login", { csrf, username: "owner", password: "wrong" }, cookie)).status, 401);
  assert.equal((await f.request("/oauth/login", { csrf, username: "owner", password }, cookie)).status, 303);
  const next = await f.begin(client); const nextCookie = f.cookieFrom(next);
  const nextCsrf = await f.csrfFrom(await f.request("/oauth/login", undefined, nextCookie));
  // The success reset the counter, so nine more failures still do not lock the owner out.
  for (let index = 0; index < 9; index++) assert.equal((await f.request("/oauth/login", { csrf: nextCsrf, username: "owner", password: "wrong" }, nextCookie)).status, 401);
  assert.equal((await f.request("/oauth/login", { csrf: nextCsrf, username: "owner", password }, nextCookie)).status, 303);
});

test("local revocation command persists and refuses password arguments and weak files", async t => {
  const f = await fixture(t); const tokens = await f.issue();
  const path = join(f.directory, "auth-config.json");
  await writeFile(path, JSON.stringify(f.config), { mode: 0o600 });
  await assert.rejects(runAuthCli(["reset-password", "--dir", f.directory, "--password", "not-allowed"]));
  await runAuthCli(["revoke-all", "--dir", f.directory]);
  await assert.rejects((await f.edgeVerifier()).verifyAccessToken(tokens.access_token));
  await f.restart();
  await assert.rejects((await f.edgeVerifier()).verifyAccessToken(tokens.access_token));
  assert.deepEqual(JSON.parse(readAuthFile(path).toString()), f.config);
  await chmod(path, 0o644); assert.throws(() => readAuthFile(path));
  await chmod(path, 0o600);
  const link = join(f.directory, "link.json"); await symlink(path, link);
  assert.throws(() => readAuthFile(link));
});

test("auth init persists the explicit D1 OAuth profile without enabling mutation tools", async () => {
  const parent = await realpath(await mkdtemp(join(tmpdir(), "mac-auth-init-")));
  const directory = join(parent, "auth");
  const envFile = join(parent, "credentials.env");
  await writeFile(envFile, "MAC_OPERATOR_USERNAME=owner\nMAC_OPERATOR_PASSWORD=test-only-long-owner-passphrase\n", { mode: 0o600 });
  try {
    await runAuthCli(["init", "--dir", directory, "--env-file", envFile, "--redirect-uri", redirectUri, "--issuer", issuer, "--grant-profile", "d1"]);
    const configBytes = readAuthFile(join(directory, "auth-config.json"));
    const edgeBytes = readAuthFile(join(directory, "edge-auth-settings.json"));
    const policyBytes = readAuthFile(join(directory, "broker-policy-input.json"));
    try {
      assert.equal(JSON.parse(configBytes.toString()).grantProfile, "d1");
      assert.deepEqual(JSON.parse(edgeBytes.toString()).oauthScopes, [...D1_SCOPES]);
      const policy = JSON.parse(policyBytes.toString()) as { principal: { scopes: string[] }; enabled_tools: string[] };
      assert.deepEqual(policy.principal.scopes, [...D1_SCOPES]);
      assert.deepEqual(policy.enabled_tools, [...READ_TOOLS]);
    } finally {
      configBytes.fill(0); edgeBytes.fill(0); policyBytes.fill(0);
    }
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test("auth init keeps the W1 policy input inside one owner Git project", async () => {
  const parent = await realpath(await mkdtemp(join(homedir(), ".mac-auth-w1-init-")));
  const directory = join(parent, "auth");
  const project = join(parent, "project");
  const invalidProject = join(parent, "not-a-git-project");
  const envFile = join(parent, "credentials.env");
  const previousProjectRoot = process.env.MAC_OPERATOR_PROJECT_ROOT;
  await mkdir(project, { mode: 0o700 });
  await mkdir(join(project, ".git"), { mode: 0o700 });
  await mkdir(invalidProject, { mode: 0o700 });
  await writeFile(envFile, "MAC_OPERATOR_USERNAME=owner\nMAC_OPERATOR_PASSWORD=test-only-long-owner-passphrase\n", { mode: 0o600 });
  try {
    process.env.MAC_OPERATOR_PROJECT_ROOT = invalidProject;
    await assert.rejects(runAuthCli(["init", "--dir", directory, "--env-file", envFile,
      "--redirect-uri", redirectUri, "--issuer", issuer, "--grant-profile", "w1"]), /Git repository/u);
    await assert.rejects(lstat(directory), { code: "ENOENT" });
    process.env.MAC_OPERATOR_PROJECT_ROOT = project;
    await runAuthCli(["init", "--dir", directory, "--env-file", envFile, "--redirect-uri", redirectUri, "--issuer", issuer,
      "--grant-profile", "w1"]);
    const configBytes = readAuthFile(join(directory, "auth-config.json"));
    const policyBytes = readAuthFile(join(directory, "broker-policy-input.json"));
    try {
      assert.equal(JSON.parse(configBytes.toString()).grantProfile, "w1");
      const policy = JSON.parse(policyBytes.toString()) as {
        principal: { scopes: string[] }; enabled_tools: string[];
        filesystem_roots: { root_id: string; path: string; write: boolean }[];
        target_rules: { scope: string; target: { kind: string; reference: string } }[];
      };
      assert.deepEqual(policy.principal.scopes, [...W1_SCOPES]);
      assert.deepEqual(policy.enabled_tools, [...W1_TOOLS]);
      assert.deepEqual(policy.filesystem_roots.filter(root => root.write).map(root => root.path), [project]);
      assert.deepEqual(policy.target_rules.filter(rule => rule.scope === "mac.git.write").map(rule => rule.target),
        [{ kind: "project", reference: project }]);
    } finally { configBytes.fill(0); policyBytes.fill(0); }
  } finally {
    if (previousProjectRoot === undefined) delete process.env.MAC_OPERATOR_PROJECT_ROOT;
    else process.env.MAC_OPERATOR_PROJECT_ROOT = previousProjectRoot;
    await rm(parent, { recursive: true, force: true });
  }
});

test("corrupt state is rejected without creating a replacement", async () => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mac-auth-corrupt-")));
  try {
    const path = join(directory, "auth.sqlite");
    await writeFile(path, "invalid database", { mode: 0o600 });
    assert.throws(() => new AuthStore(directory));
    assert.equal(await readFile(path, "utf8"), "invalid database");
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("browser forms preserve same-origin POST signals and reject null or foreign origins", async t => {
  const f = await fixture(t);
  const clientId = await f.register();
  const initial = await f.begin(clientId);
  assert.equal(initial.headers.get("referrer-policy"), "no-referrer");
  const cookie = f.cookieFrom(initial);
  const loginPage = await f.request("/oauth/login", undefined, cookie);
  assert.equal(loginPage.headers.get("referrer-policy"), "same-origin");
  const csrf = await f.csrfFrom(loginPage);
  for (const origin of ["null", "https://attacker.test"]) {
    const rejected = await f.request("/oauth/login", { username: "owner", password, csrf }, cookie, { origin });
    assert.equal(rejected.status, 400);
  }
  const loggedIn = await f.request("/oauth/login", { username: "owner", password, csrf }, cookie, { origin: new URL(issuer).origin });
  assert.equal(loggedIn.status, 303);
  const authenticatedCookie = f.cookieFrom(loggedIn);
  const consent = await f.request("/oauth/consent", undefined, authenticatedCookie);
  assert.equal(consent.headers.get("referrer-policy"), "same-origin");
  const consentCsrf = await f.csrfFrom(consent);
  assert.equal((await f.request("/oauth/consent", { csrf: consentCsrf, decision: "allow" }, authenticatedCookie, { origin: "null" })).status, 400);
  assert.equal((await f.request("/oauth/consent", { csrf: consentCsrf, decision: "allow" }, authenticatedCookie, { origin: new URL(issuer).origin })).status, 303);
});

test("owner browser approval reviews a durable non-secret preview and issues through the bridge", async t => {
  const preview: ApprovalBrowserPreview = {
    requestId: "browser-preview-1", requestingPrincipalId: "owner-1", tool: "mac_service_control", contractVersion: "0.1",
    targetKind: "service", targetRef: "service:gui/501/com.example.agent", payloadDigest: "b".repeat(64),
    policyVersion: "policy-r2", approvalClass: "trusted_write", unattended: false, expiresAtMs: Date.now() + 60_000
  };
  let issued = 0;
  const bridge: ApprovalBrowserBridge = {
    async preview(requestId) { return requestId === preview.requestId ? preview : undefined; },
    async issue(requestId) { assert.equal(requestId, preview.requestId); issued++; return { approvalId: "approval:browser-preview-1", expiresAtMs: preview.expiresAtMs, revision: 3 }; }
  };
  const f = await fixture(t, bridge);
  const initial = await f.request(`/approval?request_id=${preview.requestId}`);
  assert.equal(initial.status, 303);
  const initialCookie = f.cookieFrom(initial);
  const loginPage = await f.request("/approval/login", undefined, initialCookie);
  assert.equal(loginPage.status, 200);
  const csrf = await f.csrfFrom(loginPage);
  const loggedIn = await f.request("/approval/login", { username: "owner", password, csrf }, initialCookie, { origin: new URL(issuer).origin });
  assert.equal(loggedIn.status, 303);
  const cookie = f.cookieFrom(loggedIn);
  const review = await f.request("/approval/review", undefined, cookie);
  assert.equal(review.status, 200);
  assert.equal(review.headers.get("referrer-policy"), "same-origin",
    "The review form must preserve its origin on native browser submission");
  const html = await review.text();
  assert.match(html, /mac_service_control/u);
  assert.match(html, /service:gui\/501\/com\.example\.agent/u);
  assert.match(html, /b{64}/u);
  assert.doesNotMatch(html, /payloadValue/u);
  const reviewCsrf = await f.csrfFrom(new Response(html, { status: 200, headers: { "content-type": "text/html" } }));
  for (const origin of ["null", "https://attacker.test"]) {
    assert.equal((await f.request("/approval/decision", { csrf: reviewCsrf, decision: "allow" }, cookie, { origin })).status, 400);
    assert.equal(issued, 0);
  }
  const approved = await f.request("/approval/decision", { csrf: reviewCsrf, decision: "allow" }, cookie, { origin: new URL(issuer).origin });
  assert.equal(approved.status, 200);
  assert.match(await approved.text(), /approval:browser-preview-1/u);
  assert.equal(issued, 1);
  const nextApproval = await f.request(`/approval?request_id=${preview.requestId}`, undefined, f.cookieFrom(approved));
  assert.equal(nextApproval.headers.get("location"), "/approval/review", "Successful approval must not log the owner out");
  assert.equal((await f.request("/approval/decision", { csrf: reviewCsrf, decision: "allow" }, cookie, { origin: new URL(issuer).origin })).status, 400);
});

test("approval browser route is absent when the owner bridge is not assembled", async t => {
  const f = await fixture(t);
  assert.equal((await f.request("/approval?request_id=browser-preview-1")).status, 404);
});

test("approval expiry keeps owner authentication for a fresh exact request without extending the session", async t => {
  const preview: ApprovalBrowserPreview = {
    requestId: "approval-old", requestingPrincipalId: "owner-1", tool: "mac_app_focus", contractVersion: "0.1",
    targetKind: "app_window", targetRef: "window:com.google.Chrome", payloadDigest: "b".repeat(64),
    policyVersion: "policy-g1", approvalClass: "trusted_gui", unattended: false, expiresAtMs: Date.now() + 60_000
  };
  let issued = 0;
  const f = await fixture(t, {
    async preview(id) { return id === preview.requestId ? preview : undefined; },
    async issue(id) { assert.equal(id, preview.requestId); issued++; return { approvalId: "approval:new", expiresAtMs: preview.expiresAtMs, revision: 1 }; }
  });
  const initial = await f.request("/approval?request_id=approval-old");
  const initialCookie = f.cookieFrom(initial);
  const csrf = await f.csrfFrom(await f.request("/approval/login", undefined, initialCookie));
  const login = await f.request("/approval/login", { username: "owner", password, csrf }, initialCookie);
  const cookie = f.cookieFrom(login);
  const keyOf = (value: string) => createHash("sha256").update(value.split("=")[1]!).digest("hex");
  const expiresAt = f.store().get("approval_session", keyOf(cookie))!.expiresAt;
  preview.expiresAtMs = Date.now() - 1;
  const expired = await f.request("/approval/review", undefined, cookie);
  assert.equal(expired.status, 410);
  assert.match(await expired.text(), /You do not need to reconnect the MCP app/u);
  preview.requestId = "approval-new";
  preview.expiresAtMs = Date.now() + 60_000;
  const next = await f.request("/approval?request_id=approval-new", undefined, cookie);
  assert.equal(next.headers.get("location"), "/approval/review");
  const nextCookie = f.cookieFrom(next);
  assert.notEqual(nextCookie, cookie);
  assert.equal(f.store().get("approval_session", keyOf(cookie)), undefined);
  assert.equal(f.store().get("approval_session", keyOf(nextCookie))!.expiresAt, expiresAt);
  assert.equal(issued, 0);
  assert.equal((await f.request("/approval/decision", { csrf, decision: "allow" }, nextCookie)).status, 400);
  assert.equal(issued, 0);
  const reviewCsrf = await f.csrfFrom(await f.request("/approval/review", undefined, nextCookie));
  assert.equal((await f.request("/approval/decision", { csrf: reviewCsrf, decision: "allow" }, nextCookie)).status, 200);
  assert.equal(issued, 1);
});

test("approval entry rejects unavailable previews before login and distinguishes missing sign-in", async t => {
  const f = await fixture(t, { async preview() { return undefined; }, async issue() { throw new Error("Must not issue"); } });
  const entry = await f.request("/approval?request_id=missing");
  assert.equal(entry.status, 410);
  assert.equal(entry.headers.get("set-cookie"), null);
  assert.match(await entry.text(), /Operation approval unavailable/u);
  const review = await f.request("/approval/review");
  assert.equal(review.status, 400);
  assert.match(await review.text(), /Approval sign-in expired/u);
});

test("consent CSP permits only its validated callback origin and repeated submission shows recovery", async t => {
  const f = await fixture(t);
  const clientId = await f.register();
  const initial = await f.begin(clientId);
  const loginPage = await f.request("/oauth/login", undefined, f.cookieFrom(initial));
  assert.ok(!loginPage.headers.get("content-security-policy")!.includes(new URL(redirectUri).origin));
  const session = await f.login(clientId);
  const consent = await f.request("/oauth/consent", undefined, session.cookie);
  const policy = consent.headers.get("content-security-policy")!;
  assert.ok(policy.includes(`form-action 'self' ${new URL(redirectUri).origin};`));
  assert.ok(!policy.includes("*"));
  assert.ok(policy.includes("default-src 'none'"));
  const allowed = await f.request("/oauth/consent", { csrf: session.csrf, decision: "allow" }, session.cookie);
  assert.equal(allowed.status, 303);
  assert.equal(allowed.headers.get("content-security-policy"), policy);
  assert.equal(new URL(allowed.headers.get("location")!).origin, new URL(redirectUri).origin);
  const repeated = await f.request("/oauth/consent", { csrf: session.csrf, decision: "allow" }, session.cookie);
  assert.equal(repeated.status, 400);
  assert.ok((await repeated.text()).includes("Start a new connection"));
});

async function createCanaryCertificate(directory: string): Promise<{ certificatePath: string; keyPath: string }> {
  const certificatePath = join(directory, "edge.crt");
  const keyPath = join(directory, "edge.key");
  await execFileAsync("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyPath,
    "-out", certificatePath, "-days", "1", "-subj", "/CN=mac.example.test", "-addext", "subjectAltName=DNS:mac.example.test"], {
    cwd: "/", env: { PATH: "/usr/bin:/bin" }, timeout: 10_000, maxBuffer: 64 * 1024
  });
  return { certificatePath, keyPath };
}

async function runCanaryGit(cwd: string, args: readonly string[]) {
  return await execFileAsync("/usr/bin/git", [...args], {
    cwd,
    env: {
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      HOME: "/var/empty",
      LANG: "C",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_SYSTEM: "/dev/null",
      GIT_NO_REPLACE_OBJECTS: "1",
      GIT_TERMINAL_PROMPT: "0",
      GIT_OPTIONAL_LOCKS: "0"
    },
    timeout: 10_000,
    maxBuffer: 256 * 1024
  });
}

async function setupD1UserServiceCanary(store: BrokerStore): Promise<{
  serviceId: string;
  runtime: ReturnType<typeof createUserServiceControlRuntime>;
  cleanup: () => Promise<void>;
}> {
  const uid = process.getuid?.();
  if (process.platform !== "darwin" || uid === undefined || uid < 1) {
    throw new Error("D1 user-service canary requires a non-root macOS user");
  }
  const label = "com.mac-operator.d1-auth-canary";
  const serviceId = `gui/${uid}/${label}`;
  const domain = `gui/${uid}`;
  const launchAgentDirectory = join(homedir(), "Library", "LaunchAgents");
  const plistPath = join(launchAgentDirectory, `${label}.plist`);
  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>${label}</string>
<key>ProgramArguments</key><array><string>/bin/sleep</string><string>60</string></array>
<key>RunAtLoad</key><false/>
<key>KeepAlive</key><false/>
</dict></plist>
`;
  const sourceRevision = sha256(Buffer.from(plist, "utf8"));
  let plistCreated = false;
  let loaded = false;
  const cleanup = async () => {
    if (loaded) {
      const bootout = await runLaunchctl(["bootout", domain, plistPath]);
      const status = await runLaunchctl(["print", serviceId]);
      if (status.code === 0) throw new Error("D1 user-service canary remained loaded after cleanup");
      if (bootout.code === null) throw new Error("D1 user-service canary cleanup was not observable");
      loaded = false;
    }
    if (plistCreated) {
      const entry = await lstat(plistPath);
      if (!entry.isFile() || entry.isSymbolicLink() || entry.uid !== uid || (entry.mode & 0o077) !== 0) {
        throw new Error("D1 user-service canary plist failed owner-only cleanup checks");
      }
      await unlink(plistPath);
      plistCreated = false;
    }
  };
  try {
    if (await realpath(launchAgentDirectory) !== launchAgentDirectory) throw new Error("D1 user-service LaunchAgents directory is not canonical");
    const existing = await runLaunchctl(["print", serviceId]);
    if (existing.code === 0) throw new Error("D1 user-service canary identity is already loaded");
    if (existing.code === null) throw new Error("D1 user-service canary identity absence is not observable");
    await writeFile(plistPath, plist, { mode: 0o600, flag: "wx" });
    plistCreated = true;
    const entry = await lstat(plistPath);
    if (!entry.isFile() || entry.isSymbolicLink() || entry.uid !== uid || (entry.mode & 0o077) !== 0 || await realpath(plistPath) !== plistPath) {
      throw new Error("D1 user-service canary plist failed owner-only checks");
    }
    const bootstrap = await runLaunchctl(["bootstrap", domain, plistPath]);
    if (bootstrap.code !== 0) throw new Error(`D1 user-service canary bootstrap failed (${bootstrap.code ?? "unknown"})`);
    loaded = true;
    const runtime = createUserServiceControlRuntime({
      store,
      startup: {
        enabled: true,
        uid,
        bindings: [{ serviceId, sourceRevision, plistPath, program: "/bin/sleep", arguments: ["/bin/sleep", "60"] }],
        authorizedPrincipalIds: ["owner-1"],
        sourceRevisionReader: {
          read: async (requestedServiceId, control) => {
            if (requestedServiceId !== serviceId || control.shouldCancel()) throw new Error("D1 user-service source readback was not authorized");
            return sha256(await readFile(plistPath));
          }
        },
        systemPublishedExecutablePathAccepted: true
      },
      now: () => Date.now()
    });
    if (!runtime.adapter.available || !runtime.executor.available) throw new Error("D1 user-service canary runtime is unavailable");
    return { serviceId, runtime, cleanup };
  } catch (error) {
    await cleanup().catch(() => undefined);
    throw error;
  }
}

async function runLaunchctl(args: readonly string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  try {
    const result = await execFileAsync("/bin/launchctl", [...args], {
      cwd: "/",
      env: {},
      timeout: 5_000,
      maxBuffer: 128 * 1024
    });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    const record = error && typeof error === "object" ? error as Record<string, unknown> : {};
    return {
      code: typeof record.code === "number" ? record.code : null,
      stdout: typeof record.stdout === "string" ? record.stdout : "",
      stderr: typeof record.stderr === "string" ? record.stderr : ""
    };
  }
}

async function waitForCanaryRunningTask(store: BrokerStore, targetRef: string) {
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const audit = [...store.auditRows()].reverse().find(row =>
      row.tool === "mac_task_run" && row.event_type === "intent" && row.target_ref === targetRef
    );
    const requestId = typeof audit?.request_id === "string" ? audit.request_id : undefined;
    const jobId = requestId === undefined ? undefined : store.requestRecord(requestId)?.jobId;
    const job = jobId === undefined || jobId === null ? undefined : store.ownedJob(jobId, "owner-1");
    if (job?.state === "running" && job.processMetadata?.pid !== undefined) return job;
    await new Promise<void>(resolve => setTimeout(resolve, 10));
  }
  throw new Error("Task did not expose a running Broker-owned process identity through the HTTPS canary");
}

function currentProcessVerifier(): MacOsPeerCredentialVerifier {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined) throw new Error("POSIX identity is unavailable");
  return new MacOsPeerCredentialVerifier({ expectedUid: uid, expectedGid: gid, allowedProcessIds: new Set([process.pid]) });
}

function createCanaryFetch(port: number): FetchLike {
  return async (input, init = {}) => {
    const target = typeof input === "string" ? new URL(input) : new URL(input.href);
    const headers = new Headers(init.headers);
    headers.set("Host", "mac.example.test");
    headers.set("Origin", "https://client.example.test");
    const requestBody = init.body === undefined ? undefined : typeof init.body === "string" ? Buffer.from(init.body) : init.body as Uint8Array;
    return await new Promise<Response>((resolveResponse, reject) => {
      const request = https.request({ hostname: "127.0.0.1", port, path: `${target.pathname}${target.search}`, method: init.method ?? "GET",
        headers: Object.fromEntries(headers), rejectUnauthorized: false, agent: false }, response => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () => {
          const responseHeaders = new Headers();
          for (const [name, value] of Object.entries(response.headers)) if (value !== undefined) responseHeaders.set(name, Array.isArray(value) ? value.join(", ") : value);
          resolveResponse(new Response(Buffer.concat(chunks), { status: response.statusCode ?? 500, headers: responseHeaders }));
        });
      });
      request.once("error", reject);
      if (init.signal) {
        if (init.signal.aborted) { request.destroy(); reject(init.signal.reason ?? new Error("Request aborted")); return; }
        init.signal.addEventListener("abort", () => request.destroy(init.signal?.reason), { once: true });
      }
      if (requestBody !== undefined) request.write(requestBody);
      request.end();
    });
  };
}

test("owner GUI session consent preserves sign-in and exposes a CSRF-protected stop control", async t => {
  const preview: ApprovalBrowserPreview = { requestId: "session-preview", requestingPrincipalId: "owner-1",
    tool: "mac_app_focus", contractVersion: "0.1", targetKind: "app_window", targetRef: "app_window:window:bundle:com.google.Chrome",
    payloadDigest: "b".repeat(64), policyVersion: "policy-1", approvalClass: "trusted_gui", unattended: false,
    expiresAtMs: Date.now() + 600000, sessionEligible: true };
  let starts = 0, revoked = false;
  const grant = { id: "gui-session:12345678-1234-1234-1234-123456789abc", appId: "bundle:com.google.Chrome", expiresAtMs: Date.now() + 1800000, remainingOperations: 500 };
  const f = await fixture(t, { async preview() { return preview; }, async issue() { throw new Error("Not per-operation consent"); },
    async startSession(id) { assert.equal(id, preview.requestId); starts++; return grant; },
    async sessionStatus(id) { assert.equal(id, grant.id); return revoked ? undefined : grant; },
    async revokeSession(id) { assert.equal(id, grant.id); revoked = true; } });
  const entry = await f.request("/approval?request_id=session-preview");
  const initial = f.cookieFrom(entry);
  const csrf = await f.csrfFrom(await f.request("/approval/login", undefined, initial));
  assert.equal((await f.request("/approval/decision", { csrf, decision: "allow-session" }, initial)).status, 403);
  const login = await f.request("/approval/login", { username: "owner", password, csrf }, initial);
  const cookie = f.cookieFrom(login);
  const review = await f.request("/approval/review", undefined, cookie);
  const reviewCsrf = await f.csrfFrom(review);
  assert.equal((await f.request("/approval/decision", { csrf: reviewCsrf, decision: "allow-session" }, cookie, { origin: "https://other.test" })).status, 400);
  const approved = await f.request("/approval/decision", { csrf: reviewCsrf, decision: "allow-session" }, cookie);
  assert.equal(approved.status, 303);
  assert.equal(starts, 1);
  const activeCookie = f.cookieFrom(approved);
  const status = await f.request("/approval/gui-session", undefined, activeCookie);
  const html = await status.text();
  assert.match(html, /Browser session active/u);
  const stopCsrf = await f.csrfFrom(new Response(html));
  assert.equal((await f.request("/approval/gui-session/revoke", { csrf: "0".repeat(64) }, activeCookie)).status, 400);
  assert.equal(revoked, false);
  const stopped = await f.request("/approval/gui-session/revoke", { csrf: stopCsrf }, activeCookie);
  assert.equal(stopped.status, 303);
  assert.equal(revoked, true);
  const next = await f.request("/approval?request_id=session-preview", undefined, f.cookieFrom(stopped));
  assert.equal(next.headers.get("location"), "/approval/review");
});


test("persistent consent and management login do not depend on a live operation preview", async t => {
  const preview: ApprovalBrowserPreview = { requestId: "persistent-preview", requestingPrincipalId: "owner-1",
    tool: "mac_app_focus", contractVersion: "0.1", targetKind: "app_window", targetRef: "app_window:window:bundle:com.google.Chrome",
    payloadDigest: "b".repeat(64), policyVersion: "policy-1", approvalClass: "trusted_gui", unattended: false,
    expiresAtMs: Date.now() + 600000, sessionEligible: true };
  let started = false, revoked = false, previewAvailable = true;
  const grant = { id: "gui-session:12345678-1234-1234-1234-123456789abc", appId: "bundle:com.google.Chrome",
    persistent: true, expiresAtMs: Number.MAX_SAFE_INTEGER, remainingOperations: Number.MAX_SAFE_INTEGER };
  const f = await fixture(t, { async preview() { return previewAvailable ? preview : undefined; }, async issue() { throw new Error("Unexpected single approval"); },
    async startPersistentSession(id) { assert.equal(id, preview.requestId); started = true; return grant; },
    async listSessions() { return started && !revoked ? [grant] : []; },
    async sessionStatus() { return revoked ? undefined : grant; },
    async revokeSession(id) { assert.equal(id, grant.id); revoked = true; } });
  const entry = await f.request("/approval?request_id=persistent-preview");
  const initial = f.cookieFrom(entry);
  const csrf = await f.csrfFrom(await f.request("/approval/login", undefined, initial));
  assert.equal((await f.request("/approval/decision", { csrf, decision: "allow-permanent" }, initial)).status, 403);
  const login = await f.request("/approval/login", { username: "owner", password, csrf }, initial);
  const cookie = f.cookieFrom(login);
  const reviewHtml = await (await f.request("/approval/review", undefined, cookie)).text();
  assert.match(reviewHtml, /Allow this browser until revoked/u);
  assert.match(reviewHtml, /Allow this browser for 30 minutes/u);
  const reviewCsrf = await f.csrfFrom(new Response(reviewHtml));
  const approved = await f.request("/approval/decision", { csrf: reviewCsrf, decision: "allow-permanent" }, cookie);
  assert.equal(approved.status, 303);
  assert.equal(started, true);
  const activeCookie = f.cookieFrom(approved);
  const activeKey = createHash("sha256").update(activeCookie.split("=")[1]!).digest("hex");
  assert.ok(f.store().get("approval_session", activeKey)!.expiresAt < Date.now() + 31 * 60000);
  assert.match(await (await f.request("/approval/gui-session", undefined, activeCookie)).text(), /Until revoked/u);
  previewAvailable = false;
  // A fresh management login remains available even after every preview and cookie expires.
  assert.equal((await f.request("/approval/gui-session")).headers.get("location"), "/approval/access");
  const manage = await f.request("/approval/access");
  const managementCookie = f.cookieFrom(manage);
  const page = await f.request("/approval/login", undefined, managementCookie);
  assert.equal(page.status, 200);
  const managementCsrf = await f.csrfFrom(page);
  const loggedIn = await f.request("/approval/login", { username: "owner", password, csrf: managementCsrf }, managementCookie);
  assert.equal(loggedIn.headers.get("location"), "/approval/gui-session");
  const manageCookie = f.cookieFrom(loggedIn);
  const status = await f.request("/approval/gui-session", undefined, manageCookie);
  const stopCsrf = await f.csrfFrom(status);
  assert.equal((await f.request("/approval/gui-session/revoke", { csrf: "0".repeat(64), grant_id: grant.id }, manageCookie)).status, 400);
  assert.equal((await f.request("/approval/gui-session/revoke", { csrf: stopCsrf, grant_id: "gui-session:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" }, manageCookie)).status, 403);
  const stop = await f.request("/approval/gui-session/revoke", { csrf: stopCsrf, grant_id: grant.id }, manageCookie);
  assert.equal(stop.status, 303);
  assert.equal(revoked, true);
});


test("independent terminal consent binds clients, browser flows, codes, refresh, status and revoke", async t => {
  let revocations = 0;
  const f = await fixture(t, undefined, "v2", () => { revocations++; }, true);
  const terminal = ownerTerminalAuthConfig(f.config);
  const metadata = await (await f.request("/.well-known/oauth-authorization-server/terminal")).json() as { issuer: string; scopes_supported: string[]; token_endpoint: string };
  assert.equal(metadata.issuer, terminal.issuer);
  assert.equal(metadata.token_endpoint, `${issuer}terminal/token`);
  assert.deepEqual(metadata.scopes_supported, [...O1_SCOPES]);
  assert.deepEqual(await (await f.request("/terminal/.well-known/oauth-authorization-server")).json(), metadata);
  const primaryMetadata = await (await f.request("/.well-known/oauth-authorization-server")).json() as { scopes_supported: string[] };
  assert.deepEqual(primaryMetadata.scopes_supported, [...V2_CODING_SCOPES]);
  const rootClient = await f.register();
  const terminalClient = await f.register("/terminal");
  const begin = (clientId: string) => f.request(`/terminal/authorize?${new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri,
    response_type: "code", scope: O1_SCOPES.join(" "), state: "terminal-state", code_challenge: challenge,
    code_challenge_method: "S256", resource: terminal.resource })}`);
  assert.equal((await begin(rootClient)).status, 400);
  assert.equal((await f.begin(terminalClient)).status, 400);
  const initial = await begin(terminalClient);
  assert.equal(initial.status, 303);
  assert.equal(initial.headers.get("location"), "/terminal/oauth/login");
  const cookie = f.cookieFrom(initial);
  assert.match(cookie, /^__Host-mac-terminal-session=/u);
  const page = await f.request("/terminal/oauth/login", undefined, cookie);
  const html = await page.text();
  assert.match(html, /action="\/terminal\/oauth\/login"/u);
  assert.match(html, /href="\/terminal\/oauth\/style.css"/u);
  const csrf = /name="csrf" value="([a-f0-9]{64})"/u.exec(html)![1]!;
  assert.equal((await f.request("/oauth/login", undefined, cookie.replace("mac-terminal-session", "mac-session"))).status, 400);
  const rootSession = await f.login(rootClient, V2_CODING_SCOPES.join(" "));
  const login = await f.request("/terminal/oauth/login", { username: "owner", password, csrf }, cookie);
  assert.equal(login.status, 303);
  const logged = f.cookieFrom(login);
  assert.equal((await f.request("/oauth/consent", undefined, rootSession.cookie)).status, 200);
  const consentHtml = await (await f.request("/terminal/oauth/consent", undefined, logged)).text();
  assert.match(consentHtml, /Run shell commands/u);
  assert.match(consentHtml, /existing CLI authentication state/u);
  assert.doesNotMatch(consentHtml, /No unrestricted shell/u);
  const consentCsrf = /name="csrf" value="([a-f0-9]{64})"/u.exec(consentHtml)![1]!;
  const consent = await f.request("/terminal/oauth/consent", { csrf: consentCsrf, decision: "allow" }, logged);
  assert.equal(consent.status, 303);
  const callback = new URL(consent.headers.get("location")!);
  assert.equal(callback.searchParams.get("iss"), terminal.issuer);
  const code = callback.searchParams.get("code")!;
  const exchangeBody = { grant_type: "authorization_code", client_id: terminalClient, code,
    code_verifier: verifier, redirect_uri: redirectUri };
  assert.equal((await f.request("/token", exchangeBody)).status, 400);
  assert.ok(f.store().get("code", fingerprint(code)));
  const exchanged = await f.request("/terminal/token", exchangeBody);
  assert.equal(exchanged.status, 200);
  const tokens = await exchanged.json() as { access_token: string; refresh_token: string };
  const claims = decodeJwt(tokens.access_token);
  assert.equal(claims.iss, terminal.issuer);
  assert.equal(claims.aud, terminal.resource);
  assert.equal((claims.scope as string).includes("mac.terminal.exec"), true);
  assert.equal(await f.provider().getAccessToken(tokens.access_token), false);
  const status = async (prefix: string) => (await f.request(`${prefix}/oauth/status`, { sessionId: String(claims.sid), subject: f.config.principalId },
    undefined, { authorization: `Bearer ${f.statusKey.toString("hex")}` })).json() as Promise<{ active: boolean; scopes: string[] }>;
  assert.deepEqual(await status(""), { active: false, scopes: [] });
  assert.equal((await status("/terminal")).active, true);
  const refreshBody = { grant_type: "refresh_token", client_id: terminalClient, refresh_token: tokens.refresh_token };
  assert.equal((await f.request("/token", refreshBody)).status, 400);
  await f.request("/revoke", { client_id: terminalClient, token: tokens.refresh_token });
  assert.equal((await status("/terminal")).active, true);
  const refreshed = await f.request("/terminal/token", refreshBody);
  assert.equal(refreshed.status, 200);
  const next = await refreshed.json() as { access_token: string; refresh_token: string };
  // A consumed token at the other endpoint cannot trigger replay revocation.
  assert.equal((await f.request("/token", refreshBody)).status, 400);
  assert.equal((await status("/terminal")).active, true);
  const primaryTokens = await f.issue(V2_CODING_SCOPES.join(" "));
  const crossRootRefresh = { grant_type: "refresh_token", client_id: primaryTokens.clientId, refresh_token: primaryTokens.refresh_token };
  assert.equal((await f.request("/terminal/token", crossRootRefresh)).status, 400);
  await f.request("/terminal/revoke", { client_id: primaryTokens.clientId, token: primaryTokens.refresh_token });
  assert.ok(await f.provider().getAccessToken(primaryTokens.access_token));
  await f.restart();
  assert.equal((await status("/terminal")).active, true);
  assert.equal((await f.request("/terminal/token", { ...refreshBody, refresh_token: next.refresh_token })).status, 200);
  await f.request("/terminal/revoke", { client_id: terminalClient, token: next.access_token });
  assert.equal((await status("/terminal")).active, false);
  assert.equal(revocations, 1);
  assert.ok(await f.provider().getAccessToken(primaryTokens.access_token));
});

test("legacy root O1 refresh grants retain their approved scopes with independent terminal enabled", async t => {
  const f = await fixture(t, undefined, "v2", undefined, true);
  const clientId = await f.register();
  const grantId = randomBytes(32).toString("hex");
  const refresh = randomBytes(32).toString("hex");
  const expiresAt = Date.now() + 60_000;
  f.store().put("grant", grantId, { clientId, principalId: f.config.principalId, scopes: [...O1_SCOPES], expiresAt, revoked: false });
  f.store().put("refresh", fingerprint(refresh), { clientId, grantId, expiresAt, consumed: false });
  const body = { grant_type: "refresh_token", client_id: clientId, refresh_token: refresh };
  assert.equal((await f.request("/terminal/token", body)).status, 400);
  assert.equal(f.store().get("grant", grantId)?.revoked, false);
  const response = await f.request("/token", body);
  assert.equal(response.status, 200);
  const tokens = await response.json() as { access_token: string };
  assert.deepEqual((decodeJwt(tokens.access_token).scope as string).split(" "), [...O1_SCOPES]);
  assert.ok(await f.provider().getAccessToken(tokens.access_token));
  assert.equal((await f.begin(clientId, { scope: O1_SCOPES.join(" ") })).status, 400);
});
