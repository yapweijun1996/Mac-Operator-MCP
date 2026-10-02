import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { chmod, link, mkdir, mkdtemp, readFile, realpath, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { request as httpRequest, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { jwtVerify } from "jose";
import { sha256 } from "@mac-operator/contracts";
import { CODEX_CONTROLLER_EXECUTABLE_SHA256, CODEX_CONTROLLER_VERSION } from "@mac-operator/broker";
import { createAuthApp } from "./app.js";
import { configSchema, O1_SCOPES, V2_CODING_SCOPES } from "./contracts.js";
import { createPersonalDevelopmentRuntime, developmentPolicyConfiguration, loadPersonalDevelopmentRuntimeConfig,
  REQUIRED_CONTAINER_EVIDENCE, type PersonalDevelopmentRuntimeConfig } from "./personal-development-runtime.js";
import { fingerprint } from "./provider.js";
import { AuthStore } from "./store.js";

async function runtimeFixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mac-development-runtime-")));
  const project = join(root, "project"), state = join(root, "state"), trees = join(root, "trees");
  for (const path of [project, state, trees]) await mkdir(path, { mode: 0o700 });
  const evidencePath = join(root, "evidence.json"), configPath = join(root, "development-runtime.json");
  const evidence: Record<string, unknown> = {
    schemaVersion: "0.1", imageId: `sha256:${"a".repeat(64)}`, engineId: "fixture-engine",
    codexExecutableSha256: CODEX_CONTROLLER_EXECUTABLE_SHA256, codexVersion: CODEX_CONTROLLER_VERSION,
    checks: REQUIRED_CONTAINER_EVIDENCE.map(name => ({ name, status: "pass" }))
  };
  const config: PersonalDevelopmentRuntimeConfig = {
    schemaVersion: "0.1", ownerProjectRoot: project, developmentProjects: [project], stateRoot: state, worktreeRoot: trees,
    taskProfiles: ["fixture.test"], socketPath: join(root, "engine.sock"), engineId: evidence.engineId as string,
    imageId: evidence.imageId as string, codexExecutable: join(root, "codex"),
    codexExecutableSha256: CODEX_CONTROLLER_EXECUTABLE_SHA256, codexVersion: CODEX_CONTROLLER_VERSION,
    evidencePath, evidenceSha256: "0".repeat(64), snapshotExcludedPaths: [], entries: [{ profile: "fixture.test", projectRoot: project,
      manifestPath: "package.json", manifestSha256: "b".repeat(64), scriptName: "test", scriptValue: "node --test",
      command: ["/usr/local/bin/node", "--test"], timeoutMs: 2000, outputCapBytes: 4096, type: "test" }]
  };
  async function saveConfig(value: unknown = config) { await writeFile(configPath, `${JSON.stringify(value)}\n`, { mode: 0o600 }); }
  async function saveEvidence() {
    const bytes = Buffer.from(`${JSON.stringify(evidence)}\n`);
    await writeFile(evidencePath, bytes, { mode: 0o600 });
    config.evidenceSha256 = sha256(bytes);
    await saveConfig();
  }
  await saveEvidence();
  return { root, project, state, trees, configPath, evidencePath, config, evidence, saveConfig, saveEvidence,
    load: () => loadPersonalDevelopmentRuntimeConfig(configPath), close: () => rm(root, { recursive: true, force: true }) };
}

test("development runtime accepts only bound private evidence and projects a separate four-field policy configuration", async () => {
  const f = await runtimeFixture();
  try {
    const loaded = f.load();
    assert.deepEqual(loaded, f.config);
    const projection = developmentPolicyConfiguration(loaded);
    assert.deepEqual(Object.keys(projection).sort(), ["developmentProjects", "stateRoot", "taskProfiles", "worktreeRoot"]);
    assert.deepEqual(projection, { developmentProjects: [f.project], stateRoot: f.state, worktreeRoot: f.trees, taskProfiles: ["fixture.test"] });
    assert.equal("codexExecutable" in projection, false);
    assert.equal("entries" in projection, false);
    assert.equal("evidencePath" in projection, false);
  } finally { await f.close(); }
});

test("development runtime rejects absent or modified evidence before any Engine connection", async () => {
  const f = await runtimeFixture();
  try {
    await writeFile(f.evidencePath, `${JSON.stringify({ ...f.evidence, marker: "modified" })}\n`);
    assert.throws(() => f.load(), /evidence content changed/u);
    await unlink(f.evidencePath);
    assert.throws(() => f.load());
  } finally { await f.close(); }
});

test("development runtime defaults snapshot exclusions safely and keeps explicit exclusions outside policy authority", async () => {
  const f = await runtimeFixture();
  try {
    const { snapshotExcludedPaths: _excluded, ...legacy } = f.config;
    await f.saveConfig(legacy);
    assert.deepEqual(f.load().snapshotExcludedPaths, []);
    f.config.snapshotExcludedPaths = ["portal/data", "mcp-connector/data", "portal/uploads"];
    await f.saveConfig();
    const loaded = f.load();
    assert.deepEqual(loaded.snapshotExcludedPaths, f.config.snapshotExcludedPaths);
    assert.equal("snapshotExcludedPaths" in developmentPolicyConfiguration(loaded), false);
  } finally { await f.close(); }
});

test("development runtime snapshot exclusions reject traversal, secrets, duplicates and overbroad malformed input", async () => {
  const f = await runtimeFixture();
  try {
    for (const paths of [["/"], ["/etc"], ["../outside"], ["portal/../data"], ["portal//data"], [""], ["."], ["portal/data/"], [".git"], [".env"], [".ssh"], ["portal\\data"], ["portal/data", "portal/data"], Array.from({ length: 65 }, (_, index) => `excluded-${index}`), "portal/data", null]) {
      await f.saveConfig({ ...f.config, snapshotExcludedPaths: paths });
      assert.throws(() => f.load());
    }
  } finally { await f.close(); }
});

for (const field of ["schemaVersion", "imageId", "engineId", "codexExecutableSha256", "codexVersion"] as const) {
  test(`development runtime refuses authentic evidence for another ${field}`, async () => {
    const f = await runtimeFixture();
    try {
      f.evidence[field] = field === "imageId" ? `sha256:${"f".repeat(64)}` : field === "codexExecutableSha256" ? "f".repeat(64) : "different-runtime";
      await f.saveEvidence();
      assert.throws(() => f.load(), /evidence is incomplete or belongs to a different runtime/u);
    } finally { await f.close(); }
  });
}

for (const check of REQUIRED_CONTAINER_EVIDENCE) {
  test(`development runtime requires passing ${check} evidence`, async () => {
    const f = await runtimeFixture();
    try {
      f.evidence.checks = REQUIRED_CONTAINER_EVIDENCE.map(name => ({ name, status: name === check ? "fail" : "pass" }));
      await f.saveEvidence();
      assert.throws(() => f.load(), /evidence is incomplete/u);
      f.evidence.checks = REQUIRED_CONTAINER_EVIDENCE.filter(name => name !== check).map(name => ({ name, status: "pass" }));
      await f.saveEvidence();
      assert.throws(() => f.load(), /evidence is incomplete/u);
    } finally { await f.close(); }
  });
}

test("development runtime rejects an absent checks array and unrecognized check statuses", async () => {
  const f = await runtimeFixture();
  try {
    for (const checks of [undefined, {}, "pass", REQUIRED_CONTAINER_EVIDENCE.map(name => ({ name, status: true }))]) {
      f.evidence.checks = checks;
      await f.saveEvidence();
      assert.throws(() => f.load(), /evidence is incomplete/u);
    }
  } finally { await f.close(); }
});

test("development runtime rejects widened, duplicate or mismatched command registries", async () => {
  const f = await runtimeFixture();
  try {
    const entry = f.config.entries[0]!;
    for (const config of [
      { ...f.config, developmentProjects: [f.project, f.project] },
      { ...f.config, taskProfiles: ["fixture.test", "fixture.test"] },
      { ...f.config, taskProfiles: ["unapproved.task"] },
      { ...f.config, entries: [entry, entry] },
      { ...f.config, entries: [{ ...entry, projectRoot: join(f.root, "unapproved") }] },
      { ...f.config, entries: [{ ...entry, profile: "unapproved.task" }] }
    ]) {
      await f.saveConfig(config);
      assert.throws(() => f.load(), /registry differs from approved/u);
    }
  } finally { await f.close(); }
});

test("development runtime schema denies additional authority, traversal and unpinned controller versions", async () => {
  const f = await runtimeFixture();
  try {
    for (const config of [
      { ...f.config, allowedScopes: ["mac.git.push"] },
      { ...f.config, environment: { INJECTED: "true" } },
      { ...f.config, stateRoot: `${f.state}/../state` },
      { ...f.config, worktreeRoot: "relative/worktrees" },
      { ...f.config, codexVersion: "unverified" },
      { ...f.config, codexExecutableSha256: "f".repeat(64) },
      { ...f.config, entries: [{ ...f.config.entries[0], cwd: "/" }] }
    ]) {
      await f.saveConfig(config);
      assert.throws(() => f.load());
    }
  } finally { await f.close(); }
});

test("development runtime protected files reject symlinks, hard links, broad modes and oversized input", async () => {
  const f = await runtimeFixture();
  try {
    const configLink = join(f.root, "config-link");
    await symlink(f.configPath, configLink);
    assert.throws(() => loadPersonalDevelopmentRuntimeConfig(configLink), /Protected auth file/u);
    const evidenceLink = join(f.root, "evidence-link");
    await symlink(f.evidencePath, evidenceLink);
    await f.saveConfig({ ...f.config, evidencePath: evidenceLink });
    assert.throws(() => f.load(), /Protected auth file/u);
    await f.saveConfig();
    const hardLink = join(f.root, "evidence-hard-link");
    await link(f.evidencePath, hardLink);
    assert.throws(() => f.load(), /Protected auth file/u);
    await unlink(hardLink);
    for (const path of [f.configPath, f.evidencePath]) {
      await chmod(path, 0o644);
      assert.throws(() => f.load(), /Protected auth file/u);
      await chmod(path, 0o600);
    }
    await chmod(f.root, 0o755);
    assert.throws(() => f.load(), /Protected auth directory/u);
    await chmod(f.root, 0o700);
    await writeFile(f.configPath, " ".repeat(131073));
    assert.throws(() => f.load(), /Invalid protected file/u);
  } finally { await f.close(); }
});

test("development runtime refuses nonprivate or symlinked control storage before connecting to an Engine", async () => {
  const f = await runtimeFixture();
  try {
    await chmod(f.state, 0o755);
    await assert.rejects(createPersonalDevelopmentRuntime(f.config, "owner-1"), /private canonical directory/u);
    await chmod(f.state, 0o700);
    const linked = join(f.root, "linked-state");
    await symlink(f.state, linked);
    await assert.rejects(createPersonalDevelopmentRuntime({ ...f.config, stateRoot: linked }, "owner-1"), /private canonical directory/u);
    await chmod(f.trees, 0o755);
    await assert.rejects(createPersonalDevelopmentRuntime(f.config, "owner-1"), /private canonical directory/u);
    assert.equal(await readFile(f.configPath, "utf8"), `${JSON.stringify(f.config)}\n`);
  } finally { await f.close(); }
});

async function oauthFixture() {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mac-development-consent-")));
  const store = new AuthStore(directory, true);
  const config = configSchema.parse({ version: 1, issuer: "https://mac.development.test/", resource: "https://mac.development.test/mcp", issuerId: "mac-operator-auth", principalId: "owner-1", keyId: "key-1", port: 3444, allowedRedirectUris: ["https://client.example.test/callback"], grantProfile: "v2" });
  // No password login is performed; these are schema-valid fixture records only.
  store.put("account", "owner", { username: "owner", salt: "a".repeat(64), passwordHash: "b".repeat(64), principalId: "owner-1" });
  const key = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
  const statusKey = randomBytes(32);
  const assembly = await createAuthApp({ config, store, signingKey: key, statusKey });
  const server: Server = assembly.app.listen(0, "127.0.0.1");
  await new Promise<void>(ok => server.once("listening", ok));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const request = async (path: string, body?: Record<string, unknown>, json = false) => new Promise<Response>((ok, fail) => {
    const outgoing = httpRequest(`http://127.0.0.1:${address.port}${path}`, { method: body ? "POST" : "GET", agent: false,
      headers: { host: "mac.development.test", ...(body ? { "content-type": json ? "application/json" : "application/x-www-form-urlencoded" } : {}) } }, incoming => {
      const chunks: Buffer[] = [];
      incoming.on("data", chunk => chunks.push(Buffer.from(chunk)));
      incoming.on("end", () => {
        const headers = new Headers();
        for (const [name, value] of Object.entries(incoming.headers)) if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join("; ") : value);
        ok(new Response(Buffer.concat(chunks), { status: incoming.statusCode!, headers }));
      });
    });
    outgoing.on("error", fail);
    outgoing.setTimeout(5000, () => outgoing.destroy(new Error("Fixture request timeout")));
    outgoing.end(body === undefined ? undefined : json ? JSON.stringify(body) : new URLSearchParams(Object.entries(body).map(([name, value]) => {
      assert.equal(typeof value, "string");
      return [name, value as string];
    })).toString());
  });
  const register = async (scope?: string) => {
    const response = await request("/register", { client_name: "V2 consent fixture", redirect_uris: [config.allowedRedirectUris[0]!], token_endpoint_auth_method: "none", ...(scope === undefined ? {} : { scope }) }, true);
    return response;
  };
  const begin = (clientId: string, scope?: string) => request(`/authorize?${new URLSearchParams({ client_id: clientId, redirect_uri: config.allowedRedirectUris[0]!, response_type: "code", state: "fixture-state", code_challenge: "a".repeat(43), code_challenge_method: "S256", resource: config.resource, ...(scope === undefined ? {} : { scope }) })}`);
  return { store, config, key, provider: assembly.provider, request, register, begin,
    async close() { server.closeAllConnections(); await new Promise<void>((ok, fail) => server.close(error => error ? fail(error) : ok())); store.close(); statusKey.fill(0); await rm(directory, { recursive: true, force: true }); }
  };
}

test("fresh V2 OAuth discovery and default consent offer coding scopes without owner terminal", async () => {
  const f = await oauthFixture();
  try {
    const metadata = await (await f.request("/.well-known/oauth-authorization-server")).json() as { scopes_supported: string[] };
    assert.deepEqual(metadata.scopes_supported, [...V2_CODING_SCOPES]);
    assert.equal((metadata.scopes_supported as readonly string[]).includes("mac.terminal.exec"), false);
    const registered = await f.register();
    assert.equal(registered.status, 201);
    const clientId = (await registered.json() as { client_id: string }).client_id;
    const begun = await f.begin(clientId);
    assert.equal(begun.status, 303);
    const sessionValue = begun.headers.get("set-cookie")!.split(";")[0]!.split("=")[1]!;
    const session = f.store.get("session", fingerprint(sessionValue));
    assert.ok(session);
    const transaction = f.store.get("transaction", session.transactionId);
    assert.deepEqual(transaction?.scopes, [...V2_CODING_SCOPES]);
    assert.equal((transaction?.scopes as readonly string[]).includes("mac.terminal.exec"), false);
  } finally { await f.close(); }
});

test("fresh V2 OAuth rejects explicit terminal authority in registration and authorization", async () => {
  const f = await oauthFixture();
  try {
    const explicit = [...V2_CODING_SCOPES, "mac.terminal.exec"].join(" ");
    assert.equal((await f.register(explicit)).status, 400);
    const registered = await f.register();
    const clientId = (await registered.json() as { client_id: string }).client_id;
    assert.equal((await f.begin(clientId, explicit)).status, 400);
    const client = await f.provider.getClient(clientId);
    assert.ok(client);
    assert.equal(await f.provider.validateScope({}, client, [...V2_CODING_SCOPES, "mac.terminal.exec"]), false);
    assert.equal((await f.begin(clientId, V2_CODING_SCOPES.join(" "))).status, 303);
  } finally { await f.close(); }
});

test("V2 refresh preserves a preexisting explicit O1 grant without adding coding authority", async () => {
  const f = await oauthFixture();
  try {
    const registered = await f.register();
    const clientId = (await registered.json() as { client_id: string }).client_id;
    const grantId = "fixture-preexisting-o1", refresh = randomBytes(32).toString("hex");
    f.store.put("grant", grantId, { clientId, principalId: f.config.principalId, scopes: [...O1_SCOPES], expiresAt: Date.now() + 60000, revoked: false });
    f.store.put("refresh", fingerprint(refresh), { clientId, grantId, expiresAt: Date.now() + 60000, consumed: false });
    const rejected = await f.request("/token", { grant_type: "refresh_token", client_id: clientId, refresh_token: refresh, scope: [...O1_SCOPES, "mac.agent.run"].join(" "), resource: f.config.resource });
    assert.equal(rejected.status, 400);
    assert.equal(f.store.get("refresh", fingerprint(refresh))?.consumed, false);
    const response = await f.request("/token", { grant_type: "refresh_token", client_id: clientId, refresh_token: refresh, resource: f.config.resource });
    assert.equal(response.status, 200);
    const token = await response.json() as { access_token: string; refresh_token: string; scope: string };
    const verified = await jwtVerify(token.access_token, createPublicKey(f.key), { issuer: f.config.issuer, audience: f.config.resource, algorithms: ["ES256"] });
    assert.deepEqual((verified.payload.scope as string).split(" "), [...O1_SCOPES]);
    assert.equal((verified.payload.scope as string).includes("mac.agent.run"), false);
    assert.equal(f.store.get("refresh", fingerprint(refresh))?.consumed, true);
    assert.deepEqual(f.store.get("grant", grantId)?.scopes, [...O1_SCOPES]);
    assert.equal(f.store.get("refresh", fingerprint(token.refresh_token))?.grantId, grantId);
  } finally { await f.close(); }
});
