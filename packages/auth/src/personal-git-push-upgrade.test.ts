import { configSchema, V2_CODING_SCOPES, V2_TOOLS } from "./contracts.js";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createPrivateKey, sign } from "node:crypto";
import { chmod, copyFile, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { BrokerStore, CODEX_CONTROLLER_EXECUTABLE_SHA256, CODEX_CONTROLLER_VERSION, PolicyBundleVerifier, PolicyManager, type SignedPolicyBundle } from "@mac-operator/broker";
import { runAuthCli } from "./cli.js";
import { assertV2Policy, buildV2PolicyDocument } from "./v2-policy.js";
import { REQUIRED_CONTAINER_EVIDENCE, developmentPolicyConfiguration, loadPersonalDevelopmentRuntimeConfig } from "./personal-development-runtime.js";

const execFileAsync = promisify(execFile);
const supported = process.platform === "darwin" && process.getuid?.() !== 0;
const entrypoint = (): string => join(process.cwd(), "packages/auth/dist/personal-service.js");
const PUSH_TOOL = "mac_git_push";
const PUSH_SCOPE = "mac.git.push";

async function provision(): Promise<{ root: string; project: string; personal: string; auth: { principalId: string; issuerId: string } }> {
  const root = await realpath(await mkdtemp("/tmp/mac-push-upgrade-"));
  const project = await realpath(await mkdtemp(join(homedir(), ".mac-push-upgrade-project-")));
  const tls = join(root, "tls");
  await mkdir(join(project, ".git"), { mode: 0o700 });
  await mkdir(tls, { mode: 0o700 });
  const credentials = join(root, "credentials.env");
  await writeFile(credentials, "MAC_OPERATOR_USERNAME=owner\nMAC_OPERATOR_PASSWORD=test-only-long-owner-passphrase\n", { mode: 0o600 });
  const previous = process.env.MAC_OPERATOR_PROJECT_ROOT;
  process.env.MAC_OPERATOR_PROJECT_ROOT = project;
  try {
    await runAuthCli(["init", "--dir", join(root, "auth"), "--env-file", credentials, "--redirect-uri", "https://client.example.test/callback",
      "--issuer", "https://mac.example.test/", "--grant-profile", "o1"]);
  } finally { if (previous === undefined) delete process.env.MAC_OPERATOR_PROJECT_ROOT; else process.env.MAC_OPERATOR_PROJECT_ROOT = previous; }
  await execFileAsync("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", join(tls, "edge.key"), "-out", join(tls, "edge.crt"),
    "-days", "1", "-subj", "/CN=mac.example.test", "-addext", "subjectAltName=DNS:mac.example.test", "-addext", "basicConstraints=critical,CA:TRUE"],
    { cwd: "/", timeout: 10_000, maxBuffer: 64 * 1024 });
  await chmod(join(tls, "edge.key"), 0o600); await chmod(join(tls, "edge.crt"), 0o600);
  await copyFile(join(tls, "edge.crt"), join(tls, "origin-ca.crt")); await chmod(join(tls, "origin-ca.crt"), 0o600);
  await execFileAsync(process.execPath, [entrypoint(), "init", root, "abcdef0"],
    { cwd: process.cwd(), env: { ...process.env, MAC_OPERATOR_PROJECT_ROOT: project }, timeout: 20_000, maxBuffer: 64 * 1024 });
  const auth = JSON.parse(await readFile(join(root, "auth/auth-config.json"), "utf8")) as { principalId: string; issuerId: string };
  return { root, project, personal: join(root, "personal"), auth };
}

/** Builds a V2 state signed before push existed: the current V2 document minus the push tool, scope and project rules. */
async function convertToPrePushV2(root: string, personal: string, auth: { principalId: string; issuerId: string }, mutate?: (tools: { tool: string; enabled: boolean }[]) => { tool: string; enabled: boolean }[]) {
  const base = await realpath(await mkdtemp(join(homedir(), ".mac-push-upgrade-v2-")));
  const developmentProject = join(base, "development-project");
  const stateRoot = join(base, "control");
  const worktreeRoot = join(base, "worktrees");
  for (const directory of [developmentProject, stateRoot, worktreeRoot]) mkdirSync(directory, { mode: 0o700 });
  mkdirSync(join(developmentProject, ".git"), { mode: 0o700 });
  const verifier = await PolicyBundleVerifier.createFromKeyFile({ schemaDirectory: join(process.cwd(), "schemas"),
    expectedKeyId: "personal-policy-1", publicKeyPath: join(personal, "policy-public.pem") });
  const prior = await verifier.verifyFile(join(personal, "policy.json"));
  const ownerProjectRoot = prior.policy.filesystemRoots.find(value => value.rootId === "owner-project")!.path;
  const manifest = Buffer.from(JSON.stringify({ scripts: { test: "true" } }));
  await writeFile(join(developmentProject, "package.json"), manifest);
  const imageId = `sha256:${"a".repeat(64)}`;
  const engineId = "synthetic-engine-1";
  const evidencePath = join(base, "acceptance.json");
  const evidence = Buffer.from(JSON.stringify({ schemaVersion: "0.1", imageId, engineId, codexExecutableSha256: CODEX_CONTROLLER_EXECUTABLE_SHA256,
    codexVersion: CODEX_CONTROLLER_VERSION, checks: REQUIRED_CONTAINER_EVIDENCE.map(name => ({ name, status: "pass" })) }));
  await writeFile(evidencePath, evidence, { mode: 0o600 });
  const runtimeConfig = { schemaVersion: "0.1", ownerProjectRoot, developmentProjects: [developmentProject], stateRoot, worktreeRoot,
    taskProfiles: ["synthetic.test"], socketPath: join(base, "engine.sock"), engineId, imageId,
    codexExecutable: join(base, "codex"), codexExecutableSha256: CODEX_CONTROLLER_EXECUTABLE_SHA256, codexVersion: CODEX_CONTROLLER_VERSION,
    evidencePath, evidenceSha256: sha256(evidence), snapshotExcludedPaths: [],
    entries: [{ profile: "synthetic.test", projectRoot: developmentProject, manifestPath: "package.json", manifestSha256: sha256(manifest),
      scriptName: "test", scriptValue: "true", command: ["/usr/bin/true"], timeoutMs: 60000, outputCapBytes: 4096, type: "test" }] };
  await writeFile(join(personal, "development-runtime.json"), `${JSON.stringify(runtimeConfig, null, 2)}\n`, { mode: 0o600 });
  const configuration = developmentPolicyConfiguration(loadPersonalDevelopmentRuntimeConfig(join(personal, "development-runtime.json")));

  const original = JSON.parse(await readFile(join(personal, "policy.json"), "utf8")) as SignedPolicyBundle;
  const full = buildV2PolicyDocument(original.payload, auth.principalId, auth.issuerId, configuration);
  const baseTools = full.tool_enablement.filter(entry => entry.tool !== PUSH_TOOL);
  const payload = { ...full, revision: original.payload.revision + 1, issued_at_ms: Date.now(),
    tool_enablement: mutate ? mutate(baseTools) : baseTools,
    principal_grants: full.principal_grants.map(grant => ({ ...grant, scopes: grant.scopes.filter(scope => scope !== PUSH_SCOPE) })),
    target_rules: full.target_rules.filter(rule => rule.scope !== PUSH_SCOPE) };
  const bytes = Buffer.from(canonicalJson(payload));
  const bundle = { ...original, payload, payload_digest: sha256(bytes),
    signature: sign(null, bytes, createPrivateKey(await readFile(join(root, "personal-policy-private.key")))).toString("base64") };
  const verified = verifier.verify(bundle);
  const store = new BrokerStore(join(personal, "broker.sqlite"), { runtimeFence: true,
    auditAnchor: { path: join(personal, "audit.anchor"), keySource: { keyId: "personal-audit-1", loadKey: () => readFileSync(join(personal, "audit.key")) } } });
  try { const manager = new PolicyManager(prior.policy, store); manager.restore(prior); manager.activate(verified); } finally { store.close(); }
  await writeFile(join(personal, "policy.json"), `${JSON.stringify(bundle, null, 2)}\n`);
  const prePushScopes = V2_CODING_SCOPES.filter(scope => scope !== PUSH_SCOPE);
  const edge = JSON.parse(await readFile(join(personal, "edge-service.json"), "utf8")) as Record<string, unknown>;
  await writeFile(join(personal, "edge-service.json"), `${JSON.stringify({ ...edge, oauthScopes: [...prePushScopes], policyVersion: verified.policy.version }, null, 2)}\n`);
  const authPath = join(root, "auth/auth-config.json");
  await writeFile(authPath, `${JSON.stringify({ ...JSON.parse(await readFile(authPath, "utf8")), grantProfile: "v2" }, null, 2)}\n`);
  const settingsPath = join(root, "auth/edge-auth-settings.json");
  await writeFile(settingsPath, `${JSON.stringify({ ...JSON.parse(await readFile(settingsPath, "utf8")), grantProfile: "v2", oauthScopes: [...prePushScopes] }, null, 2)}\n`);
  return { base, configuration, verifier };
}

test("git-push upgrade adds only the push tool, scope and project rules to a pre-push V2 policy", { skip: !supported }, async () => {
  const { root, project, personal, auth } = await provision();
  let base: string | undefined;
  try {
    const converted = await convertToPrePushV2(root, personal, auth);
    base = converted.base;
    const before = await converted.verifier.verifyFile(join(personal, "policy.json"));
    assert.throws(() => assertV2Policy(before.policy, auth.principalId, auth.issuerId, converted.configuration));
    const legacyBytes = await readFile(join(personal, "policy.json"), "utf8");

    await assert.rejects(execFileAsync(process.execPath, [entrypoint(), "git-push", root, "abcdef1"], { timeout: 20_000 }));
    assert.equal(await readFile(join(personal, "policy.json"), "utf8"), legacyBytes, "refusal must not change state");

    await execFileAsync(process.execPath, [entrypoint(), "git-push", root, "abcdef1", "--enable"], { timeout: 30_000 });
    const after = await converted.verifier.verifyFile(join(personal, "policy.json"));
    assert.doesNotThrow(() => assertV2Policy(after.policy, auth.principalId, auth.issuerId, converted.configuration));
    assert.equal(after.policy.revision, before.policy.revision + 1);
    assert.deepEqual([...after.policy.tools.values()].filter(tool => tool.enabled).map(tool => tool.tool).sort(), [...V2_TOOLS].sort());
    const legacy = JSON.parse(legacyBytes) as SignedPolicyBundle;
    const upgraded = JSON.parse(await readFile(join(personal, "policy.json"), "utf8")) as SignedPolicyBundle;
    assert.deepEqual(upgraded.payload.filesystem_roots, legacy.payload.filesystem_roots);
    assert.deepEqual(upgraded.payload.kill_switches, legacy.payload.kill_switches);
    assert.equal(upgraded.payload.kill_switches.destructive, true);
    assert.deepEqual(upgraded.payload.target_rules.filter(rule => rule.scope !== PUSH_SCOPE), legacy.payload.target_rules);
    assert.deepEqual(upgraded.payload.target_rules.filter(rule => rule.scope === PUSH_SCOPE).map(rule => rule.target.reference), [converted.configuration.developmentProjects[0]]);
    const edge = JSON.parse(await readFile(join(personal, "edge-service.json"), "utf8")) as { policyVersion: string; sourceRevision: string; oauthScopes: string[] };
    assert.equal(edge.policyVersion, after.policy.version);
    assert.equal(edge.sourceRevision, "abcdef1");
    assert.deepEqual([...edge.oauthScopes].sort(), [...V2_CODING_SCOPES].sort());
    const settings = JSON.parse(await readFile(join(root, "auth/edge-auth-settings.json"), "utf8")) as { oauthScopes: string[] };
    assert.deepEqual([...settings.oauthScopes].sort(), [...V2_CODING_SCOPES].sort());
    const input = JSON.parse(await readFile(join(root, "auth/broker-policy-input.json"), "utf8")) as { enabled_tools: string[] };
    assert.ok(input.enabled_tools.includes(PUSH_TOOL));
    const config = configSchema.parse(JSON.parse(await readFile(join(root, "auth/auth-config.json"), "utf8")));
    assert.equal(config.grantProfile, "v2");

    await execFileAsync(process.execPath, [entrypoint(), "git-push", root, "abcdef2", "--enable"], { timeout: 30_000 });
    assert.equal((await converted.verifier.verifyFile(join(personal, "policy.json"))).policy.revision, after.policy.revision, "re-running is a no-op");
  } finally {
    await rm(root, { recursive: true, force: true }); await rm(project, { recursive: true, force: true });
    if (base !== undefined) await rm(base, { recursive: true, force: true });
  }
});

test("git-push upgrade refuses a policy whose tool set differs from the expected pre-push V2 set", { skip: !supported }, async () => {
  const { root, project, personal, auth } = await provision();
  let base: string | undefined;
  try {
    const converted = await convertToPrePushV2(root, personal, auth, tools => tools.filter(entry => entry.tool !== "mac_git_commit"));
    base = converted.base;
    const before = await readFile(join(personal, "policy.json"), "utf8");
    await assert.rejects(execFileAsync(process.execPath, [entrypoint(), "git-push", root, "abcdef1", "--enable"], { timeout: 30_000 }), /./u);
    assert.equal(await readFile(join(personal, "policy.json"), "utf8"), before);
  } finally {
    await rm(root, { recursive: true, force: true }); await rm(project, { recursive: true, force: true });
    if (base !== undefined) await rm(base, { recursive: true, force: true });
  }
});
