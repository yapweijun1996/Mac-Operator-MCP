import { V2_CODING_SCOPES } from "./contracts.js";
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
const PUSH_SCOPE = "mac.git.push";

async function provision(): Promise<{ root: string; project: string; personal: string; auth: { principalId: string; issuerId: string } }> {
  const root = await realpath(await mkdtemp("/tmp/mac-project-add-"));
  const project = await realpath(await mkdtemp(join(homedir(), ".mac-project-add-project-")));
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


/** Installs a complete current V2 policy with one development project, as the live installation has. */
async function installV2(root: string, personal: string, auth: { principalId: string; issuerId: string }) {
  const base = await realpath(await mkdtemp(join(homedir(), ".mac-project-add-v2-")));
  const dirs = { first: join(base, "first"), second: join(base, "second"), state: join(base, "control"), trees: join(base, "worktrees") };
  for (const directory of Object.values(dirs)) mkdirSync(directory, { mode: 0o700 });
  for (const project of [dirs.first, dirs.second]) mkdirSync(join(project, ".git"), { mode: 0o700 });
  const verifier = await PolicyBundleVerifier.createFromKeyFile({ schemaDirectory: join(process.cwd(), "schemas"),
    expectedKeyId: "personal-policy-1", publicKeyPath: join(personal, "policy-public.pem") });
  const prior = await verifier.verifyFile(join(personal, "policy.json"));
  const ownerProjectRoot = prior.policy.filesystemRoots.find(value => value.rootId === "owner-project")!.path;
  const manifest = Buffer.from(JSON.stringify({ scripts: { test: "true" } }));
  await writeFile(join(dirs.first, "package.json"), manifest);
  const imageId = `sha256:${"a".repeat(64)}`, engineId = "synthetic-engine-1", evidencePath = join(base, "acceptance.json");
  const evidence = Buffer.from(JSON.stringify({ schemaVersion: "0.1", imageId, engineId, codexExecutableSha256: CODEX_CONTROLLER_EXECUTABLE_SHA256,
    codexVersion: CODEX_CONTROLLER_VERSION, checks: REQUIRED_CONTAINER_EVIDENCE.map(name => ({ name, status: "pass" })) }));
  await writeFile(evidencePath, evidence, { mode: 0o600 });
  const runtimeConfig = { schemaVersion: "0.1", ownerProjectRoot, developmentProjects: [dirs.first], stateRoot: dirs.state, worktreeRoot: dirs.trees,
    taskProfiles: ["synthetic.test"], socketPath: join(base, "engine.sock"), engineId, imageId,
    codexExecutable: join(base, "codex"), codexExecutableSha256: CODEX_CONTROLLER_EXECUTABLE_SHA256, codexVersion: CODEX_CONTROLLER_VERSION,
    evidencePath, evidenceSha256: sha256(evidence), snapshotExcludedPaths: [],
    entries: [{ profile: "synthetic.test", projectRoot: dirs.first, manifestPath: "package.json", manifestSha256: sha256(manifest),
      scriptName: "test", scriptValue: "true", command: ["/usr/bin/true"], timeoutMs: 60000, outputCapBytes: 4096, type: "test" }] };
  await writeFile(join(personal, "development-runtime.json"), `${JSON.stringify(runtimeConfig, null, 2)}\n`, { mode: 0o600 });
  const configuration = developmentPolicyConfiguration(loadPersonalDevelopmentRuntimeConfig(join(personal, "development-runtime.json")));
  const original = JSON.parse(await readFile(join(personal, "policy.json"), "utf8")) as SignedPolicyBundle;
  const payload = { ...buildV2PolicyDocument(original.payload, auth.principalId, auth.issuerId, configuration), revision: original.payload.revision + 1, issued_at_ms: Date.now() };
  const bytes = Buffer.from(canonicalJson(payload));
  const bundle = { ...original, payload, payload_digest: sha256(bytes),
    signature: sign(null, bytes, createPrivateKey(await readFile(join(root, "personal-policy-private.key")))).toString("base64") };
  const verified = verifier.verify(bundle);
  const store = new BrokerStore(join(personal, "broker.sqlite"), { runtimeFence: true,
    auditAnchor: { path: join(personal, "audit.anchor"), keySource: { keyId: "personal-audit-1", loadKey: () => readFileSync(join(personal, "audit.key")) } } });
  try { const manager = new PolicyManager(prior.policy, store); manager.restore(prior); manager.activate(verified); } finally { store.close(); }
  await writeFile(join(personal, "policy.json"), `${JSON.stringify(bundle, null, 2)}\n`);
  const edge = JSON.parse(await readFile(join(personal, "edge-service.json"), "utf8")) as Record<string, unknown>;
  await writeFile(join(personal, "edge-service.json"), `${JSON.stringify({ ...edge, oauthScopes: [...V2_CODING_SCOPES], policyVersion: verified.policy.version }, null, 2)}\n`);
  const authPath = join(root, "auth/auth-config.json");
  await writeFile(authPath, `${JSON.stringify({ ...JSON.parse(await readFile(authPath, "utf8")), grantProfile: "v2" }, null, 2)}\n`);
  const settingsPath = join(root, "auth/edge-auth-settings.json");
  await writeFile(settingsPath, `${JSON.stringify({ ...JSON.parse(await readFile(settingsPath, "utf8")), grantProfile: "v2", oauthScopes: [...V2_CODING_SCOPES] }, null, 2)}\n`);
  return { base, dirs, runtimeConfig, configuration, verifier, ownerProjectRoot };
}

async function writeNext(base: string, value: unknown): Promise<string> {
  const path = join(base, "next-runtime.json");
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  return path;
}

test("development-project-add appends push-denied projects and keeps every existing rule", { skip: !supported }, async () => {
  const { root, project, personal, auth } = await provision();
  let base: string | undefined;
  try {
    const installed = await installV2(root, personal, auth);
    base = installed.base;
    const before = JSON.parse(await readFile(join(personal, "policy.json"), "utf8")) as SignedPolicyBundle;
    const next = { ...installed.runtimeConfig, developmentProjects: [installed.dirs.first, installed.dirs.second, installed.ownerProjectRoot],
      gitPushDeniedProjects: [installed.dirs.second, installed.ownerProjectRoot] };
    const nextPath = await writeNext(base, next);
    await assert.rejects(execFileAsync(process.execPath, [entrypoint(), "development-project-add", root, "abcdef1", nextPath], { timeout: 20_000 }));
    assert.equal(JSON.stringify(JSON.parse(await readFile(join(personal, "policy.json"), "utf8"))), JSON.stringify(before), "refusal must not change state");

    await execFileAsync(process.execPath, [entrypoint(), "development-project-add", root, "abcdef1", nextPath, "--enable"], { timeout: 30_000 });
    const after = await installed.verifier.verifyFile(join(personal, "policy.json"));
    const nextConfiguration = developmentPolicyConfiguration(loadPersonalDevelopmentRuntimeConfig(join(personal, "development-runtime.json")));
    assert.doesNotThrow(() => assertV2Policy(after.policy, auth.principalId, auth.issuerId, nextConfiguration));
    assert.equal(after.policy.revision, before.payload.revision + 1);
    const upgraded = JSON.parse(await readFile(join(personal, "policy.json"), "utf8")) as SignedPolicyBundle;
    const content = (rule: { rule_id: string }) => { const { rule_id: _id, ...rest } = rule; return canonicalJson(rest); };
    const afterKeys = upgraded.payload.target_rules.map(content);
    for (const rule of before.payload.target_rules) {
      const index = afterKeys.indexOf(content(rule));
      assert.notEqual(index, -1, `existing rule kept: ${rule.rule_id}`);
      afterKeys.splice(index, 1);
    }
    const added = upgraded.payload.target_rules.filter(rule => afterKeys.includes(content(rule)));
    assert.ok(added.length > 0);
    assert.ok(added.every(rule => rule.scope !== PUSH_SCOPE), "no push on added projects");
    assert.equal(upgraded.payload.target_rules.filter(rule => rule.scope === PUSH_SCOPE).length, before.payload.target_rules.filter(rule => rule.scope === PUSH_SCOPE).length, "push rules unchanged");
    assert.ok(upgraded.payload.target_rules.some(rule => rule.scope === PUSH_SCOPE && rule.target.reference === installed.dirs.first), "first project keeps push");
    assert.deepEqual(upgraded.payload.principal_grants, before.payload.principal_grants);
    assert.deepEqual(upgraded.payload.tool_enablement, before.payload.tool_enablement);
    assert.deepEqual(upgraded.payload.kill_switches, before.payload.kill_switches);
    const edge = JSON.parse(await readFile(join(personal, "edge-service.json"), "utf8")) as { policyVersion: string; oauthScopes: string[] };
    assert.equal(edge.policyVersion, after.policy.version);
    assert.deepEqual([...edge.oauthScopes].sort(), [...V2_CODING_SCOPES].sort());
    const backup = join(personal, `project-add-backup-${before.payload.revision}`);
    assert.equal(JSON.parse(await readFile(join(backup, "personal__policy.json"), "utf8")).payload.revision, before.payload.revision);

    await execFileAsync(process.execPath, [entrypoint(), "development-project-add", root, "abcdef2", nextPath, "--enable"], { timeout: 30_000 });
    assert.equal((await installed.verifier.verifyFile(join(personal, "policy.json"))).policy.revision, after.policy.revision, "re-running is a no-op");
  } finally {
    await rm(root, { recursive: true, force: true }); await rm(project, { recursive: true, force: true });
    if (base !== undefined) await rm(base, { recursive: true, force: true });
  }
});

test("development-project-add refuses configs that widen anything beyond push-denied appended projects", { skip: !supported }, async () => {
  const { root, project, personal, auth } = await provision();
  let base: string | undefined;
  try {
    const installed = await installV2(root, personal, auth);
    base = installed.base;
    const before = await readFile(join(personal, "policy.json"), "utf8");
    const appended = [installed.dirs.first, installed.dirs.second];
    const bad: Record<string, unknown>[] = [
      { ...installed.runtimeConfig, developmentProjects: appended, gitPushDeniedProjects: [] },
      { ...installed.runtimeConfig, developmentProjects: appended, gitPushDeniedProjects: appended },
      { ...installed.runtimeConfig, developmentProjects: [installed.dirs.second, installed.dirs.first], gitPushDeniedProjects: [installed.dirs.second] },
      { ...installed.runtimeConfig, developmentProjects: appended, gitPushDeniedProjects: [installed.dirs.second], engineId: "other-engine" },
      { ...installed.runtimeConfig, developmentProjects: appended, gitPushDeniedProjects: [installed.dirs.second], taskProfiles: ["synthetic.test", "extra"] },
    ];
    for (const candidate of bad) {
      const nextPath = await writeNext(base, candidate);
      await assert.rejects(execFileAsync(process.execPath, [entrypoint(), "development-project-add", root, "abcdef1", nextPath, "--enable"], { timeout: 30_000 }), /./u);
      assert.equal(await readFile(join(personal, "policy.json"), "utf8"), before);
    }
  } finally {
    await rm(root, { recursive: true, force: true }); await rm(project, { recursive: true, force: true });
    if (base !== undefined) await rm(base, { recursive: true, force: true });
  }
});
