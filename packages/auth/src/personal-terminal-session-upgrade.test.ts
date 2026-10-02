import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createPrivateKey, randomBytes, sign } from "node:crypto";
import { chmod, copyFile, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { Broker, BrokerStore, EdgeKeyring, OwnerTerminalSessionManager, PersonalOwnerTerminalExecutor, PolicyBundleVerifier, PolicyManager,
  type SignedPolicyBundle } from "@mac-operator/broker";
import { runAuthCli } from "./cli.js";
import { O1_TOOLS } from "./contracts.js";
import { assertO1Policy } from "./w1-policy.js";
import { upgradePersonalTerminalSessions } from "./personal-terminal-session-upgrade.js";

const execFileAsync = promisify(execFile);
const SESSION_TOOL = "mac_terminal_session";
const supported = process.platform === "darwin" && process.getuid?.() !== 0;

async function provisionO1(): Promise<{ root: string; project: string; personal: string; auth: { principalId: string; issuerId: string } }> {
  const root = await realpath(await mkdtemp("/tmp/mac-session-upgrade-"));
  const project = await realpath(await mkdtemp(join(homedir(), ".mac-session-upgrade-project-")));
  const authDirectory = join(root, "auth");
  const tls = join(root, "tls");
  await mkdir(join(project, ".git"), { mode: 0o700 });
  await mkdir(tls, { mode: 0o700 });
  const credentials = join(root, "credentials.env");
  await writeFile(credentials, "MAC_OPERATOR_USERNAME=owner\nMAC_OPERATOR_PASSWORD=test-only-long-owner-passphrase\n", { mode: 0o600 });
  const previous = process.env.MAC_OPERATOR_PROJECT_ROOT;
  process.env.MAC_OPERATOR_PROJECT_ROOT = project;
  try {
    await runAuthCli(["init", "--dir", authDirectory, "--env-file", credentials, "--redirect-uri", "https://client.example.test/callback",
      "--issuer", "https://mac.example.test/", "--grant-profile", "o1"]);
  } finally { if (previous === undefined) delete process.env.MAC_OPERATOR_PROJECT_ROOT; else process.env.MAC_OPERATOR_PROJECT_ROOT = previous; }
  await execFileAsync("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", join(tls, "edge.key"), "-out", join(tls, "edge.crt"),
    "-days", "1", "-subj", "/CN=mac.example.test", "-addext", "subjectAltName=DNS:mac.example.test", "-addext", "basicConstraints=critical,CA:TRUE"],
    { cwd: "/", timeout: 10_000, maxBuffer: 64 * 1024 });
  await chmod(join(tls, "edge.key"), 0o600); await chmod(join(tls, "edge.crt"), 0o600);
  await copyFile(join(tls, "edge.crt"), join(tls, "origin-ca.crt")); await chmod(join(tls, "origin-ca.crt"), 0o600);
  await execFileAsync(process.execPath, [join(process.cwd(), "packages/auth/dist/personal-service.js"), "init", root, "abcdef0"],
    { cwd: process.cwd(), env: { ...process.env, MAC_OPERATOR_PROJECT_ROOT: project }, timeout: 20_000, maxBuffer: 64 * 1024 });
  const auth = JSON.parse(await readFile(join(authDirectory, "auth-config.json"), "utf8")) as { principalId: string; issuerId: string };
  return { root, project, personal: join(root, "personal"), auth };
}

/** Rewrites provisioned state into what a pre-session release signed: the same policy without the tool. */
async function downgradeToPreSession(root: string, personal: string): Promise<void> {
  const verifier = await PolicyBundleVerifier.createFromKeyFile({ schemaDirectory: join(process.cwd(), "schemas"),
    expectedKeyId: "personal-policy-1", publicKeyPath: join(personal, "policy-public.pem") });
  const prior = await verifier.verifyFile(join(personal, "policy.json"));
  const original = JSON.parse(await readFile(join(personal, "policy.json"), "utf8")) as SignedPolicyBundle;
  const payload = { ...original.payload, revision: original.payload.revision + 1, issued_at_ms: Date.now(),
    tool_enablement: original.payload.tool_enablement.filter(entry => entry.tool !== SESSION_TOOL) };
  const bytes = Buffer.from(canonicalJson(payload));
  const bundle = { ...original, payload, payload_digest: sha256(bytes),
    signature: sign(null, bytes, createPrivateKey(await readFile(join(root, "personal-policy-private.key")))).toString("base64") };
  const verified = verifier.verify(bundle);
  const store = new BrokerStore(join(personal, "broker.sqlite"), { runtimeFence: true,
    auditAnchor: { path: join(personal, "audit.anchor"), keySource: { keyId: "personal-audit-1", loadKey: () => readFileSync(join(personal, "audit.key")) } } });
  try { const manager = new PolicyManager(prior.policy, store); manager.restore(prior); manager.activate(verified); } finally { store.close(); }
  await writeFile(join(personal, "policy.json"), `${JSON.stringify(bundle, null, 2)}\n`);
  const edge = JSON.parse(await readFile(join(personal, "edge-service.json"), "utf8")) as Record<string, unknown>;
  await writeFile(join(personal, "edge-service.json"), `${JSON.stringify({ ...edge, policyVersion: verified.policy.version }, null, 2)}\n`);
}

const entrypoint = (): string => join(process.cwd(), "packages/auth/dist/personal-service.js");

test("terminal-sessions upgrade re-signs a pre-session O1 policy with only the new tool", { skip: !supported }, async () => {
  const { root, project, personal, auth } = await provisionO1();
  try {
    await downgradeToPreSession(root, personal);
    const verifier = await PolicyBundleVerifier.createFromKeyFile({ schemaDirectory: join(process.cwd(), "schemas"),
      expectedKeyId: "personal-policy-1", publicKeyPath: join(personal, "policy-public.pem") });
    const before = await verifier.verifyFile(join(personal, "policy.json"));
    assert.throws(() => assertO1Policy(before.policy, auth.principalId, auth.issuerId), "legacy policy must not satisfy the new O1 tool set");
    const legacyBytes = await readFile(join(personal, "policy.json"), "utf8");
    const legacy = JSON.parse(legacyBytes) as SignedPolicyBundle;

    await assert.rejects(execFileAsync(process.execPath, [entrypoint(), "terminal-sessions", root, "abcdef1"], { timeout: 20_000 }));
    assert.equal(await readFile(join(personal, "policy.json"), "utf8"), legacyBytes, "refusal must not change state");
    // The CLI reports every failure as one closed message, but the legacy O1 state must not be touched.
    await assert.rejects(execFileAsync(process.execPath, [entrypoint(), "owner-terminal", root, "abcdef1", "--enable"], { timeout: 20_000 }));
    assert.equal(await readFile(join(personal, "policy.json"), "utf8"), legacyBytes);

    await upgradePersonalTerminalSessions(root, process.cwd(), "abcdef1");
    const after = await verifier.verifyFile(join(personal, "policy.json"));
    assert.doesNotThrow(() => assertO1Policy(after.policy, auth.principalId, auth.issuerId));
    assert.equal(after.policy.revision, before.policy.revision + 1);
    assert.equal(after.policy.tools.get(SESSION_TOOL)?.enabled, true);
    const upgraded = JSON.parse(await readFile(join(personal, "policy.json"), "utf8")) as SignedPolicyBundle;
    const { revision: _r, issued_at_ms: _i, tool_enablement: legacyTools, ...legacyRest } = legacy.payload;
    const { revision: _r2, issued_at_ms: _i2, tool_enablement: upgradedTools, ...upgradedRest } = upgraded.payload;
    assert.deepEqual(upgradedRest, legacyRest, "only revision, issue time and tool enablement may change");
    assert.deepEqual(upgradedTools.filter(entry => !legacyTools.some(old => old.tool === entry.tool)), [{ tool: SESSION_TOOL, enabled: true }]);
    const edge = JSON.parse(await readFile(join(personal, "edge-service.json"), "utf8")) as { policyVersion: string; sourceRevision: string };
    assert.equal(edge.policyVersion, after.policy.version);
    assert.equal(edge.sourceRevision, "abcdef1");
    const input = JSON.parse(await readFile(join(root, "auth/broker-policy-input.json"), "utf8")) as { enabled_tools: string[] };
    assert.deepEqual([...input.enabled_tools].sort(), [...O1_TOOLS].sort());

    // The same capability check the service performs at startup must now hold.
    const store = new BrokerStore(join(personal, "broker.sqlite"), { runtimeFence: true,
      auditAnchor: { path: join(personal, "audit.anchor"), keySource: { keyId: "personal-audit-1", loadKey: () => readFileSync(join(personal, "audit.key")) } } });
    const key = randomBytes(32);
    const broker = new Broker({ store, policy: after.policy, ownerTerminalExecutor: new PersonalOwnerTerminalExecutor({ enabled: true }),
      ownerTerminalSessions: new OwnerTerminalSessionManager({ enabled: true }), authorizeOwnerTerminal: async () => false,
      edgeAuthenticationKeys: new EdgeKeyring([{ edgeId: "personal-edge", keyId: "personal-edge-1", key, notBeforeMs: Date.now() - 1000, expiresAtMs: Date.now() + 60_000 }]) });
    try { assert.deepEqual([...broker.enabledRuntimeCapabilityNames()].sort(), [...O1_TOOLS].sort()); }
    finally { await broker.close(); store.close(); key.fill(0); }

    await execFileAsync(process.execPath, [entrypoint(), "terminal-sessions", root, "abcdef2", "--enable"], { timeout: 30_000 });
    assert.equal((await verifier.verifyFile(join(personal, "policy.json"))).policy.revision, after.policy.revision, "re-running is a no-op");
  } finally { await rm(root, { recursive: true, force: true }); await rm(project, { recursive: true, force: true }); }
});

test("terminal-sessions upgrade refuses a policy that differs from the expected pre-session tool set", { skip: !supported }, async () => {
  const { root, project, personal } = await provisionO1();
  try {
    await downgradeToPreSession(root, personal);
    const original = JSON.parse(await readFile(join(personal, "policy.json"), "utf8")) as SignedPolicyBundle;
    const verifier = await PolicyBundleVerifier.createFromKeyFile({ schemaDirectory: join(process.cwd(), "schemas"),
      expectedKeyId: "personal-policy-1", publicKeyPath: join(personal, "policy-public.pem") });
    const prior = await verifier.verifyFile(join(personal, "policy.json"));
    const payload = { ...original.payload, revision: original.payload.revision + 1,
      tool_enablement: original.payload.tool_enablement.filter(entry => entry.tool !== "mac_git_commit") };
    const bytes = Buffer.from(canonicalJson(payload));
    const bundle = { ...original, payload, payload_digest: sha256(bytes),
      signature: sign(null, bytes, createPrivateKey(await readFile(join(root, "personal-policy-private.key")))).toString("base64") };
    const store = new BrokerStore(join(personal, "broker.sqlite"), { runtimeFence: true,
      auditAnchor: { path: join(personal, "audit.anchor"), keySource: { keyId: "personal-audit-1", loadKey: () => readFileSync(join(personal, "audit.key")) } } });
    try { const manager = new PolicyManager(prior.policy, store); manager.restore(prior); manager.activate(verifier.verify(bundle)); } finally { store.close(); }
    await writeFile(join(personal, "policy.json"), `${JSON.stringify(bundle, null, 2)}\n`);
    const before = await readFile(join(personal, "policy.json"), "utf8");
    await assert.rejects(execFileAsync(process.execPath, [entrypoint(), "terminal-sessions", root, "abcdef1", "--enable"], { timeout: 30_000 }), /./u);
    assert.equal(await readFile(join(personal, "policy.json"), "utf8"), before);
  } finally { await rm(root, { recursive: true, force: true }); await rm(project, { recursive: true, force: true }); }
});
