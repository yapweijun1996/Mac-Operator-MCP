import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { chmod, copyFile, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { readFileSync } from "node:fs";
import { AuthStore } from "./store.js";
import { BrokerStore, PolicyBundleVerifier } from "@mac-operator/broker";
import { runAuthCli } from "./cli.js";
import { G1_SCOPES, G1_TOOLS, W1_READ_SCOPES, W1_SCOPES } from "./contracts.js";
import { assertG1Policy, assertW1Policy } from "./w1-policy.js";

const execFileAsync = promisify(execFile);

test("personal W1 provisioning signs a project-bound policy and attended approval issuer", async () => {
  if (process.platform !== "darwin" || process.getuid?.() === 0) return;
  const root = await realpath(await mkdtemp("/tmp/mac-w1-service-"));
  const project = await realpath(await mkdtemp(join(homedir(), ".mac-w1-project-")));
  const authDirectory = join(root, "auth");
  const tlsDirectory = join(root, "tls");
  const credentialsPath = join(root, "credentials.env");
  try {
    await mkdir(join(project, ".git"), { mode: 0o700 });
    await mkdir(tlsDirectory, { mode: 0o700 });
    await writeFile(credentialsPath, "MAC_OPERATOR_USERNAME=owner\nMAC_OPERATOR_PASSWORD=test-only-long-owner-passphrase\n", { mode: 0o600 });
    await runAuthCli(["init", "--dir", authDirectory, "--env-file", credentialsPath,
      "--redirect-uri", "https://client.example.test/callback", "--issuer", "https://mac.example.test/",
      "--grant-profile", "w1"]);
    await execFileAsync("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes",
      "-keyout", join(tlsDirectory, "edge.key"), "-out", join(tlsDirectory, "edge.crt"), "-days", "1",
      "-subj", "/CN=mac.example.test", "-addext", "subjectAltName=DNS:mac.example.test",
      "-addext", "basicConstraints=critical,CA:TRUE"], { cwd: "/", timeout: 10_000, maxBuffer: 64 * 1024 });
    await chmod(join(tlsDirectory, "edge.key"), 0o600);
    await chmod(join(tlsDirectory, "edge.crt"), 0o600);
    await copyFile(join(tlsDirectory, "edge.crt"), join(tlsDirectory, "origin-ca.crt"));
    await chmod(join(tlsDirectory, "origin-ca.crt"), 0o600);
    const entrypoint = join(process.cwd(), "packages/auth/dist/personal-service.js");
    await execFileAsync(process.execPath, [entrypoint, "init", root, "abcdef0"], {
      cwd: process.cwd(), env: { ...process.env, MAC_OPERATOR_PROJECT_ROOT: project },
      timeout: 20_000, maxBuffer: 64 * 1024
    });
    await execFileAsync(process.execPath, [join(process.cwd(), "scripts/verify-personal-snapshot.mjs"), root], {
      cwd: process.cwd(), timeout: 10_000, maxBuffer: 64 * 1024
    });
    const personal = join(root, "personal");
    const verifier = await PolicyBundleVerifier.createFromKeyFile({
      schemaDirectory: join(process.cwd(), "schemas"), expectedKeyId: "personal-policy-1",
      publicKeyPath: join(personal, "policy-public.pem")
    });
    const policy = (await verifier.verifyFile(join(personal, "policy.json"))).policy;
    const auth = JSON.parse(await readFile(join(authDirectory, "auth-config.json"), "utf8")) as { principalId: string; issuerId: string };
    assert.doesNotThrow(() => assertW1Policy(policy, auth.principalId, auth.issuerId));
    assert.equal(policy.filesystemRoots.find(root => root.rootId === "owner-project")?.path, project);
    const edge = JSON.parse(await readFile(join(personal, "edge-service.json"), "utf8")) as { oauthScopes: string[]; requiredScopes: string[] };
    assert.deepEqual(edge.oauthScopes, [...W1_SCOPES]);
    assert.deepEqual(edge.requiredScopes, [...W1_READ_SCOPES]);
    const approval = JSON.parse(await readFile(join(personal, "approval-issuer.json"), "utf8")) as { enabled: boolean };
    assert.equal(approval.enabled, true);
    const keyConfig = JSON.parse(await readFile(join(personal, "approval-keys.json"), "utf8")) as {
      keys: { issuerId: string; allowUnattended: boolean }[]
    };
    assert.deepEqual(keyConfig.keys.map(key => key.allowUnattended), [false]);
    assert.notEqual(keyConfig.keys[0]?.issuerId, auth.principalId,
      "The browser approver must be distinct from the MCP requester");
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(project, { recursive: true, force: true });
  }
});

test("personal G1 provisioning enables browser GUI scopes without task execution", async () => {
  if (process.platform !== "darwin" || process.getuid?.() === 0) return;
  const root = await realpath(await mkdtemp("/tmp/mac-g1-service-"));
  const project = await realpath(await mkdtemp(join(homedir(), ".mac-g1-project-")));
  const authDirectory = join(root, "auth");
  const tlsDirectory = join(root, "tls");
  const credentialsPath = join(root, "credentials.env");
  try {
    await mkdir(join(project, ".git"), { mode: 0o700 });
    await mkdir(tlsDirectory, { mode: 0o700 });
    await writeFile(credentialsPath, "MAC_OPERATOR_USERNAME=owner\nMAC_OPERATOR_PASSWORD=test-only-long-owner-passphrase\n", { mode: 0o600 });
    await runAuthCli(["init", "--dir", authDirectory, "--env-file", credentialsPath,
      "--redirect-uri", "https://client.example.test/callback", "--issuer", "https://mac.example.test/",
      "--grant-profile", "g1"]);
    await execFileAsync("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes",
      "-keyout", join(tlsDirectory, "edge.key"), "-out", join(tlsDirectory, "edge.crt"), "-days", "1",
      "-subj", "/CN=mac.example.test", "-addext", "subjectAltName=DNS:mac.example.test",
      "-addext", "basicConstraints=critical,CA:TRUE"], { cwd: "/", timeout: 10_000, maxBuffer: 64 * 1024 });
    await chmod(join(tlsDirectory, "edge.key"), 0o600);
    await chmod(join(tlsDirectory, "edge.crt"), 0o600);
    await copyFile(join(tlsDirectory, "edge.crt"), join(tlsDirectory, "origin-ca.crt"));
    await chmod(join(tlsDirectory, "origin-ca.crt"), 0o600);
    await execFileAsync(process.execPath, [join(process.cwd(), "packages/auth/dist/personal-service.js"), "init", root, "abcdef0"], {
      cwd: process.cwd(), env: { ...process.env, MAC_OPERATOR_PROJECT_ROOT: project },
      timeout: 20_000, maxBuffer: 64 * 1024
    });
    const personal = join(root, "personal");
    const verifier = await PolicyBundleVerifier.createFromKeyFile({ schemaDirectory: join(process.cwd(), "schemas"),
      expectedKeyId: "personal-policy-1", publicKeyPath: join(personal, "policy-public.pem") });
    const policy = (await verifier.verifyFile(join(personal, "policy.json"))).policy;
    const auth = JSON.parse(await readFile(join(authDirectory, "auth-config.json"), "utf8")) as { principalId: string; issuerId: string };
    assert.doesNotThrow(() => assertG1Policy(policy, auth.principalId, auth.issuerId));
    assert.deepEqual([...policy.tools.values()].filter(tool => tool.enabled).map(tool => tool.tool).sort(), [...G1_TOOLS].sort());
    assert.equal(policy.tools.get("mac_task_run")?.enabled, false);
    assert.equal(policy.killSwitches.gui, false);
    const edge = JSON.parse(await readFile(join(personal, "edge-service.json"), "utf8")) as { oauthScopes: string[]; ipcTimeoutMs: number };
    assert.deepEqual(edge.oauthScopes, [...G1_SCOPES]);
    assert.equal(edge.ipcTimeoutMs, 30_000);
    const keyConfig = JSON.parse(await readFile(join(personal, "approval-keys.json"), "utf8")) as {
      keys: { issuerId: string; allowUnattended: boolean }[]
    };
    assert.notEqual(keyConfig.keys[0]?.issuerId, auth.principalId,
      "The browser approver must be distinct from the MCP requester");
    assert.deepEqual(keyConfig.keys.map(key => key.allowUnattended), [false]);
    const entrypoint = join(process.cwd(), "packages/auth/dist/personal-service.js");
    const store = new BrokerStore(join(personal, "broker.sqlite"), { runtimeFence: true,
      auditAnchor: { path: join(personal, "audit.anchor"), keySource: {
        keyId: "personal-audit-1", loadKey: () => readFileSync(join(personal, "audit.key"))
      } } });
    try {
      const now = Date.now();
      const requestId = "local-owner-browser-consent";
      const targetRef = "app_window:window:bundle:com.google.Chrome";
      store.admitRequest({ requestId, edgeId: "personal-edge", nonce: "browser-consent-nonce", nonceExpiresAtMs: now + 60000,
        principalId: auth.principalId, sessionId: "owner-session", tool: "mac_app_focus", policyVersion: policy.version,
        payloadDigest: "a".repeat(64), mutation: true, receivedAtMs: now });
      store.recordRequestDecision({ requestId, principalId: auth.principalId, tool: "mac_app_focus", eventType: "decision",
        decision: "allow", resultClass: "AUTHORIZED", targetRef, policyVersion: policy.version, evidence: {}, timestampMs: now });
      store.createApprovalPreview(requestId, { contractVersion: "0.1", targetKind: "app_window", targetRef,
        payloadDigest: "a".repeat(64), approvalClass: "trusted_gui", unattended: false }, now, now + 600000);
    } finally { store.close(); }
    await assert.rejects(execFileAsync(process.execPath, [entrypoint, "browser-access", root, "local-owner-browser-consent"], { timeout: 10000 }));
    await execFileAsync(process.execPath, [entrypoint, "browser-access", root, "local-owner-browser-consent", "--until-revoked"], { timeout: 10000 });
    const authStore = new AuthStore(authDirectory);
    try {
      assert.equal(authStore.browserGrants().length, 1);
      assert.equal(authStore.browserGrants()[0]?.principalId, auth.principalId);
      assert.equal(authStore.browserGrants()[0]?.revoked, false);
    } finally { authStore.close(); }
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(project, { recursive: true, force: true });
  }
});
