import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, copyFile, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { PolicyBundleVerifier } from "@mac-operator/broker";
import { runAuthCli } from "./cli.js";
import { AuthStore } from "./store.js";
import { upgradePersonalComputerUse } from "./personal-computer-use-upgrade.js";
import { assertO1Policy } from "./w1-policy.js";

const exec = promisify(execFile);
const supported = process.platform === "darwin" && process.getuid?.() !== 0;

test("explicit computer-use migration signs only GUI targets, stores distinct consent and is idempotent", { skip: !supported }, async () => {
  const root = await realpath(await mkdtemp("/tmp/mac-computer-use-"));
  const project = await realpath(await mkdtemp(join(homedir(), ".mac-computer-use-project-")));
  try {
    await mkdir(join(project, ".git"), { mode: 0o700 });
    await mkdir(join(root, "tls"), { mode: 0o700 });
    const credentials = join(root, "credentials.env");
    await writeFile(credentials, "MAC_OPERATOR_USERNAME=owner\nMAC_OPERATOR_PASSWORD=test-only-long-owner-passphrase\n", { mode: 0o600 });
    await runAuthCli(["init", "--dir", join(root, "auth"), "--env-file", credentials,
      "--redirect-uri", "https://client.example.test/callback", "--issuer", "https://mac.example.test/", "--grant-profile", "o1"]);
    const tls = join(root, "tls");
    await exec("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", join(tls, "edge.key"),
      "-out", join(tls, "edge.crt"), "-days", "1", "-subj", "/CN=mac.example.test", "-addext", "subjectAltName=DNS:mac.example.test",
      "-addext", "basicConstraints=critical,CA:TRUE"], { timeout: 15000, maxBuffer: 65536 });
    await chmod(join(tls, "edge.key"), 0o600); await chmod(join(tls, "edge.crt"), 0o600);
    await copyFile(join(tls, "edge.crt"), join(tls, "origin-ca.crt")); await chmod(join(tls, "origin-ca.crt"), 0o600);
    const cli = join(process.cwd(), "packages/auth/dist/personal-service.js");
    await exec(process.execPath, [cli, "init", root, "abcdef0"], {
      env: { ...process.env, MAC_OPERATOR_PROJECT_ROOT: project }, timeout: 30000, maxBuffer: 65536
    });
    const personal = join(root, "personal");
    const configPath = join(root, "auth/auth-config.json");
    const config = JSON.parse(await readFile(configPath, "utf8")) as { principalId: string; issuerId: string; guiAccess?: string };
    const verifier = await PolicyBundleVerifier.createFromKeyFile({ schemaDirectory: join(process.cwd(), "schemas"),
      expectedKeyId: "personal-policy-1", publicKeyPath: join(personal, "policy-public.pem") });
    const before = await verifier.verifyFile(join(personal, "policy.json"));
    const policyBefore = await readFile(join(personal, "policy.json"), "utf8");
    const authStore = new AuthStore(join(root, "auth"));
    const browserId = "gui-session:11111111-1111-1111-1111-111111111111";
    try { authStore.put("browser_grant", browserId, { id: browserId, principalId: config.principalId, sessionId: "old-session",
      appId: "bundle:com.google.Chrome", policyVersion: before.policy.version, consentRequestId: "old-browser-consent", createdAt: Date.now(), revoked: false }); }
    finally { authStore.close(); }
    await assert.rejects(exec(process.execPath, [cli, "computer-use", root, "abcdef1", "--enable"], { timeout: 30000 }));
    assert.equal(await readFile(join(personal, "policy.json"), "utf8"), policyBefore);
    await assert.rejects(upgradePersonalComputerUse(root, process.cwd(), "not-a-revision"), /revision/u);
    const result = await upgradePersonalComputerUse(root, process.cwd(), "abcdef1");
    const after = await verifier.verifyFile(join(personal, "policy.json"));
    assert.equal(after.policy.revision, before.policy.revision + 1);
    assert.equal(result.policyVersion, after.policy.version);
    assert.equal(result.changed, true);
    assertO1Policy(after.policy, config.principalId, config.issuerId, "desktop");
    assert.throws(() => assertO1Policy(after.policy, config.principalId, config.issuerId), /target rules/u);
    const guiScopes = new Set(["mac.app.control", "mac.ui.observe", "mac.ui.control"]);
    assert.deepEqual(after.policy.targetRules.filter(rule => !guiScopes.has(rule.scope)), before.policy.targetRules.filter(rule => !guiScopes.has(rule.scope)));
    assert.deepEqual([...after.policy.principalGrants], [...before.policy.principalGrants]);
    assert.deepEqual([...after.policy.tools], [...before.policy.tools]);
    assert.deepEqual(after.policy.filesystemRoots, before.policy.filesystemRoots);
    assert.deepEqual(after.policy.killSwitches, before.policy.killSwitches);
    assert.equal(JSON.parse(await readFile(configPath, "utf8")).guiAccess, "desktop");
    const upgradedStore = new AuthStore(join(root, "auth"));
    try {
      assert.equal(upgradedStore.desktopGrants().length, 1);
      assert.equal(upgradedStore.desktopGrants()[0]?.id, result.desktopGrantId);
      assert.equal(upgradedStore.get("browser_grant", browserId)?.policyVersion, before.policy.version, "old browser consent must not acquire desktop authority");
      assert.equal(upgradedStore.get("browser_grant", browserId)?.appId, "bundle:com.google.Chrome");
    } finally { upgradedStore.close(); }
    const rerun = await upgradePersonalComputerUse(root, process.cwd(), "abcdef1");
    assert.deepEqual(rerun, { ...result, changed: false });
    assert.equal((await verifier.verifyFile(join(personal, "policy.json"))).policy.revision, after.policy.revision);
    const revokedStore = new AuthStore(join(root, "auth"));
    try {
      const record = revokedStore.get("desktop_grant", result.desktopGrantId)!;
      revokedStore.put("desktop_grant", record.id, { ...record, revoked: true });
    } finally { revokedStore.close(); }
    const renewed = await upgradePersonalComputerUse(root, process.cwd(), "abcdef1");
    assert.notEqual(renewed.desktopGrantId, result.desktopGrantId, "explicit renewed consent creates a new record, never un-revokes old authority");
    assert.equal((await verifier.verifyFile(join(personal, "policy.json"))).policy.revision, after.policy.revision);
  } finally { await rm(root, { recursive: true, force: true }); await rm(project, { recursive: true, force: true }); }
});
