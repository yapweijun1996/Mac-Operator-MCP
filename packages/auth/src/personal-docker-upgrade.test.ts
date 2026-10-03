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
import { configSchema, O1_SCOPES, ownerTools, scopesForGrantProfile } from "./contracts.js";
import { upgradePersonalDockerRead } from "./personal-docker-upgrade.js";
import { upgradePersonalComputerUse } from "./personal-computer-use-upgrade.js";
import { assertO1Policy } from "./w1-policy.js";
const exec = promisify(execFile);
const supported = process.platform === "darwin" && process.getuid?.() !== 0;

test("Docker reads require explicit opt-in without changing default consent", () => {
  assert.deepEqual(scopesForGrantProfile("o1"), O1_SCOPES);
  assert.equal(scopesForGrantProfile("o1").includes("mac.docker.read"), false);
  assert.equal(scopesForGrantProfile("o1", true).includes("mac.docker.read"), true);
  assert.equal(ownerTools().includes("mac_docker_status"), false);
  assert.equal(ownerTools(true).filter(tool => tool.startsWith("mac_docker_")).length, 3);
});

test("Docker migration preserves GUI authority and OAuth scopes and rejects non-O1 opt-in", { skip: !supported }, async () => {
  const root = await realpath(await mkdtemp("/tmp/mac-docker-read-"));
  const project = await realpath(await mkdtemp(join(homedir(), ".mac-docker-read-project-")));
  try {
    await exec("/usr/bin/git", ["init", "--quiet", project], { timeout: 10000 });
    await mkdir(join(root, "tls"), { mode: 0o700 });
    const credentials = join(root, "credentials.env");
    await writeFile(credentials, "MAC_OPERATOR_USERNAME=owner\nMAC_OPERATOR_PASSWORD=test-only-long-owner-passphrase\n", { mode: 0o600 });
    const previousProjectRoot = process.env.MAC_OPERATOR_PROJECT_ROOT;
    process.env.MAC_OPERATOR_PROJECT_ROOT = project;
    try {
      await runAuthCli(["init", "--dir", join(root, "auth"), "--env-file", credentials,
        "--redirect-uri", "https://client.example.test/callback", "--issuer", "https://mac.example.test/", "--grant-profile", "o1"]);
    } finally {
      if (previousProjectRoot === undefined) delete process.env.MAC_OPERATOR_PROJECT_ROOT;
      else process.env.MAC_OPERATOR_PROJECT_ROOT = previousProjectRoot;
    }
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

    const store = new AuthStore(join(root, "auth"));
    const grantId = "existing-owner-grant";
    try { store.put("grant", grantId, { clientId: "existing-client", principalId: config.principalId, scopes: [...O1_SCOPES], expiresAt: Date.now() + 600000, revoked: false }); }
    finally { store.close(); }
    await assert.rejects(exec(process.execPath, [cli, "docker-read", root, "abcdef1"], { timeout: 30000 }));
    assert.equal((await verifier.verifyFile(join(personal, "policy.json"))).policy.revision, before.policy.revision);
    await upgradePersonalComputerUse(root, process.cwd(), "abcdef1");
    const gui = await verifier.verifyFile(join(personal, "policy.json"));
    const result = await upgradePersonalDockerRead(root, process.cwd(), "abcdef2");
    const after = await verifier.verifyFile(join(personal, "policy.json"));
    assert.equal(result.changed, true); assert.equal(result.reconnectRequired, true);
    assert.equal(after.policy.revision, gui.policy.revision + 1);
    assertO1Policy(after.policy, config.principalId, config.issuerId, "desktop", true);
    assert.throws(() => assertO1Policy(after.policy, config.principalId, config.issuerId, "desktop"));
    assert.deepEqual(after.policy.targetRules.filter(rule => rule.scope !== "mac.docker.read"), gui.policy.targetRules);
    assert.deepEqual(after.policy.filesystemRoots, gui.policy.filesystemRoots);
    assert.deepEqual(after.policy.killSwitches, gui.policy.killSwitches);
    const migrated = new AuthStore(join(root, "auth"));
    try {
      assert.deepEqual(migrated.get("grant", grantId)?.scopes, [...O1_SCOPES]);
      assert.equal(migrated.desktopGrants()[0]?.policyVersion, after.policy.version);
    } finally { migrated.close(); }
    const rerun = await upgradePersonalDockerRead(root, process.cwd(), "abcdef2");
    assert.deepEqual(rerun, { ...result, changed: false });
    assert.equal((await verifier.verifyFile(join(personal, "policy.json"))).policy.revision, after.policy.revision);
    await upgradePersonalComputerUse(root, process.cwd(), "abcdef2");
    const nextConfig = JSON.parse(await readFile(configPath, "utf8"));
    assert.equal(configSchema.safeParse({ ...nextConfig, grantProfile: "r1" }).success, false);
    assert.equal(configSchema.safeParse({ ...nextConfig, issuer: "https://mac.example.test/terminal/", resource: "https://mac.example.test/terminal/mcp" }).success, false);
  } finally { await rm(root, { recursive: true, force: true }); await rm(project, { recursive: true, force: true }); }
});
