import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { chmod, copyFile, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { PolicyBundleVerifier } from "@mac-operator/broker";
import { runAuthCli } from "./cli.js";
import { READ_SCOPES, W1_SCOPES } from "./contracts.js";
import { assertW1Policy } from "./w1-policy.js";

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
    assert.deepEqual(edge.requiredScopes, [...READ_SCOPES]);
    const approval = JSON.parse(await readFile(join(personal, "approval-issuer.json"), "utf8")) as { enabled: boolean };
    assert.equal(approval.enabled, true);
    const keyConfig = JSON.parse(await readFile(join(personal, "approval-keys.json"), "utf8")) as {
      keys: { allowUnattended: boolean }[]
    };
    assert.deepEqual(keyConfig.keys.map(key => key.allowUnattended), [false]);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(project, { recursive: true, force: true });
  }
});
