import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

function manifest() {
  const root = "/Library/Application Support/MacOperator/PrivilegedHelper";
  const signedArtifactPath = `${root}/MacOperatorPrivilegedHelper.app`;
  const program = `${signedArtifactPath}/Contents/MacOS/mac-operator-privileged-helper`;
  return {
    schemaVersion: "0.1",
    operation: "install",
    helperRoot: root,
    plistPath: "/Library/LaunchDaemons/com.mac-operator.privileged-helper.plist",
    service: {
      label: "com.mac-operator.privileged-helper",
      program,
      programArguments: [program],
      workingDirectory: root,
      stdoutPath: `${root}/logs/helper.out.log`,
      stderrPath: `${root}/logs/helper.err.log`
    },
    signedArtifactPath,
    signature: {
      identifier: "com.mac-operator.privileged-helper",
      teamIdentifier: "ABCDE12345",
      cdHash: "0123456789abcdef0123"
    },
    helperKeyConfigPath: `${root}/config/helper-keys.json`,
    helperSocketPath: `${root}/run/helper.sock`,
    brokerSocketPath: "/Users/operator/Library/Application Support/MacOperator/run/broker.sock",
    helperAuthoritySocketPath: "/Users/operator/Library/Application Support/MacOperator/run/helper-authority.sock",
    brokerPeer: { uid: 501, gid: 20 },
    sourceRevision: "0123456789abcdef0123456789abcdef01234567",
    contractVersion: "0.1",
    policyVersion: "policy-0.1"
  };
}

test("privileged helper plan CLI emits a read-only root-domain plan", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-privileged-helper-plan-"));
  const path = join(directory, "manifest.json");
  try {
    await writeFile(path, `${JSON.stringify(manifest())}\n`, { mode: 0o600 });
    const output = execFileSync(process.execPath, ["scripts/plan-privileged-helper.mjs", "--manifest", path], {
      cwd: new URL("..", import.meta.url),
      env: { PATH: process.env.PATH ?? "" },
      shell: false,
      maxBuffer: 1024 * 1024,
      timeout: 30_000,
      encoding: "utf8"
    });
    const result = JSON.parse(output);
    assert.equal(result.mechanism, "macos-privileged-helper-plan-v1");
    assert.equal(result.plan.serviceId, "system/com.mac-operator.privileged-helper");
    assert.equal(result.plan.capabilityRelease, null);
    assert.equal(result.apply.available, false);
    assert.equal(result.plan.launchd.runsAsRoot, true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("privileged helper plan CLI rejects unsupported manifest fields", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-privileged-helper-invalid-"));
  const path = join(directory, "manifest.json");
  try {
    await writeFile(path, `${JSON.stringify({ ...manifest(), unsafe: true })}\n`, { mode: 0o600 });
    assertCommandFails(["scripts/plan-privileged-helper.mjs", "--manifest", path]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("privileged helper apply CLI refuses non-root callers before host mutation", async () => {
  if ((process.getuid?.() ?? -1) === 0) return;
  const directory = await mkdtemp(join(tmpdir(), "mops-privileged-helper-apply-"));
  const path = join(directory, "manifest.json");
  try {
    await writeFile(path, `${JSON.stringify(manifest())}\n`, { mode: 0o600 });
    assertCommandFails(["scripts/apply-privileged-helper.mjs", "--manifest", path, "--confirm", "install"]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

function assertCommandFails(args) {
  assert.throws(() => execFileSync(process.execPath, args, {
    cwd: new URL("..", import.meta.url),
    env: { PATH: process.env.PATH ?? "" },
    shell: false,
    maxBuffer: 1024 * 1024,
    timeout: 30_000,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  }), (error) => error?.status === 1);
}
