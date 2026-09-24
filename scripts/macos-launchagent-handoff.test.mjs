import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import test from "node:test";

const execFileAsync = promisify(execFile);
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function baseComponent(component, uid, installRoot, userHome) {
  const label = `com.mac-operator.${component}`;
  const brokerArtifact = `${installRoot}/MacOperatorBroker.app`;
  const artifactPath = component === "broker" ? brokerArtifact : `${installRoot}/node`;
  const program = component === "broker" ? `${brokerArtifact}/Contents/MacOS/broker` : `${installRoot}/node`;
  const entrypoint = component === "broker"
    ? `${brokerArtifact}/Contents/Resources/runtime/${component}.js`
    : `${installRoot}/${component}.js`;
  return {
    uid,
    userHome,
    installRoot,
    plistPath: `${userHome}/Library/LaunchAgents/${label}.plist`,
    service: {
      label,
      program,
      programArguments: [program, entrypoint],
      workingDirectory: installRoot,
      stdoutPath: `${installRoot}/logs/${component}.out.log`,
      stderrPath: `${installRoot}/logs/${component}.err.log`,
      runAtLoad: true,
      keepAlive: true,
      throttleIntervalSeconds: 5
    },
    metadata: {
      component: `mac-operator-${component}`,
      sourceRevision: "0123456789abcdef0123456789abcdef01234567",
      contractVersion: "0.1",
      policyVersion: "policy-1"
    },
    signature: { identifier: label },
    signaturePolicy: "development-ad-hoc",
    signedArtifactPath: artifactPath,
    enabledCapabilities: []
  };
}

function authorityComponent(uid, installRoot, userHome) {
  const component = baseComponent("authority", uid, installRoot, userHome);
  const configPath = `${installRoot}/broker-service.json`;
  const socketPath = `${installRoot}/run/authority-operator.sock`;
  component.service.programArguments = [component.service.program, `${installRoot}/authority-control-service.js`, "--config", configPath];
  component.metadata.component = "mac-operator-authority";
  component.authorityConfigPath = configPath;
  component.authorityOperatorSocketPath = socketPath;
  return component;
}

function addApplyStatusBinding(component, name) {
  component.statusSocketPath = `${component.installRoot}/run/${name}.sock`;
  component.statusKeyPath = `${component.installRoot}/run/${name}.key`;
  component.statusKeyDigest = "a".repeat(64);
  return component;
}

function manifest(includeAuthority = true) {
  const uid = process.getuid?.() ?? 501;
  const userHome = "/Users/operator";
  const installRoot = `${userHome}/MacOperator`;
  const value = {
    schemaVersion: "0.1",
    operation: "install",
    edge: baseComponent("edge", uid, installRoot, userHome),
    broker: baseComponent("broker", uid, installRoot, userHome)
  };
  value.edge.bindHost = "127.0.0.1";
  value.edge.bindPort = 9443;
  if (includeAuthority) value.authority = authorityComponent(uid, installRoot, userHome);
  return value;
}

async function writeManifest(directory, value, name = "manifest.json") {
  const path = join(directory, name);
  await writeFile(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
  return path;
}

function applyManifestPair() {
  const primary = manifest(true);
  addApplyStatusBinding(primary.edge, "edge-status");
  addApplyStatusBinding(primary.broker, "broker-status");
  const recovery = structuredClone(primary);
  recovery.operation = "uninstall";
  return { primary, recovery };
}

async function assertChildProcessRejects(argumentsValue, expectedMessage) {
  await assert.rejects(
    execFileAsync(process.execPath, argumentsValue, { cwd: repositoryRoot, maxBuffer: 2 * 1024 * 1024 }),
    (error) => {
      const output = `${error?.message ?? ""}\n${error?.stdout ?? ""}\n${error?.stderr ?? ""}`;
      assert.match(output, expectedMessage);
      return true;
    }
  );
}

test("three-component plan handoff emits the real startup dependency order", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-handoff-"));
  try {
    const path = await writeManifest(directory, manifest(true));
    const result = await execFileAsync(process.execPath, [
      "scripts/plan-macos-launchagents.mjs", "--manifest", path, "--development-probe"
    ], { cwd: repositoryRoot, maxBuffer: 2 * 1024 * 1024 });
    const output = JSON.parse(result.stdout);
    assert.deepEqual(output.order, ["authority", "edge", "broker"]);
    assert.deepEqual(output.components.map((component) => component.component), [
      "mac-operator-authority", "mac-operator-edge", "mac-operator-broker"
    ]);
    assert.equal(output.apply.available, false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("three-component plan handoff rejects a missing operator socket binding", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-handoff-invalid-"));
  try {
    const value = manifest(true);
    delete value.authority.authorityOperatorSocketPath;
    const path = await writeManifest(directory, value);
    await assert.rejects(
      execFileAsync(process.execPath, [
        "scripts/plan-macos-launchagents.mjs", "--manifest", path, "--development-probe"
      ], { cwd: repositoryRoot, maxBuffer: 2 * 1024 * 1024 }),
      /missing fields|authorityOperatorSocketPath|operator socket/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("three-component apply handoff rejects ad-hoc release plans before host mutation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-apply-reject-"));
  try {
    const { primary, recovery } = applyManifestPair();
    const primaryPath = await writeManifest(directory, primary, "primary.json");
    const recoveryPath = await writeManifest(directory, recovery, "recovery.json");
    const authorityDatabasePath = join(directory, "authority.sqlite");
    const authoritySocketPath = primary.authority.authorityOperatorSocketPath;
    await assertChildProcessRejects([
      "scripts/apply-macos-launchagents.mjs",
      "--manifest", primaryPath,
      "--recovery", recoveryPath,
      "--confirm", "install",
      "--apply",
      "--authority-database", authorityDatabasePath,
      "--authority-operator-socket", authoritySocketPath,
      "--authority-key-config", join(directory, "authority-keys.json"),
      "--edge-id", "edge-1"
    ], /development ad-hoc plans are probe-only/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("readback mode is distinct from apply and fails closed without protected status material", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-readback-"));
  try {
    const primary = manifest(false);
    addApplyStatusBinding(primary.edge, "edge-status");
    addApplyStatusBinding(primary.broker, "broker-status");
    const recovery = structuredClone(primary);
    recovery.operation = "uninstall";
    const primaryPath = await writeManifest(directory, primary, "primary.json");
    const recoveryPath = await writeManifest(directory, recovery, "recovery.json");
    await assertChildProcessRejects([
      "scripts/apply-macos-launchagents.mjs",
      "--manifest", primaryPath,
      "--recovery", recoveryPath,
      "--confirm", "install",
      "--readback"
    ], /failed|protected|status|key/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("apply handoff rejects duplicate Authority socket aliases before reading manifests", async () => {
  await assertChildProcessRejects([
    "scripts/apply-macos-launchagents.mjs",
    "--manifest", "/tmp/unused-primary.json",
    "--recovery", "/tmp/unused-recovery.json",
    "--confirm", "install",
    "--apply",
    "--authority-socket", "/tmp/authority.sock",
    "--authority-operator-socket", "/tmp/authority.sock"
  ], /provide only one Authority operator socket option/u);
});
