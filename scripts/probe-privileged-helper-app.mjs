import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CONTRACT_VERSION } from "@mac-operator/contracts";

assert.equal(process.platform, "darwin", "helper app packaging probe requires macOS");
assert.equal(process.arch, "arm64", "helper app packaging probe requires arm64");
assert.notEqual(process.geteuid?.(), 0, "helper app packaging probe must not run as root");
assert.equal(process.argv.length, 3, "usage: node scripts/probe-privileged-helper-app.mjs /absolute/path/node-v24.21.0-darwin-arm64.tar.gz");

const temporaryRoot = await realpath(await mkdtemp(join(tmpdir(), "mac-operator-helper-app-probe-")));
const nodeArchive = await realpath(process.argv[2]);
const descriptorPath = join(temporaryRoot, "runtime-descriptor.json");
const enabledDescriptorPath = join(temporaryRoot, "runtime-descriptor-enabled.json");
const outputPath = join(temporaryRoot, "MacOperatorPrivilegedHelper.app");
const deniedOutputPath = join(temporaryRoot, "MustNotBeBuilt.app");
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const baseDescriptor = {
  schemaVersion: "0.1",
  helperRoot: "/Library/Application Support/MacOperator/PrivilegedHelper",
  helperKeyConfigPath: "/Library/Application Support/MacOperator/PrivilegedHelper/config/helper-keys.json",
  helperSocketPath: "/Library/Application Support/MacOperator/PrivilegedHelper/run/helper.sock",
  brokerSocketPath: "/Users/501/Library/Application Support/MacOperator/run/broker.sock",
  helperAuthoritySocketPath: "/Users/501/Library/Application Support/MacOperator/run/helper-authority.sock",
  brokerPeer: { uid: 501, gid: 20 },
  sourceRevision: "a".repeat(40),
  contractVersion: CONTRACT_VERSION,
  policyVersion: "policy-packaging-probe",
  capabilities: {
    serviceControl: { enabled: false, systemPublishedExecutablePathAccepted: false },
    packageInstall: { enabled: false, systemPublishedExecutablePathAccepted: false, catalog: [] },
    power: { enabled: false, systemPublishedExecutablePathAccepted: false }
  }
};

try {
  await writeDescriptor(descriptorPath, baseDescriptor);
  await writeDescriptor(enabledDescriptorPath, {
    ...baseDescriptor,
    capabilities: {
      ...baseDescriptor.capabilities,
      serviceControl: { enabled: true, systemPublishedExecutablePathAccepted: true }
    }
  });

  const rejected = runBuilder(enabledDescriptorPath, deniedOutputPath, nodeArchive);
  assert.notEqual(rejected.status, 0, "ad-hoc packaging must reject enabled helper capabilities");
  assert.match(rejected.stderr, /ad-hoc helper bundles cannot enable privileged capabilities/u);
  await assert.rejects(stat(deniedOutputPath));

  const built = runBuilder(descriptorPath, outputPath, nodeArchive);
  assert.equal(built.status, 0, built.stderr);
  const result = parseBuildResult(built.stdout);
  assert.equal(result.status, "built-and-verified");
  assert.equal(result.runtimeVersion, "v24.21.0");
  assert.equal(result.signature.identifier, "com.mac-operator.privileged-helper");
  assert.deepEqual(result.enabledCapabilities, []);
  assert.equal(result.nativeAdapterVerified, true);
  assert.equal(result.notarized, false);
  assert.equal(result.installed, false);
  assert.equal(result.launchDaemonStarted, false);
  assert.equal(await readFile(join(outputPath, "Contents/Info.plist"), "utf8").then((text) => text.includes("com.mac-operator.privileged-helper")), true);
  process.stdout.write(`${JSON.stringify({ status: "passed", runtimeVersion: result.runtimeVersion, nativeAdapterRuntimeVerified: result.nativeAdapterVerified, signedArtifactVerified: true, runtimeImportVerified: true, adHocCapabilityGateVerified: true })}\n`);
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

async function writeDescriptor(path, value) {
  await writeFile(path, `${JSON.stringify(value)}\n`, { flag: "wx", mode: 0o600 });
}

function runBuilder(descriptorPath, outputPath, nodeArchive) {
  return spawnSync(process.execPath, [
    join(repositoryRoot, "scripts/build-privileged-helper-app.mjs"),
    "--runtime-descriptor", descriptorPath,
    "--node-archive", nodeArchive,
    "--output", outputPath,
    "--ad-hoc"
    ], {
    cwd: repositoryRoot,
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin:/usr/sbin:/sbin", NODE_OPTIONS: "" },
    encoding: "utf8",
    windowsHide: true,
    shell: false,
    timeout: 300_000,
    maxBuffer: 2 * 1024 * 1024
  });
}

function parseBuildResult(output) {
  const candidates = output.trim().split("\n").filter((line) => line.startsWith("{"));
  assert.equal(candidates.length, 1, "builder must emit one machine-readable result");
  return JSON.parse(candidates[0]);
}
