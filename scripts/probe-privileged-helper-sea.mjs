import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, copyFile, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const nativeAddonPath = await realpath(join(repositoryRoot, "packages/broker/dist/peer_credentials.node"));
const nativeAddonBytes = await readFile(nativeAddonPath);
const nativeAddonDigest = createHash("sha256").update(nativeAddonBytes).digest("hex");
const temporaryRoot = await mkdtemp(join(tmpdir(), "mac-operator-helper-sea-"));

try {
  assert.equal(process.platform, "darwin", "SEA native-addon probe requires macOS");
  assert.equal(process.arch, "arm64", "SEA native-addon probe requires arm64");
  assert.match(process.versions.node, /^\d+\.\d+\.\d+$/u, "SEA probe requires a stable Node.js version");
  assert.ok(compareVersions(process.versions.node, "24.0.0") >= 0 && compareVersions(process.versions.node, "25.0.0") < 0,
    "SEA probe requires the Node.js 24 LTS legacy injection workflow");

  const mainPath = join(temporaryRoot, "main.cjs");
  const configPath = join(temporaryRoot, "sea-config.json");
  const blobPath = join(temporaryRoot, "sea-prep.blob");
  const executablePath = join(temporaryRoot, "privileged-helper-sea-probe");
  await writeFile(mainPath, buildProbeMain(nativeAddonDigest), { flag: "wx", mode: 0o600 });
  await writeFile(configPath, JSON.stringify({
    main: mainPath,
    output: blobPath,
    disableExperimentalSEAWarning: true,
    useSnapshot: false,
    useCodeCache: false,
    execArgvExtension: "none",
    assets: { "peer_credentials.node": nativeAddonPath }
  }), { flag: "wx", mode: 0o600 });

  run(process.execPath, ["--experimental-sea-config", configPath], {
    cwd: repositoryRoot,
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" },
    timeout: 120_000,
    maxBuffer: 1024 * 1024
  }, "SEA preparation blob generation");

  await copyFile(process.execPath, executablePath);
  await chmod(executablePath, 0o700);
  removeCodeSignatureIfPresent(executablePath);
  run("postject", [
    executablePath,
    "NODE_SEA_BLOB",
    blobPath,
    "--sentinel-fuse",
    "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2",
    "--macho-segment-name",
    "NODE_SEA"
  ], {
    cwd: repositoryRoot,
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin:/usr/sbin:/sbin" },
    timeout: 120_000,
    maxBuffer: 1024 * 1024
  }, "SEA blob injection");
  run("/usr/bin/codesign", ["--sign", "-", "--force", executablePath], {
    cwd: repositoryRoot,
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" },
    timeout: 30_000,
    maxBuffer: 1024 * 1024
  }, "local ad-hoc signing");

  const output = run(executablePath, [], {
    cwd: temporaryRoot,
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", NODE_OPTIONS: "--trace-warnings" },
    timeout: 30_000,
    maxBuffer: 1024 * 1024
  }, "SEA execution");
  const result = JSON.parse(output.trim());
  assert.deepEqual(result, {
    sea: true,
    nativeAddon: "loaded",
    nativeAddonDigest,
    runtimeVersion: process.versions.node,
    sqlite: "passed",
    nodeOptionsIgnored: true
  });
  process.stdout.write(`${JSON.stringify({ status: "passed", runtimeVersion: process.versions.node, nativeAddonDigest })}\n`);
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

function buildProbeMain(expectedAddonDigest) {
  return `"use strict";
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const sea = require("node:sea");
const { DatabaseSync } = require("node:sqlite");
if (!sea.isSea()) throw new Error("single-executable mode is unavailable");
const addonBytes = Buffer.from(sea.getAsset("peer_credentials.node"));
const addonDigest = crypto.createHash("sha256").update(addonBytes).digest("hex");
if (addonDigest !== ${JSON.stringify(expectedAddonDigest)}) throw new Error("embedded native adapter digest mismatch");
const privateDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "mop-native-addon-"));
fs.chmodSync(privateDirectory, 0o700);
const addonPath = path.join(privateDirectory, "peer_credentials.node");
const descriptor = fs.openSync(addonPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o500);
try {
  let offset = 0;
  while (offset < addonBytes.length) offset += fs.writeSync(descriptor, addonBytes, offset, addonBytes.length - offset);
  fs.fsyncSync(descriptor);
} finally {
  fs.closeSync(descriptor);
}
const nativeModule = { exports: {} };
try {
  process.dlopen(nativeModule, addonPath);
} finally {
  fs.rmSync(privateDirectory, { recursive: true, force: true });
}
const native = nativeModule.exports;
if (native.nativeNodeVersion !== process.versions.node) throw new Error("native adapter runtime version mismatch");
if (native.nativePlatform !== process.platform || native.nativeArch !== process.arch) throw new Error("native adapter host mismatch");
const identity = native.getProcessIdentity(process.pid);
if (!identity || identity.pid !== process.pid || !Number.isSafeInteger(identity.startTimeMicros) || identity.startTimeMicros < 1) {
  throw new Error("native process identity readback failed");
}
const database = new DatabaseSync(":memory:");
const row = database.prepare("SELECT 1 AS value").get();
database.close();
if (row.value !== 1) throw new Error("built-in SQLite smoke failed");
const result = {
  sea: true,
  nativeAddon: "loaded",
  nativeAddonDigest: addonDigest,
  runtimeVersion: process.versions.node,
  sqlite: "passed",
  nodeOptionsIgnored: process.execArgv.length === 0
};
if (!result.nodeOptionsIgnored) throw new Error("NODE_OPTIONS unexpectedly altered the SEA runtime");
process.stdout.write(JSON.stringify(result) + "\\n");
`;
}

function run(executable, args, options, label) {
  const result = spawnSync(executable, args, {
    ...options,
    encoding: "utf8",
    windowsHide: true,
    shell: false
  });
  if (result.error !== undefined) throw new Error(`${label} could not run: ${result.error.message}`);
  if (result.status !== 0) {
    const detail = (result.stderr ?? "").trim().slice(-2_000);
    throw new Error(`${label} failed with exit code ${String(result.status)}${detail === "" ? "" : `: ${detail}`}`);
  }
  return result.stdout ?? "";
}

function removeCodeSignatureIfPresent(executablePath) {
  const inspection = spawnSync("/usr/bin/codesign", ["--display", "--verbose=2", executablePath], {
    cwd: repositoryRoot,
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" },
    encoding: "utf8",
    windowsHide: true,
    shell: false,
    timeout: 30_000,
    maxBuffer: 1024 * 1024
  });
  if (inspection.status === 0) {
    run("/usr/bin/codesign", ["--remove-signature", executablePath], {
      cwd: repositoryRoot,
      env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" },
      timeout: 30_000,
      maxBuffer: 1024 * 1024
    }, "removing source binary signature");
    return;
  }
  const detail = `${inspection.stdout ?? ""}\n${inspection.stderr ?? ""}`;
  if (!detail.includes("code object is not signed at all")) {
    throw new Error(`Could not inspect source binary signature: ${detail.trim().slice(-2_000)}`);
  }
}

function compareVersions(left, right) {
  const leftParts = left.split(".").map(Number);
  const rightParts = right.split(".").map(Number);
  for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index += 1) {
    const difference = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}
