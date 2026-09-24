import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

const MAX_MANIFEST_BYTES = 512 * 1024;
const REQUIRED_KEYS = [
  "brokerPeer", "brokerSocketPath", "contractVersion", "helperAuthoritySocketPath",
  "helperKeyConfigPath", "helperRoot", "helperSocketPath", "operation", "policyVersion",
  "schemaVersion", "service", "signature", "signedArtifactPath", "sourceRevision"
];
const OPTIONAL_KEYS = ["capabilityRelease", "expectedPreviousSourceRevision", "plistPath"];

try {
  const manifestPath = parseArguments(process.argv.slice(2));
  const manifest = readManifest(manifestPath);
  const { buildPrivilegedHelperPackagePlan } = await import("../packages/broker/dist/index.js");
  const plan = buildPrivilegedHelperPackagePlan(manifest);
  process.stdout.write(`${JSON.stringify({
    schemaVersion: "0.1",
    mechanism: "macos-privileged-helper-plan-v1",
    mode: "read-only-plan",
    operation: plan.operation,
    manifestPath,
    plan: summarizePlan(plan),
    apply: {
      available: false,
      reason: "this command never writes root-domain plists, calls launchctl, installs packages, or changes service state"
    }
  })}\n`);
} catch (error) {
  const message = error instanceof Error ? error.message : "privileged helper plan generation failed";
  process.stderr.write(`Privileged helper plan failed: ${message}\n`);
  process.exitCode = 1;
}

function parseArguments(args) {
  if (args.length !== 2 || args[0] !== "--manifest") {
    throw new Error("usage: node scripts/plan-privileged-helper.mjs --manifest /absolute/path/manifest.json");
  }
  if (!isCanonicalAbsolutePath(args[1])) throw new Error("manifest path must be a canonical absolute path");
  return args[1];
}

function readManifest(path) {
  const before = readManifestStat(path);
  const bytes = readFileSync(path);
  if (bytes.byteLength > MAX_MANIFEST_BYTES) throw new Error("privileged helper manifest exceeds its size budget");
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("privileged helper manifest is not strict UTF-8 JSON");
  }
  validateManifest(value);
  const after = readManifestStat(path);
  if (!sameIdentity(before, after)) throw new Error("privileged helper manifest changed during read");
  return value;
}

function validateManifest(value) {
  assertRecord(value, "privileged helper manifest");
  const allowed = new Set([...REQUIRED_KEYS, ...OPTIONAL_KEYS]);
  const actual = Object.keys(value).sort();
  if (actual.some((key) => !allowed.has(key)) || REQUIRED_KEYS.some((key) => !Object.hasOwn(value, key))) {
    throw new Error("privileged helper manifest contains unsupported or missing fields");
  }
  if (value.schemaVersion !== "0.1") throw new Error("privileged helper manifest schema version is unsupported");
  if (!["install", "upgrade", "rollback", "uninstall"].includes(value.operation)) {
    throw new Error("privileged helper operation is invalid");
  }
}

function summarizePlan(plan) {
  return {
    component: "mac-operator-privileged-helper",
    serviceId: `${plan.domain}/${plan.label}`,
    domain: plan.domain,
    label: plan.label,
    operation: plan.operation,
    helperRoot: plan.helperRoot,
    replayLedgerPath: plan.replayLedgerPath,
    plistPath: plan.plistPath,
    signedArtifactPath: plan.signedArtifactPath,
    signature: plan.signature,
    capabilityRelease: plan.capabilityRelease === undefined ? null : {
      source: plan.capabilityRelease.source,
      adapterAvailable: plan.capabilityRelease.adapterAvailable,
      enabledCapabilities: [...plan.capabilityRelease.enabledCapabilities],
      evidenceRef: plan.capabilityRelease.evidenceRef
    },
    sockets: {
      helper: plan.helperSocketPath,
      broker: plan.brokerSocketPath,
      authority: plan.helperAuthoritySocketPath
    },
    brokerPeer: plan.brokerPeer,
    launchd: plan.launchd,
    plist: {
      bytes: Buffer.byteLength(plan.renderedPlist, "utf8"),
      sha256: createHash("sha256").update(plan.renderedPlist, "utf8").digest("hex")
    },
    commands: {
      signatureVerify: plan.signatureVerify,
      notarizationAssess: plan.notarizationAssess,
      installBootstrap: plan.install.bootstrap,
      rollbackBootout: plan.rollback.bootout,
      rollbackBootstrap: plan.rollback.bootstrap,
      uninstallBootout: plan.uninstall.bootout
    },
    preflight: [...plan.preflight]
  };
}

function readManifestStat(path) {
  let stats;
  try { stats = lstatSync(path); } catch { throw new Error("privileged helper manifest is unavailable"); }
  const uid = process.getuid?.() ?? -1;
  if (!stats.isFile() || stats.uid !== uid || (stats.mode & 0o077) !== 0) {
    throw new Error("privileged helper manifest must be an owner-only regular file");
  }
  return stats;
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid &&
    left.mode === right.mode && left.size === right.size && left.mtimeMs === right.mtimeMs;
}

function assertRecord(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(`${label} must be a plain object`);
  }
}

function isCanonicalAbsolutePath(path) {
  return typeof path === "string" && isAbsolute(path) && path !== "/" && !path.endsWith("/") &&
    !path.includes("\0") && !path.includes("\r") && !path.includes("\n") && resolve(path) === path;
}
