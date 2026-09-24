import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

const MAX_MANIFEST_BYTES = 512 * 1024;
const REQUIRED_KEYS = [
  "authoritySocketPath", "attestationPublicKeyConfigPath", "brokerPeer", "brokerSocketPath",
  "contractVersion", "evidenceRef", "helperKeyConfigPath", "helperRoot", "operation", "policyVersion",
  "releaseEvidence", "service", "signedArtifactPath", "signature", "snapshotRoot", "socketPath",
  "sourceRevision", "schemaVersion"
];
const OPTIONAL_KEYS = ["expectedPreviousSourceRevision", "plistPath", "reservedSocketPaths", "statusSocketPath"];

try {
  const manifestPath = parseArguments(process.argv.slice(2));
  const manifest = await readManifest(manifestPath);
  const { buildRootHelperSnapshotPackagePlan } = await import("../packages/broker/dist/index.js");
  const plan = buildRootHelperSnapshotPackagePlan(manifest);
  process.stdout.write(`${JSON.stringify({
    schemaVersion: "0.1",
    mechanism: "macos-root-helper-snapshot-plan-v1",
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
  const message = error instanceof Error ? error.message : "root-helper snapshot plan generation failed";
  process.stderr.write(`Root-helper snapshot plan failed: ${message}\n`);
  process.exitCode = 1;
}

function parseArguments(args) {
  if (args.length !== 2 || args[0] !== "--manifest") {
    throw new Error("usage: node scripts/plan-root-helper-snapshot.mjs --manifest /absolute/path/manifest.json");
  }
  const path = args[1];
  if (!isCanonicalAbsolutePath(path)) throw new Error("manifest path must be a canonical absolute path");
  return path;
}

function readManifest(path) {
  let stats;
  try {
    stats = lstatSync(path);
  } catch {
    throw new Error("root-helper plan manifest is unavailable");
  }
  const uid = process.getuid?.() ?? -1;
  if (!stats.isFile() || stats.uid !== uid || (stats.mode & 0o077) !== 0) {
    throw new Error("root-helper plan manifest must be an owner-only regular file");
  }
  const bytes = readFileSync(path);
  if (bytes.byteLength > MAX_MANIFEST_BYTES) throw new Error("root-helper plan manifest exceeds its size budget");
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("root-helper plan manifest is not strict UTF-8 JSON");
  }
  validateManifest(value);
  return value;
}

function validateManifest(value) {
  assertRecord(value, "root-helper plan manifest");
  const allowed = new Set([...REQUIRED_KEYS, ...OPTIONAL_KEYS]);
  const actual = Object.keys(value).sort();
  if (actual.some((key) => !allowed.has(key))) throw new Error("root-helper plan manifest contains unsupported fields");
  for (const key of REQUIRED_KEYS) {
    if (!Object.hasOwn(value, key)) throw new Error(`root-helper plan manifest is missing ${key}`);
  }
  if (value.schemaVersion !== "0.1") throw new Error("root-helper plan manifest schema version is unsupported");
  if (!["install", "upgrade", "rollback", "uninstall"].includes(value.operation)) {
    throw new Error("root-helper plan manifest operation is invalid");
  }
  if (value.plistPath !== undefined && value.plistPath !== "/Library/LaunchDaemons/com.mac-operator.root-helper-snapshot.plist") {
    throw new Error("root-helper plan manifest plistPath must use the exact system LaunchDaemon path");
  }
  if (value.reservedSocketPaths !== undefined && !Array.isArray(value.reservedSocketPaths)) {
    throw new Error("root-helper plan manifest reservedSocketPaths must be an array");
  }
}

function summarizePlan(plan) {
  return {
    component: "mac-operator-root-helper-snapshot",
    serviceId: `${plan.domain}/${plan.label}`,
    domain: plan.domain,
    label: plan.label,
    operation: plan.operation,
    helperRoot: plan.helperRoot,
    plistPath: plan.plistPath,
    signedArtifactPath: plan.signedArtifactPath,
    signature: plan.signature,
    releaseEvidence: {
      artifact: plan.releaseEvidence.artifact,
      signature: {
        identifier: plan.releaseEvidence.signature.identifier,
        teamIdentifier: plan.releaseEvidence.signature.teamIdentifier,
        cdHash: plan.releaseEvidence.signature.cdHash,
        signatureType: plan.releaseEvidence.signature.signatureType,
        valid: plan.releaseEvidence.signature.valid
      },
      notarization: {
        artifactPath: plan.releaseEvidence.notarization.artifactPath,
        assessed: plan.releaseEvidence.notarization.assessed,
        teamIdentifier: plan.releaseEvidence.notarization.teamIdentifier,
        source: plan.releaseEvidence.notarization.source,
        origin: plan.releaseEvidence.notarization.origin
      },
      policy: plan.releaseEvidence.policy
    },
    protectedPaths: {
      helperKeyConfigPath: plan.helperKeyConfigPath,
      attestationPublicKeyConfigPath: plan.attestationPublicKeyConfigPath,
      snapshotRoot: plan.snapshotRoot
    },
    sockets: {
      rootHelper: plan.socketPath,
      status: plan.statusSocketPath,
      broker: plan.brokerSocketPath,
      authority: plan.authoritySocketPath,
      reserved: [...plan.reservedSocketPaths]
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

function assertRecord(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(`${label} must be a plain object`);
  }
}

function isCanonicalAbsolutePath(path) {
  return typeof path === "string" && isAbsolute(path) && path !== "/" && !path.endsWith("/") &&
    !path.includes("\0") && !path.includes("\r") && !path.includes("\n") && resolve(path) === path;
}
