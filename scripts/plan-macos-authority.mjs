import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";

const MAX_MANIFEST_BYTES = 256 * 1024;
const ALLOWED_KEYS = new Set([
  "authorityConfigPath", "authorityOperatorSocketPath", "enabledCapabilities", "expectedPreviousSourceRevision", "installRoot", "metadata", "operation", "schemaVersion",
  "plistPath", "service", "signature", "signaturePolicy", "signedArtifactPath", "uid", "userHome"
]);
const REQUIRED_KEYS = ["authorityConfigPath", "authorityOperatorSocketPath", "installRoot", "metadata", "operation", "plistPath", "schemaVersion", "service", "signature", "signedArtifactPath", "uid", "userHome"];

try {
  const { manifestPath, developmentProbe } = parseArguments(process.argv.slice(2));
  const manifest = readManifest(manifestPath);
  const { buildMacOsAuthorityInstallPlan } = await import("../packages/broker/dist/index.js");
  const input = { ...manifest, operation: manifest.operation };
  if (!developmentProbe && input.signaturePolicy === "development-ad-hoc") {
    throw new Error("development-ad-hoc planning requires the explicit --development-probe flag");
  }
  const plan = buildMacOsAuthorityInstallPlan(input);
  process.stdout.write(`${JSON.stringify({
    schemaVersion: "0.1",
    mechanism: "macos-authority-launchagent-plan-v1",
    mode: "read-only-plan",
    operation: plan.operation,
    developmentProbe,
    manifestPath,
    component: summarizePlan(plan),
    apply: {
      available: false,
      reason: "this command never writes plists, calls launchctl, installs packages, or changes service state"
    }
  })}\n`);
} catch (error) {
  const message = error instanceof Error ? error.message : "macOS Authority LaunchAgent plan generation failed";
  process.stderr.write(`macOS Authority LaunchAgent plan failed: ${message}\n`);
  process.exitCode = 1;
}

function parseArguments(args) {
  if (args.length < 2 || args.length > 3 || args[0] !== "--manifest") {
    throw new Error("usage: node scripts/plan-macos-authority.mjs --manifest /absolute/path/manifest.json [--development-probe]");
  }
  const manifestPath = args[1];
  if (!isCanonicalAbsolutePath(manifestPath)) throw new Error("manifest path must be a canonical absolute path");
  if (args.length === 3 && args[2] !== "--development-probe") throw new Error("only --development-probe is supported after --manifest");
  return { manifestPath, developmentProbe: args[2] === "--development-probe" };
}

function readManifest(path) {
  let stats;
  try { stats = lstatSync(path); } catch { throw new Error("Authority deployment manifest is unavailable"); }
  const uid = process.getuid?.() ?? -1;
  if (!stats.isFile() || stats.uid !== uid || (stats.mode & 0o077) !== 0) throw new Error("Authority deployment manifest must be an owner-only regular file");
  const bytes = readFileSync(path);
  if (bytes.byteLength > MAX_MANIFEST_BYTES) throw new Error("Authority deployment manifest exceeds its size budget");
  let value;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { throw new Error("Authority deployment manifest is not strict UTF-8 JSON"); }
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error("Authority deployment manifest must be a plain object");
  if (Object.keys(value).some((key) => !ALLOWED_KEYS.has(key)) || REQUIRED_KEYS.some((key) => !Object.hasOwn(value, key))) throw new Error("Authority deployment manifest contains unsupported or missing fields");
  if (value.schemaVersion !== "0.1") throw new Error("Authority deployment manifest schema version is unsupported");
  if (value.operation !== "install" && value.operation !== "upgrade" && value.operation !== "rollback" && value.operation !== "uninstall") throw new Error("Authority deployment operation is invalid");
  return value;
}

function summarizePlan(plan) {
  return {
    component: plan.component,
    serviceId: `${plan.domain}/${plan.label}`,
    domain: plan.domain,
    label: plan.label,
    operation: plan.operation,
    installRoot: plan.installRoot,
    plistPath: plan.plistPath,
    backupPath: plan.backupPath,
    entrypointPath: plan.entrypointPath,
    authorityConfigPath: plan.authorityConfigPath,
    authorityOperatorSocketPath: plan.authorityOperatorSocketPath,
    signedArtifactPath: plan.signedArtifactPath,
    signaturePolicy: plan.signaturePolicy,
    signature: plan.signature,
    metadata: plan.metadata,
    launchd: plan.launchd,
    plist: {
      bytes: Buffer.byteLength(plan.renderedPlist, "utf8"),
      sha256: createHash("sha256").update(plan.renderedPlist, "utf8").digest("hex")
    },
    commands: {
      signatureVerify: plan.signatureVerify,
      ...(plan.notarizationAssess === undefined ? {} : { notarizationAssess: plan.notarizationAssess }),
      installBootstrap: plan.install.bootstrap,
      rollbackBootout: plan.rollback.bootout,
      uninstallBootout: plan.uninstall.bootout
    },
    preflight: [...plan.preflight]
  };
}

function isCanonicalAbsolutePath(path) {
  return typeof path === "string" && isAbsolute(path) && path !== "/" && !path.endsWith("/") &&
    !path.includes("\0") && !path.includes("\r") && !path.includes("\n") && resolve(path) === path;
}
