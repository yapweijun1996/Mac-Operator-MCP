import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";

const MAX_MANIFEST_BYTES = 256 * 1024;
const COMPONENT_INPUT_KEYS = {
  edge: new Set([
    "uid", "userHome", "installRoot", "plistPath", "service", "metadata", "signature",
    "signaturePolicy", "signedArtifactPath", "enabledCapabilities", "expectedPreviousSourceRevision",
    "bindHost", "bindPort", "statusSocketPath", "statusKeyPath", "statusKeyDigest"
  ]),
  broker: new Set([
    "uid", "userHome", "installRoot", "plistPath", "service", "metadata", "signature",
    "signaturePolicy", "signedArtifactPath", "enabledCapabilities", "expectedPreviousSourceRevision",
    "statusSocketPath", "statusKeyPath", "statusKeyDigest"
  ]),
  authority: new Set([
    "uid", "userHome", "installRoot", "plistPath", "service", "metadata", "signature",
    "signaturePolicy", "signedArtifactPath", "enabledCapabilities", "expectedPreviousSourceRevision",
    "authorityConfigPath", "authorityOperatorSocketPath"
  ])
};
const REQUIRED_COMPONENT_INPUT_KEYS = {
  edge: new Set(["uid", "userHome", "installRoot", "plistPath", "service", "metadata", "signature", "signedArtifactPath", "bindHost", "bindPort"]),
  broker: new Set(["uid", "userHome", "installRoot", "plistPath", "service", "metadata", "signature", "signedArtifactPath"]),
  authority: new Set(["uid", "userHome", "installRoot", "plistPath", "service", "metadata", "signature", "signedArtifactPath", "authorityConfigPath", "authorityOperatorSocketPath"])
};

try {
  const { manifestPath, developmentProbe } = parseArguments(process.argv.slice(2));
  const manifest = await readManifest(manifestPath);
  const { buildMacOsAuthorityInstallPlan, buildMacOsEdgeInstallPlan, buildMacOsInstallPlan } = await import("../packages/broker/dist/index.js");
  const operation = manifest.operation;
  const edgeInput = withOperation(manifest.edge, operation, "edge");
  const brokerInput = withOperation(manifest.broker, operation, "broker");
  const authorityInput = manifest.authority === undefined ? undefined : withOperation(manifest.authority, operation, "authority");
  if (!developmentProbe && [edgeInput, brokerInput, authorityInput].filter(Boolean).some((input) => input.signaturePolicy === "development-ad-hoc")) {
    throw new Error("development-ad-hoc planning requires the explicit --development-probe flag");
  }
  assertSharedDeploymentIdentity([edgeInput, brokerInput, ...(authorityInput === undefined ? [] : [authorityInput])]);
  const edgePlan = buildMacOsEdgeInstallPlan(edgeInput);
  const brokerPlan = buildMacOsInstallPlan(brokerInput);
  const authorityPlan = authorityInput === undefined ? undefined : buildMacOsAuthorityInstallPlan(authorityInput);
  process.stdout.write(`${JSON.stringify({
    schemaVersion: "0.1",
    mechanism: "macos-launchagent-plan-v1",
    mode: "read-only-plan",
    operation,
    developmentProbe,
    manifestPath,
    components: [
      ...(authorityPlan === undefined ? [] : [summarizePlan(authorityPlan)]),
      summarizePlan(edgePlan),
      summarizePlan(brokerPlan)
    ],
    order: authorityPlan === undefined ? ["edge", "broker"] : ["authority", "edge", "broker"],
    apply: {
      available: false,
      reason: "this command never writes plists, calls launchctl, installs packages, or changes service state"
    }
  })}\n`);
} catch (error) {
  const message = error instanceof Error ? error.message : "macOS LaunchAgent plan generation failed";
  process.stderr.write(`macOS LaunchAgent plan failed: ${message}\n`);
  process.exitCode = 1;
}

function parseArguments(args) {
  if (args.length < 2 || args.length > 3 || args[0] !== "--manifest") {
    throw new Error("usage: node scripts/plan-macos-launchagents.mjs --manifest /absolute/path/manifest.json [--development-probe]");
  }
  const manifestPath = args[1];
  if (!isCanonicalAbsolutePath(manifestPath)) throw new Error("manifest path must be a canonical absolute path");
  if (args.length === 3 && args[2] !== "--development-probe") {
    throw new Error("only --development-probe is supported after --manifest");
  }
  return { manifestPath, developmentProbe: args[2] === "--development-probe" };
}

async function readManifest(path) {
  let stats;
  try {
    stats = lstatSync(path);
  } catch {
    throw new Error("deployment manifest is unavailable");
  }
  const uid = process.getuid?.() ?? -1;
  if (!stats.isFile() || stats.uid !== uid || (stats.mode & 0o022) !== 0) {
    throw new Error("deployment manifest must be an owner-only regular file");
  }
  const bytes = readFileSync(path);
  if (bytes.byteLength > MAX_MANIFEST_BYTES) throw new Error("deployment manifest exceeds its size budget");
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("deployment manifest is not strict UTF-8 JSON");
  }
  validateManifest(value);
  return value;
}

function validateManifest(value) {
  assertRecord(value, "deployment manifest");
  const expectedKeys = Object.hasOwn(value, "authority")
    ? ["authority", "broker", "edge", "operation", "schemaVersion"]
    : ["broker", "edge", "operation", "schemaVersion"];
  assertExactKeys(value, expectedKeys, "deployment manifest");
  if (value.schemaVersion !== "0.1") throw new Error("deployment manifest schema version is unsupported");
  if (!["install", "upgrade", "rollback", "uninstall"].includes(value.operation)) {
    throw new Error("deployment manifest operation is invalid");
  }
  validateComponentInput(value.edge, "edge");
  validateComponentInput(value.broker, "broker");
  if (Object.hasOwn(value, "authority")) validateComponentInput(value.authority, "authority");
  validateStatusChannel(value.edge, "edge");
  validateStatusChannel(value.broker, "broker");
}

function validateComponentInput(value, component) {
  assertRecord(value, `${component} deployment input`);
  assertAllowedKeys(value, COMPONENT_INPUT_KEYS[component], `${component} deployment input`);
  for (const key of REQUIRED_COMPONENT_INPUT_KEYS[component]) {
    if (!Object.hasOwn(value, key)) throw new Error(`${component} deployment input is missing ${key}`);
  }
}

function validateStatusChannel(value, component) {
  if (component === "authority") return;
  const fields = [value.statusSocketPath, value.statusKeyPath, value.statusKeyDigest];
  const present = fields.filter((field) => field !== undefined).length;
  if (present !== 0 && present !== fields.length) {
    throw new Error(`${component} status channel configuration is incomplete`);
  }
  if (present === 0) return;
  if (!isCanonicalAbsolutePath(value.statusSocketPath) || !value.statusSocketPath.endsWith(".sock") ||
      !isCanonicalAbsolutePath(value.statusKeyPath) ||
      !isDescendant(value.installRoot, value.statusSocketPath) || !isDescendant(value.installRoot, value.statusKeyPath) ||
      !/^[a-f0-9]{64}$/u.test(value.statusKeyDigest)) {
    throw new Error(`${component} status channel path or digest is invalid`);
  }
}

function withOperation(value, operation, component) {
  return { operation, ...value };
}

function assertSharedDeploymentIdentity(components) {
  for (const key of ["uid", "userHome", "installRoot"]) {
    const expected = components[0][key];
    if (components.some((component) => component[key] !== expected)) throw new Error(`LaunchAgent ${key} values must match`);
  }
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
    authorityConfigPath: plan.authorityConfigPath ?? null,
    authorityOperatorSocketPath: plan.authorityOperatorSocketPath ?? null,
    signedArtifactPath: plan.signedArtifactPath,
    signaturePolicy: plan.signaturePolicy,
    signature: plan.signature,
    enabledCapabilities: [...plan.enabledCapabilities],
    metadata: plan.metadata,
    edgeListener: plan.edgeListener ?? null,
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

function assertRecord(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(`${label} must be a plain object`);
  }
}

function assertExactKeys(value, allowed, label) {
  const expected = [...allowed].sort();
  const actual = Object.keys(value).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} contains unsupported or missing fields`);
  }
}

function assertAllowedKeys(value, allowed, label) {
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new Error(`${label} contains unsupported fields`);
  }
}

function isCanonicalAbsolutePath(path) {
  return typeof path === "string" && isAbsolute(path) && path !== "/" && !path.endsWith("/") &&
    !path.includes("\0") && !path.includes("\r") && !path.includes("\n") && resolve(path) === path;
}

function isDescendant(root, target) {
  const suffix = relative(root, target);
  return suffix.length > 0 && !suffix.startsWith("..") && !isAbsolute(suffix);
}
