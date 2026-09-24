import { lstatSync, readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

const MAX_MANIFEST_BYTES = 512 * 1024;
const REQUIRED_KEYS = [
  "brokerPeer", "brokerSocketPath", "contractVersion", "helperAuthoritySocketPath",
  "helperKeyConfigPath", "helperRoot", "helperSocketPath", "operation", "policyVersion",
  "schemaVersion", "service", "signature", "signedArtifactPath", "sourceRevision"
];
const OPTIONAL_KEYS = ["capabilityRelease", "expectedPreviousSourceRevision", "plistPath"];
const HELPER_SERVICE_ID = "system/com.mac-operator.privileged-helper";

try {
  const { manifestPath, confirmedOperation } = parseArguments(process.argv.slice(2));
  if ((process.getuid?.() ?? -1) !== 0) throw new Error("privileged helper package mutation requires a root host process");
  const manifest = readManifest(manifestPath);
  if (manifest.operation !== confirmedOperation) throw new Error("--confirm must exactly match manifest operation");
  const broker = await import("../packages/broker/dist/index.js");
  const plan = broker.buildPrivilegedHelperPackagePlan(manifest);
  const loaded = await broker.loadPrivilegedHelperKeyConfigWithoutBroker(plan.helperKeyConfigPath);
  const authenticationKey = loaded.key.key;
  const observer = broker.createPrivilegedHelperPackageHostObserver(plan, {
    helperStatusClient: {
      socketPath: plan.helperSocketPath,
      authenticationKey
    }
  });
  try {
    const readExistingService = broker.createPrivilegedHelperPackageExistingServiceReader(plan, {
      readLaunchd: observer.readLaunchd,
      readRuntime: observer.readRuntime
    });
    const execution = await broker.executePrivilegedHelperPackagePlan(plan, {
      confirmOperation: confirmedOperation,
      ownerUid: 0,
      readExistingService,
      readback: async () => confirmedOperation === "uninstall"
        ? await readAbsentService(observer)
        : await broker.observePrivilegedHelperPackageReadback(plan, observer)
    });
    process.stdout.write(`${JSON.stringify({
      status: "passed",
      mechanism: "macos-privileged-helper-apply-v1",
      operation: execution.operation,
      serviceId: HELPER_SERVICE_ID,
      plistPath: execution.plist.path,
      readback: execution.readback === null ? null : {
        processPid: execution.readback.processIdentity.pid,
        sourceRevision: execution.readback.helper.sourceRevision,
        adapterAvailable: execution.readback.helper.adapterAvailable,
        enabledCapabilities: [...execution.readback.helper.enabledCapabilities]
      }
    })}\n`);
  } finally {
    authenticationKey.fill(0);
  }
} catch (error) {
  const message = error instanceof Error ? error.message : "privileged helper package mutation failed";
  process.stderr.write(`Privileged helper package apply failed: ${message}\n`);
  process.exitCode = 1;
}

function parseArguments(args) {
  if (args.length !== 4 || args[0] !== "--manifest" || args[2] !== "--confirm" ||
      !["install", "upgrade", "rollback", "uninstall"].includes(args[3])) {
    throw new Error("usage: node scripts/apply-privileged-helper.mjs --manifest /absolute/path/manifest.json --confirm install|upgrade|rollback|uninstall");
  }
  if (!isCanonicalAbsolutePath(args[1])) throw new Error("manifest path must be a canonical absolute path");
  return { manifestPath: args[1], confirmedOperation: args[3] };
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
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error("privileged helper manifest must be a plain object");
  }
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

async function readAbsentService(observer) {
  try {
    await observer.readLaunchd(HELPER_SERVICE_ID);
    throw new Error("privileged helper uninstall readback still reports an installed service");
  } catch (error) {
    if (error?.code === "UNAVAILABLE") return null;
    throw error;
  }
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

function isCanonicalAbsolutePath(path) {
  return typeof path === "string" && isAbsolute(path) && path !== "/" && !path.endsWith("/") &&
    !path.includes("\0") && !path.includes("\r") && !path.includes("\n") && resolve(path) === path;
}
