import { lstatSync, readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

const MAX_MANIFEST_BYTES = 512 * 1024;
const ROOT_HELPER_SERVICE_ID = "system/com.mac-operator.root-helper-snapshot";
const PLIST_PATH = "/Library/LaunchDaemons/com.mac-operator.root-helper-snapshot.plist";

try {
  const { manifestPath, confirmedOperation } = parseArguments(process.argv.slice(2));
  if ((process.getuid?.() ?? -1) !== 0) throw new Error("root-helper package mutation requires a root host process");
  const manifest = readManifest(manifestPath);
  if (manifest.operation !== confirmedOperation) throw new Error("--confirm must exactly match manifest operation");
  const broker = await import("../packages/broker/dist/index.js");
  const plan = broker.buildRootHelperSnapshotPackagePlan(manifest);
  const serviceBundle = await createServiceObserver(broker, plan);
  try {
    const serviceObserver = serviceBundle.observer;
    const readExistingService = broker.createRootHelperSnapshotPackageExistingServiceReader(plan, serviceObserver);
    const execution = await broker.executeRootHelperSnapshotPackagePlan(plan, {
      confirmOperation: confirmedOperation,
      readExistingService,
      ...(confirmedOperation === "uninstall"
        ? { readback: async () => readAbsentService(broker, serviceObserver) }
        : { readbackObserver: broker.createRootHelperSnapshotPackageHostObserver(plan, {
            readReleaseEvidence: () => readReleaseEvidence(broker, plan)
          }) })
    });
    process.stdout.write(`${JSON.stringify({
      status: "passed",
      mechanism: "macos-root-helper-snapshot-apply-v1",
      operation: execution.operation,
      serviceId: ROOT_HELPER_SERVICE_ID,
      plistPath: execution.plist.path,
      readback: execution.readback === null ? null : {
        sourceRevision: plan.sourceRevision,
        processPid: execution.readback.processIdentity.pid,
        socketCount: 4
      }
    })}\n`);
  } finally {
    serviceBundle.dispose();
  }
} catch (error) {
  const message = error instanceof Error ? error.message : "root-helper package mutation failed";
  process.stderr.write(`Root-helper package apply failed: ${message}\n`);
  process.exitCode = 1;
}

function parseArguments(args) {
  if (args.length !== 4 || args[0] !== "--manifest" || args[2] !== "--confirm" ||
      !["install", "upgrade", "rollback", "uninstall"].includes(args[3])) {
    throw new Error("usage: node scripts/apply-root-helper-snapshot.mjs --manifest /absolute/path/manifest.json --confirm install|upgrade|rollback|uninstall");
  }
  if (!isCanonicalAbsolutePath(args[1])) throw new Error("manifest path must be a canonical absolute path");
  return { manifestPath: args[1], confirmedOperation: args[3] };
}

function readManifest(path) {
  let stats;
  try { stats = lstatSync(path); } catch { throw new Error("root-helper apply manifest is unavailable"); }
  const uid = process.getuid?.() ?? -1;
  if (!stats.isFile() || stats.uid !== uid || (stats.mode & 0o077) !== 0) {
    throw new Error("root-helper apply manifest must be an owner-only regular file");
  }
  const bytes = readFileSync(path);
  if (bytes.byteLength > MAX_MANIFEST_BYTES) throw new Error("root-helper apply manifest exceeds its size budget");
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { throw new Error("root-helper apply manifest is not strict UTF-8 JSON"); }
}

async function createServiceObserver(broker, plan) {
  let key;
  if (plan.operation !== "install") {
    const loaded = await broker.loadPrivilegedHelperKeyConfigWithoutBroker(plan.helperKeyConfigPath);
    key = loaded.key.key;
  }
  const observer = broker.createRootHelperSnapshotPackageObserver({
    readSourceRevision: key === undefined ? undefined : async () => {
      const identity = await broker.captureLaunchdRootHelperProcessIdentity({ rootHelperServiceId: ROOT_HELPER_SERVICE_ID });
      const status = await broker.readRootHelperSnapshotStatus({
        socketPath: plan.statusSocketPath,
        authenticationKey: key,
        peerPolicy: { expectedUid: 0, allowedProcessIdentity: identity }
      });
      return status.sourceRevision;
    }
  });
  return { observer, dispose: () => key?.fill(0) };
}

async function readAbsentService(broker, observer) {
  try {
    await observer.readLaunchd(ROOT_HELPER_SERVICE_ID);
    return {};
  } catch (error) {
    if (error?.code === "UNAVAILABLE") return null;
    throw error;
  }
}

async function readReleaseEvidence(broker, plan) {
  return broker.runMacOsReleasePreflight({
    artifactPath: plan.signedArtifactPath,
    artifactSha256: plan.releaseEvidence.artifact.sha256,
    artifactBytes: plan.releaseEvidence.artifact.bytes,
    ownerUid: 0,
    signature: plan.signature
  });
}

function isCanonicalAbsolutePath(path) {
  return typeof path === "string" && isAbsolute(path) && path !== "/" && !path.endsWith("/") &&
    !path.includes("\0") && !path.includes("\r") && !path.includes("\n") && resolve(path) === path;
}
