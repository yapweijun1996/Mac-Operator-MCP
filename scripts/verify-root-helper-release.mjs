import { lstatSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { hasSafeParentChain } from "./safe-path-parent.mjs";
import { readProtectedRegularFile } from "./protected-file-read.mjs";

const MAX_MANIFEST_BYTES = 64 * 1024;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;

try {
  const manifestPath = parseManifestPath(process.argv.slice(2));
  const manifest = await readManifest(manifestPath);
  const {
    runMacOsReleasePreflight,
    validateRootHelperSnapshotReleaseEvidence
  } = await import("../packages/broker/dist/index.js");
  const artifact = readArtifactIdentity(manifest.artifactPath, manifest.ownerUid);
  const evidence = await runMacOsReleasePreflight({
    artifactPath: manifest.artifactPath,
    artifactSha256: manifest.artifactSha256,
    ...(manifest.artifactBytes === undefined ? {} : { artifactBytes: manifest.artifactBytes }),
    ownerUid: manifest.ownerUid,
    signature: manifest.signature
  });
  validateRootHelperSnapshotReleaseEvidence(evidence, {
    helperPath: manifest.artifactPath,
    artifactPath: manifest.artifactPath,
    signature: manifest.signature
  });
  process.stdout.write(`${JSON.stringify({
    schemaVersion: "0.1",
    mechanism: "macos-root-helper-release-v1",
    helperPath: manifest.artifactPath,
    helperBytes: artifact.size,
    releaseEvidence: evidence
  })}\n`);
} catch (error) {
  const code = error !== null && typeof error === "object" && "code" in error && typeof error.code === "string"
    ? error.code
    : "ROOT_HELPER_RELEASE_PREFLIGHT_FAILED";
  const message = error instanceof Error ? error.message : "Root-helper release preflight failed";
  process.stderr.write(`Root-helper release preflight ${code}: ${message}\n`);
  process.exitCode = 1;
}

function parseManifestPath(args) {
  if (args.length !== 2 || args[0] !== "--manifest" || typeof args[1] !== "string") {
    throw new Error("usage: node scripts/verify-root-helper-release.mjs --manifest /absolute/path/release-manifest.json");
  }
  const path = args[1];
  if (!isCanonicalAbsolutePath(path)) throw new Error("release manifest path must be a canonical absolute path");
  return path;
}

async function readManifest(path) {
  const ownerUid = process.getuid?.() ?? -1;
  if (!hasSafeParentChain(path, ownerUid)) {
    throw new Error("release manifest must be an owner-only regular file");
  }
  const bytes = await readProtectedRegularFile(path, {
    ownerUid,
    maxBytes: MAX_MANIFEST_BYTES,
    unavailableMessage: "release manifest is unavailable",
    invalidMessage: "release manifest must be an owner-only regular file",
    oversizedMessage: "release manifest exceeds its size budget"
  });
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("release manifest is not strict UTF-8 JSON");
  }
  validateManifestShape(value);
  return value;
}

function validateManifestShape(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("release manifest root is malformed");
  const keys = Object.keys(value).sort();
  const allowed = ["artifactBytes", "artifactPath", "artifactSha256", "ownerUid", "signature"];
  if (keys.length < 4 || keys.length > allowed.length || keys.some((key) => !allowed.includes(key))) {
    throw new Error("release manifest contains unsupported fields");
  }
  if (typeof value.artifactPath !== "string" || !isCanonicalAbsolutePath(value.artifactPath)) {
    throw new Error("release manifest artifactPath is not canonical");
  }
  if (typeof value.artifactSha256 !== "string" || !DIGEST_PATTERN.test(value.artifactSha256) ||
      !Number.isSafeInteger(value.ownerUid) || value.ownerUid < 0 || value.ownerUid !== (process.getuid?.() ?? -1)) {
    throw new Error("release manifest identity fields are invalid");
  }
  if (value.artifactBytes !== undefined && (!Number.isSafeInteger(value.artifactBytes) || value.artifactBytes < 1)) {
    throw new Error("release manifest artifact byte count is invalid");
  }
  if (value.signature === null || typeof value.signature !== "object" || Array.isArray(value.signature)) {
    throw new Error("release manifest signature is malformed");
  }
  const signatureKeys = Object.keys(value.signature).sort();
  if (signatureKeys.length !== 3 || signatureKeys.some((key, index) => key !== ["cdHash", "identifier", "teamIdentifier"][index]) ||
      Object.values(value.signature).some((field) => typeof field !== "string")) {
    throw new Error("release manifest signature fields are malformed");
  }
}

function readArtifactIdentity(path, ownerUid) {
  let stats;
  try {
    stats = lstatSync(path);
  } catch {
    throw new Error("release artifact is unavailable");
  }
  if (!stats.isFile() || stats.uid !== ownerUid || (stats.mode & 0o022) !== 0) {
    throw new Error("release artifact must be an owner-only regular file");
  }
  return stats;
}

function isCanonicalAbsolutePath(path) {
  return typeof path === "string" && isAbsolute(path) && path !== "/" && !path.endsWith("/") &&
    !path.includes("\0") && !path.includes("\r") && !path.includes("\n") && resolve(path) === path;
}
