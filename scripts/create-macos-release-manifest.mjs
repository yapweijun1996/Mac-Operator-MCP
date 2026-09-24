import { lstatSync, writeFileSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { hasSafeParentChain } from "./safe-path-parent.mjs";

const DIGEST_PATTERN = /^[a-f0-9]{20,64}$/u;
const TEAM_IDENTIFIER_PATTERN = /^[A-Z0-9]{10}$/u;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;

try {
  const input = parseArguments(process.argv.slice(2));
  await assertManifestOutputBoundary(input.artifactPath, input.outputPath);
  const summary = await readReleaseArtifactSummary(input.artifactPath, input.ownerUid);
  const { runMacOsReleasePreflight } = await import("../packages/broker/dist/index.js");
  const evidence = await runMacOsReleasePreflight({
    artifactPath: input.artifactPath,
    artifactSha256: summary.sha256,
    artifactBytes: summary.bytes,
    ownerUid: input.ownerUid,
    signature: input.signature
  });
  const manifest = {
    artifactBytes: summary.bytes,
    artifactPath: input.artifactPath,
    artifactSha256: summary.sha256,
    ownerUid: input.ownerUid,
    signature: input.signature
  };
  writeManifest(input.outputPath, manifest);
  process.stdout.write(`${JSON.stringify({
    schemaVersion: "0.1",
    mechanism: "macos-release-manifest-v1",
    manifestPath: input.outputPath,
    artifactPath: summary.artifactPath,
    artifactSha256: summary.sha256,
    artifactBytes: summary.bytes,
    signature: input.signature,
    policy: evidence.policy,
    notarization: evidence.notarization
  })}\n`);
} catch (error) {
  const code = error !== null && typeof error === "object" && "code" in error && typeof error.code === "string"
    ? error.code
    : "RELEASE_MANIFEST_FAILED";
  const message = error instanceof Error ? error.message : "release manifest generation failed";
  process.stderr.write(`macOS release manifest ${code}: ${message}\n`);
  process.exitCode = 1;
}

function parseArguments(args) {
  if (args.length < 10 || args.length > 12 || args[0] !== "--artifact" || args[2] !== "--output" ||
      args[4] !== "--identifier" || args[6] !== "--team-identifier" || args[8] !== "--cdhash") {
    throw new Error("usage: node scripts/create-macos-release-manifest.mjs --artifact /absolute/path --output /absolute/path --identifier id --team-identifier TEAMID1234 --cdhash hex");
  }
  const artifactPath = parseCanonicalPath(args[1], "artifact path");
  const outputPath = parseCanonicalPath(args[3], "manifest path");
  if (artifactPath === outputPath) throw new Error("manifest path must differ from the artifact path");
  const ownerUid = process.getuid?.() ?? -1;
  if (!Number.isSafeInteger(ownerUid) || ownerUid < 1) throw new Error("a non-root owner UID is required");
  if (!IDENTIFIER_PATTERN.test(args[5] ?? "")) throw new Error("signature identifier is malformed");
  if (!TEAM_IDENTIFIER_PATTERN.test(args[7] ?? "")) throw new Error("signature Team ID is malformed");
  if (!DIGEST_PATTERN.test(args[9] ?? "")) throw new Error("signature CDHash is malformed");
  if (args.length === 12 && args[10] !== "--owner-uid") throw new Error("unsupported release manifest option");
  if (args.length === 12 && args[11] !== String(ownerUid)) throw new Error("release manifest owner UID must be the current owner UID");
  return {
    artifactPath,
    outputPath,
    ownerUid,
    signature: { cdHash: args[9], identifier: args[5], teamIdentifier: args[7] }
  };
}

function parseCanonicalPath(value, label) {
  if (typeof value !== "string" || !isAbsolute(value) || value === "/" || value.endsWith("/") ||
      value.includes("\0") || value.includes("\r") || value.includes("\n") || resolve(value) !== value) {
    throw new Error(`${label} must be a canonical absolute path`);
  }
  return value;
}

async function readReleaseArtifactSummary(artifactPath, ownerUid) {
  const parentPath = await realpath(dirname(artifactPath));
  const resolvedArtifact = await realpath(artifactPath);
  if (!isDescendantOrEqual(parentPath, resolvedArtifact)) throw new Error("artifact path escaped its parent");
  const { readMacOsReleaseArtifactSummary } = await import("../packages/broker/dist/index.js");
  return readMacOsReleaseArtifactSummary(artifactPath, ownerUid);
}

async function assertManifestOutputBoundary(artifactPath, outputPath) {
  const [artifactRealPath, outputParentRealPath] = await Promise.all([
    realpath(artifactPath),
    realpath(dirname(outputPath))
  ]);
  if (isDescendantOrEqual(artifactRealPath, outputParentRealPath)) {
    throw new Error("manifest output must be outside the canonical artifact tree");
  }
}

function writeManifest(outputPath, manifest) {
  let parent;
  try {
    parent = lstatSync(dirname(outputPath));
  } catch {
    throw new Error("manifest parent directory is unavailable");
  }
  const ownerUid = process.getuid?.() ?? -1;
  if (!parent.isDirectory() || parent.uid !== ownerUid || (parent.mode & 0o077) !== 0 ||
      !hasSafeParentChain(outputPath, ownerUid)) {
    throw new Error("manifest parent directory must be owner-only");
  }
  try {
    lstatSync(outputPath);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    writeFileSync(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
    const written = lstatSync(outputPath);
    if (!written.isFile() || written.uid !== ownerUid || (written.mode & 0o077) !== 0) {
      throw new Error("generated manifest did not retain owner-only permissions");
    }
    return;
  }
  throw new Error("manifest output already exists");
}

function isDescendantOrEqual(parent, child) {
  const suffix = relative(parent, child);
  return suffix === "" || (!suffix.startsWith("..") && !isAbsolute(suffix));
}
