import { readFile } from "node:fs/promises";
import { lstatSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const MAX_MANIFEST_BYTES = 64 * 1024;
const manifestPath = parseManifestPath(process.argv.slice(2));
const manifest = await readManifest(manifestPath);

try {
  const { runMacOsReleasePreflight } = await import("../packages/broker/dist/index.js");
  const evidence = await runMacOsReleasePreflight(manifest);
  process.stdout.write(`${JSON.stringify(evidence)}\n`);
} catch (error) {
  const code = error !== null && typeof error === "object" && "code" in error && typeof error.code === "string"
    ? error.code
    : "RELEASE_PREFLIGHT_FAILED";
  const message = error instanceof Error ? error.message : "release preflight failed";
  process.stderr.write(`macOS release preflight ${code}: ${message}\n`);
  process.exitCode = 1;
}

function parseManifestPath(args) {
  if (args.length !== 2 || args[0] !== "--manifest" || typeof args[1] !== "string") {
    throw new Error("usage: node scripts/verify-macos-release.mjs --manifest /absolute/path/release-manifest.json");
  }
  const path = args[1];
  if (!isAbsolute(path) || path === "/" || path.endsWith("/") || path.includes("\0") || resolve(path) !== path) {
    throw new Error("release manifest path must be a canonical absolute path");
  }
  return path;
}

async function readManifest(path) {
  let stats;
  try {
    stats = lstatSync(path);
  } catch {
    throw new Error("release manifest is unavailable");
  }
  const ownerUid = process.getuid?.() ?? -1;
  if (!stats.isFile() || stats.uid !== ownerUid || (stats.mode & 0o022) !== 0) {
    throw new Error("release manifest must be an owner-only regular file");
  }
  let bytes;
  try {
    bytes = await readFile(path);
  } catch {
    throw new Error("release manifest could not be read");
  }
  if (bytes.byteLength > MAX_MANIFEST_BYTES) throw new Error("release manifest exceeds its size budget");
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
  if (keys.length < 4 || keys.length > allowed.length || keys.some((key) => !allowed.includes(key))) throw new Error("release manifest contains unsupported fields");
  if (value.signature === null || typeof value.signature !== "object" || Array.isArray(value.signature)) throw new Error("release manifest signature is malformed");
  const signatureKeys = Object.keys(value.signature).sort();
  if (signatureKeys.length !== 3 || signatureKeys.some((key, index) => key !== ["cdHash", "identifier", "teamIdentifier"][index])) {
    throw new Error("release manifest signature fields are malformed");
  }
}
