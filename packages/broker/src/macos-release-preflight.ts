import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";
import {
  parseCodeSignatureDetails,
  validateCodeSignatureReadback,
  type CodeSignatureExpectation,
  type CodeSignatureReadback,
  type CodeSignatureDetailsCommandSpec,
  type CodeSignatureCommandSpec,
  type MacOsInstallCommandExecutor
} from "./macos-install-plan.js";
import {
  buildMacOsNotarizationAssessmentCommand,
  readMacOsNotarizationAssessment,
  type MacOsNotarizationReadback
} from "./macos-notarization.js";
import { ProcessSupervisor } from "./process-supervisor.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";
import { isPlainDataRecord } from "./plain-record.js";

const SERVICE_TIMEOUT_MS = 5_000 as const;
const SERVICE_OUTPUT_CAP_BYTES = 131_072 as const;
const MAX_ARTIFACT_ENTRIES = 16_384 as const;
const MAX_ARTIFACT_DEPTH = 64 as const;
const MAX_ARTIFACT_BYTES = 512 * 1024 * 1024;
const READ_CHUNK_BYTES = 1024 * 1024;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const MAX_COMPONENT_NAME_BYTES = 255;

export type MacOsReleasePreflightErrorCode =
  | "INVALID_ARGUMENT"
  | "INVALID_RELEASE_POLICY"
  | "ARTIFACT_UNAVAILABLE"
  | "ARTIFACT_CHANGED"
  | "ARTIFACT_UNSAFE"
  | "ARTIFACT_LIMIT"
  | "DIGEST_MISMATCH"
  | "SIGNATURE_MISMATCH"
  | "NOTARIZATION_MISMATCH";

export class MacOsReleasePreflightError extends Error {
  readonly code: MacOsReleasePreflightErrorCode;

  constructor(code: MacOsReleasePreflightErrorCode, message: string) {
    super(message);
    this.name = "MacOsReleasePreflightError";
    this.code = code;
  }
}

export interface MacOsReleasePreflightInput {
  /** Canonical signed .app, .pkg, or archive path; no caller-selected cwd. */
  artifactPath: string;
  /** Expected deterministic artifact-tree digest, never inferred from output. */
  artifactSha256: string;
  /** Expected total regular-file bytes in the artifact tree. */
  artifactBytes?: number;
  /** Every artifact entry must be owned by this non-negative UID. */
  ownerUid: number;
  /** Release builds are always Developer ID; ad-hoc is not a release policy. */
  signature: CodeSignatureExpectation;
}

export interface MacOsReleaseArtifactSummary {
  artifactPath: string;
  sha256: string;
  bytes: number;
  files: number;
  directories: number;
  device: string;
  inode: string;
  mode: number;
}

export interface MacOsReleasePreflightEvidence {
  artifact: MacOsReleaseArtifactSummary;
  signature: CodeSignatureReadback;
  notarization: MacOsNotarizationReadback;
  policy: "developer-id-notarized";
}

interface ArtifactCounts {
  files: number;
  directories: number;
  bytes: number;
}

interface ArtifactIdentity {
  device: number;
  inode: number;
  mode: number;
  uid: number;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
  isDirectory: boolean;
  isFile: boolean;
}

/**
 * Runs the complete read-only release gate. No plist, launchd, Keychain, or
 * process state is changed. Raw command output is parsed and discarded.
 */
export async function runMacOsReleasePreflight(
  input: MacOsReleasePreflightInput,
  executor: MacOsInstallCommandExecutor = new ProcessSupervisor({ allowedEnvironmentKeys: [] })
): Promise<MacOsReleasePreflightEvidence> {
  validateInput(input);
  if (executor === null || typeof executor !== "object" || typeof executor.run !== "function") {
    fail("INVALID_ARGUMENT", "release preflight executor is unavailable");
  }
  const artifact = await summarizeArtifact(input.artifactPath, input.ownerUid, input.artifactSha256, input.artifactBytes);
  const signature = await readReleaseSignature(input, executor);
  let notarization: MacOsNotarizationReadback;
  try {
    notarization = await readMacOsNotarizationAssessment(
      input.artifactPath,
      input.signature.teamIdentifier!,
      { run: async (command) => executor.run(command) }
    );
  } catch {
    fail("NOTARIZATION_MISMATCH", "release artifact is not accepted as notarized Developer ID code");
  }
  return { artifact, signature, notarization, policy: "developer-id-notarized" };
}

/** Read a deterministic, bounded artifact summary for release manifest generation. */
export async function readMacOsReleaseArtifactSummary(
  artifactPath: string,
  ownerUid: number
): Promise<MacOsReleaseArtifactSummary> {
  if (typeof artifactPath !== "string" || !isCanonicalArtifactPath(artifactPath)) {
    fail("INVALID_ARGUMENT", "release artifact path is not canonical");
  }
  if (!Number.isSafeInteger(ownerUid) || ownerUid < 0) {
    fail("INVALID_ARGUMENT", "release artifact owner UID is invalid");
  }
  return summarizeArtifact(artifactPath, ownerUid, undefined, undefined);
}

function validateInput(input: MacOsReleasePreflightInput): void {
  if (!isPlainDataRecord(input)) fail("INVALID_ARGUMENT", "release preflight input is malformed");
  const inputKeys = Object.keys(input).sort();
  const allowedInputKeys = ["artifactBytes", "artifactPath", "artifactSha256", "ownerUid", "signature"];
  if (inputKeys.length < 4 || inputKeys.length > allowedInputKeys.length || inputKeys.some((key) => !allowedInputKeys.includes(key))) {
    fail("INVALID_ARGUMENT", "release preflight input contains unsupported fields");
  }
  if (typeof input.artifactPath !== "string" || !isCanonicalArtifactPath(input.artifactPath)) {
    fail("INVALID_ARGUMENT", "release artifact path is not canonical");
  }
  if (typeof input.artifactSha256 !== "string" || !SHA256_PATTERN.test(input.artifactSha256)) {
    fail("INVALID_ARGUMENT", "release artifact digest is invalid");
  }
  if (input.artifactBytes !== undefined && (!Number.isSafeInteger(input.artifactBytes) || input.artifactBytes < 1 || input.artifactBytes > MAX_ARTIFACT_BYTES)) {
    fail("INVALID_ARGUMENT", "release artifact byte count is invalid");
  }
  if (!Number.isSafeInteger(input.ownerUid) || input.ownerUid < 0) {
    fail("INVALID_ARGUMENT", "release artifact owner UID is invalid");
  }
  if (!isPlainDataRecord(input.signature) ||
      typeof input.signature.identifier !== "string" ||
      typeof input.signature.teamIdentifier !== "string" ||
      typeof input.signature.cdHash !== "string") {
    fail("INVALID_RELEASE_POLICY", "release policy requires Developer ID identifier, Team ID, and CDHash");
  }
  const signatureKeys = Object.keys(input.signature).sort();
  if (signatureKeys.length !== 3 || signatureKeys.some((key, index) => key !== ["cdHash", "identifier", "teamIdentifier"][index])) {
    fail("INVALID_RELEASE_POLICY", "release policy contains unsupported signature fields");
  }
}

async function readReleaseSignature(
  input: MacOsReleasePreflightInput,
  executor: MacOsInstallCommandExecutor
): Promise<CodeSignatureReadback> {
  let verification: ProcessExecutionResult;
  let details: ProcessExecutionResult;
  try {
    verification = await executor.run(codesignVerifyCommand(input.artifactPath));
    if (verification.resultClass !== "SUCCEEDED" || verification.truncated) {
      fail("SIGNATURE_MISMATCH", "release artifact code signature verification failed");
    }
    details = await executor.run(codesignDetailsCommand(input.artifactPath));
  } catch (error) {
    if (error instanceof MacOsReleasePreflightError) throw error;
    fail("SIGNATURE_MISMATCH", "release artifact code signature readback failed");
  }
  if (details.resultClass !== "SUCCEEDED" || details.truncated) {
    fail("SIGNATURE_MISMATCH", "release artifact code signature details failed");
  }
  let parsed: ReturnType<typeof parseCodeSignatureDetails>;
  try {
    parsed = parseCodeSignatureDetails(`${details.stdout}\n${details.stderr}`);
    if (parsed.signatureType !== "developer-id") fail("SIGNATURE_MISMATCH", "ad-hoc code signatures are not release eligible");
  } catch (error) {
    if (error instanceof MacOsReleasePreflightError) throw error;
    fail("SIGNATURE_MISMATCH", "release artifact code signature provenance is invalid");
  }
  const readback: CodeSignatureReadback = { artifactPath: input.artifactPath, valid: true, ...parsed };
  try {
    validateCodeSignatureReadback(input.signature, readback, input.artifactPath);
  } catch {
    fail("SIGNATURE_MISMATCH", "release artifact signature identity does not match policy");
  }
  return readback;
}

function codesignVerifyCommand(path: string): CodeSignatureCommandSpec {
  return {
    executable: "/usr/bin/codesign",
    args: ["--verify", "--strict", "--deep", path],
    cwd: "/",
    environment: {},
    timeoutMs: SERVICE_TIMEOUT_MS,
    outputCapBytes: SERVICE_OUTPUT_CAP_BYTES
  };
}

function codesignDetailsCommand(path: string): CodeSignatureDetailsCommandSpec {
  return {
    executable: "/usr/bin/codesign",
    args: ["-dv", "--verbose=4", path],
    cwd: "/",
    environment: {},
    timeoutMs: SERVICE_TIMEOUT_MS,
    outputCapBytes: SERVICE_OUTPUT_CAP_BYTES
  };
}

async function summarizeArtifact(
  artifactPath: string,
  ownerUid: number,
  expectedSha256: string | undefined,
  expectedBytes: number | undefined
): Promise<MacOsReleaseArtifactSummary> {
  const digest = createHash("sha256");
  const counts: ArtifactCounts = { files: 0, directories: 0, bytes: 0 };
  let entries = 0;
  let root: ArtifactIdentity;
  try {
    root = await readArtifactIdentity(artifactPath, ownerUid);
  } catch (error) {
    if (error instanceof MacOsReleasePreflightError) throw error;
    fail("ARTIFACT_UNAVAILABLE", "release artifact could not be inspected");
  }
  const rootRealPath = await readArtifactRealPath(artifactPath, artifactPath);
  await walkArtifact(artifactPath, "", root, rootRealPath, ownerUid, digest, counts, () => {
    entries += 1;
    if (entries > MAX_ARTIFACT_ENTRIES) fail("ARTIFACT_LIMIT", "release artifact entry budget exceeded");
  });
  const finalRoot = await readArtifactIdentity(artifactPath, ownerUid);
  assertIdentityStable(root, finalRoot);
  const finalRootRealPath = await readArtifactRealPath(artifactPath, rootRealPath);
  if (finalRootRealPath !== rootRealPath) fail("ARTIFACT_CHANGED", "release artifact root target changed during hashing");
  if (counts.files === 0 || counts.bytes < 1 || counts.bytes > MAX_ARTIFACT_BYTES) {
    fail("ARTIFACT_LIMIT", "release artifact has no bounded file payload");
  }
  if (expectedBytes !== undefined && counts.bytes !== expectedBytes) {
    fail("DIGEST_MISMATCH", "release artifact byte count does not match the expected summary");
  }
  const sha256 = digest.digest("hex");
  if (expectedSha256 !== undefined && sha256 !== expectedSha256) fail("DIGEST_MISMATCH", "release artifact digest does not match the expected summary");
  return {
    artifactPath,
    sha256,
    bytes: counts.bytes,
    files: counts.files,
    directories: counts.directories,
    device: String(root.device),
    inode: String(root.inode),
    mode: root.mode & 0o777
  };
}

async function walkArtifact(
  path: string,
  relativePath: string,
  identity: ArtifactIdentity,
  expectedRealPath: string,
  ownerUid: number,
  digest: ReturnType<typeof createHash>,
  counts: ArtifactCounts,
  countEntry: () => void
): Promise<void> {
  const depth = relativePath.length === 0 ? 0 : relativePath.split("/").length;
  if (depth > MAX_ARTIFACT_DEPTH) fail("ARTIFACT_LIMIT", "release artifact depth budget exceeded");
  countEntry();
  if (identity.isFile) {
    const contentDigest = await hashRegularFile(path, identity, expectedRealPath, ownerUid, counts);
    digest.update(`F\\0${relativePath}\\0${identity.mode & 0o777}\\0${identity.size}\\0${contentDigest}\\n`, "utf8");
    return;
  }
  counts.directories += 1;
  digest.update(`D\\0${relativePath}\\0${identity.mode & 0o777}\\n`, "utf8");
  let names: string[];
  try {
    names = (await readdir(path)).sort();
  } catch {
    fail("ARTIFACT_UNAVAILABLE", "release artifact directory could not be read");
  }
  for (const name of names) {
    if (Buffer.byteLength(name, "utf8") > MAX_COMPONENT_NAME_BYTES || name === "." || name === ".." || name.includes("\0") || name.includes("\r") || name.includes("\n") || name.includes("/")) {
      fail("ARTIFACT_UNSAFE", "release artifact contains an invalid entry name");
    }
    const childRelative = relativePath.length === 0 ? name : `${relativePath}/${name}`;
    const childPath = resolve(path, name);
    if (!isDescendantOrEqual(path, childPath)) fail("ARTIFACT_UNSAFE", "release artifact escaped its inspected root");
    const childIdentity = await readArtifactIdentity(childPath, ownerUid);
    const childRealPath = await readArtifactRealPath(childPath, expectedRealPath);
    await walkArtifact(childPath, childRelative, childIdentity, childRealPath, ownerUid, digest, counts, countEntry);
  }
  const finalIdentity = await readArtifactIdentity(path, ownerUid);
  assertIdentityStable(identity, finalIdentity);
  const finalRealPath = await readArtifactRealPath(path, expectedRealPath);
  if (finalRealPath !== expectedRealPath) fail("ARTIFACT_CHANGED", "release artifact directory target changed during hashing");
}

async function hashRegularFile(path: string, expected: ArtifactIdentity, expectedRealPath: string, ownerUid: number, counts: ArtifactCounts): Promise<string> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    const realPathBeforeOpen = await readArtifactRealPath(path, expectedRealPath);
    if (realPathBeforeOpen !== expectedRealPath) fail("ARTIFACT_CHANGED", "release artifact file target changed before hashing");
    handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const opened = toArtifactIdentity(await handle.stat());
    assertIdentityStable(expected, opened);
    if (!opened.isFile || opened.uid !== ownerUid) fail("ARTIFACT_UNSAFE", "release artifact file identity is unsafe");
    const digest = createHash("sha256");
    const buffer = Buffer.allocUnsafe(READ_CHUNK_BYTES);
    let offset = 0;
    while (offset < opened.size) {
      const readSize = Math.min(buffer.byteLength, opened.size - offset);
      const result = await handle.read(buffer, 0, readSize, offset);
      if (result.bytesRead === 0) fail("ARTIFACT_CHANGED", "release artifact file ended before its expected size");
      digest.update(buffer.subarray(0, result.bytesRead));
      offset += result.bytesRead;
    }
    const after = toArtifactIdentity(await handle.stat());
    assertIdentityStable(expected, after);
    const realPathAfterRead = await readArtifactRealPath(path, expectedRealPath);
    if (realPathAfterRead !== expectedRealPath) fail("ARTIFACT_CHANGED", "release artifact file target changed during hashing");
    counts.files += 1;
    counts.bytes += opened.size;
    if (counts.bytes > MAX_ARTIFACT_BYTES) fail("ARTIFACT_LIMIT", "release artifact byte budget exceeded");
    return digest.digest("hex");
  } catch (error) {
    if (error instanceof MacOsReleasePreflightError) throw error;
    fail("ARTIFACT_CHANGED", "release artifact file changed during hashing");
  } finally {
    await handle?.close().catch(() => undefined);
  }
  return fail("ARTIFACT_CHANGED", "release artifact file could not be hashed");
}

async function readArtifactIdentity(path: string, ownerUid: number): Promise<ArtifactIdentity> {
  let stats;
  try {
    stats = await lstat(path);
  } catch {
    fail("ARTIFACT_UNAVAILABLE", "release artifact entry is unavailable");
  }
  const identity = toArtifactIdentity(stats);
  if (!identity.isFile && !identity.isDirectory) fail("ARTIFACT_UNSAFE", "release artifact contains a special file");
  if (identity.uid !== ownerUid) fail("ARTIFACT_UNSAFE", "release artifact owner does not match the release owner");
  if ((identity.mode & 0o022) !== 0) fail("ARTIFACT_UNSAFE", "release artifact is writable by group or other users");
  return identity;
}

function toArtifactIdentity(stats: { dev: number; ino: number; mode: number; uid: number; size: number; mtimeMs: number; ctimeMs: number; isDirectory(): boolean; isFile(): boolean }): ArtifactIdentity {
  return {
    device: stats.dev,
    inode: stats.ino,
    mode: stats.mode,
    uid: stats.uid,
    size: stats.size,
    mtimeMs: stats.mtimeMs,
    ctimeMs: stats.ctimeMs,
    isDirectory: stats.isDirectory(),
    isFile: stats.isFile()
  };
}

function assertIdentityStable(expected: ArtifactIdentity, actual: ArtifactIdentity): void {
  if (expected.device !== actual.device || expected.inode !== actual.inode || expected.uid !== actual.uid ||
      expected.mode !== actual.mode || expected.size !== actual.size || expected.mtimeMs !== actual.mtimeMs ||
      expected.ctimeMs !== actual.ctimeMs || expected.isDirectory !== actual.isDirectory || expected.isFile !== actual.isFile) {
    fail("ARTIFACT_CHANGED", "release artifact identity changed during preflight");
  }
}

function isCanonicalArtifactPath(path: string): boolean {
  return isAbsolute(path) && path !== "/" && !path.endsWith("/") && !path.includes("\0") && !path.includes("\r") && !path.includes("\n") && resolve(path) === path;
}

async function readArtifactRealPath(path: string, expectedRootOrPath: string): Promise<string> {
  let resolvedPath: string;
  try {
    resolvedPath = await realpath(path);
  } catch {
    fail("ARTIFACT_UNAVAILABLE", "release artifact target could not be canonicalized");
  }
  const root = expectedRootOrPath === path ? resolvedPath : expectedRootOrPath;
  if (!isDescendantOrEqual(root, resolvedPath)) fail("ARTIFACT_UNSAFE", "release artifact target escaped its inspected root");
  return resolvedPath;
}

function isDescendantOrEqual(root: string, target: string): boolean {
  const child = relative(root, target);
  return child.length === 0 || (child !== ".." && !child.startsWith("../") && !child.startsWith("/"));
}

function fail(code: MacOsReleasePreflightErrorCode, message: string): never {
  throw new MacOsReleasePreflightError(code, message);
}
