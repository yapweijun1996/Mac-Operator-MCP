import { lstatSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import {
  FilesystemInspector,
  type FilesystemIdentityPrecondition,
  type FilesystemPathPlan,
  type SafePathMetadata
} from "./filesystem-inspector.js";
import { assertContentDoesNotContainSecrets, assertSourceWritePathAllowed } from "./secret-policy.js";

const MAX_PATCH_BYTES = 524_288;
const MAX_PATCH_FILES = 64;
const MAX_PATCH_FILE_BYTES = 1_048_576;
const MAX_PATCH_TOTAL_BYTES = 8 * 1_048_576;
const MAX_PATCH_PATH_LENGTH = 4_096;
const PATCH_PATH_PATTERN = /^[^/\\\u0000\n][^\\\u0000\n]*$/u;

export interface FilesystemPatchFileResult {
  path: string;
  sha256: string;
  sizeBytes: number;
}

export interface FilesystemPatchResult {
  operation: "patch";
  projectRoot: string;
  result: "applied" | "no_change";
  changedPaths: readonly string[];
  precondition: {
    checked: boolean;
    expectedSha256: string | null;
    actualSha256: string;
    matched: boolean;
  };
  files: readonly FilesystemPatchFileResult[];
}

interface ParsedPatchFile {
  relativePath: string;
  kind: "update" | "add";
  hunks: readonly PatchHunk[];
}

interface PatchHunk {
  oldLines: readonly string[];
  newLines: readonly string[];
  changed: boolean;
}

interface PreparedPatchFile {
  relativePath: string;
  path: string;
  plan: FilesystemPathPlan;
  original: Buffer;
  originalDigest: string | null;
  originalIdentity: FilesystemIdentityPrecondition;
  next: Buffer;
}

/**
 * Apply a deliberately narrow textual patch inside one Broker-authorized
 * project root. The function performs all reads and patch matching before the
 * first write, binds each write to the observed file identity, and rolls back
 * already-applied files when a later write fails.
 */
export function applyFilesystemPatch(
  inspector: FilesystemInspector,
  projectRootPlan: FilesystemPathPlan,
  patchText: string,
  expectedBaseHash: string | undefined,
  temporaryNameFactory: () => string = () => `.mac-operator-write-patch-${cryptoRandomToken()}`,
  beforeMutation?: () => void
): FilesystemPatchResult {
  const parsed = parsePatch(patchText);
  assertContentDoesNotContainSecrets(Buffer.from(patchText, "utf8"));
  assertProjectRoot(inspector, projectRootPlan);

  const prepared: PreparedPatchFile[] = [];
  let totalBytes = 0;
  for (const file of parsed) {
    const path = join(projectRootPlan.requestedPath, file.relativePath);
    if (!isCanonicalContainedPath(projectRootPlan.requestedPath, path)) {
      throw new BrokerError("PATH_DENIED", "Patch path escaped the authorized project root");
    }
    const plan = inspector.planPath(path, "write");
    const current = readPatchTarget(inspector, plan);
    if (file.kind === "add" && current.digest !== null) {
      throw new BrokerError("PRECONDITION_FAILED", "Patch add target already exists");
    }
    const next = file.kind === "add"
      ? buildAddedFile(file)
      : applyUpdate(file, current.content);
    if (next.byteLength > MAX_PATCH_FILE_BYTES) {
      throw new BrokerError("OUTPUT_LIMIT", "Patched file exceeds the supported size");
    }
    assertSourceWritePathAllowed(path);
    assertContentDoesNotContainSecrets(next);
    totalBytes += next.byteLength;
    if (totalBytes > MAX_PATCH_TOTAL_BYTES) {
      throw new BrokerError("OUTPUT_LIMIT", "Patch output exceeds the supported size");
    }
    prepared.push({
      relativePath: file.relativePath,
      path,
      plan,
      original: current.content,
      originalDigest: current.digest,
      originalIdentity: current.identity,
      next
    });
  }

  const actualBaseHash = sha256(canonicalJson(prepared.map((file) => ({
    path: file.relativePath,
    present: file.originalDigest !== null,
    sha256: file.originalDigest
  }))));
  const normalizedExpected = expectedBaseHash?.toLowerCase() ?? null;
  const matched = normalizedExpected === null || normalizedExpected === actualBaseHash;
  if (!matched) throw new BrokerError("PRECONDITION_FAILED", "Patch base hash did not match");

  const changed = prepared.filter((file) => !file.next.equals(file.original));
  if (changed.length === 0) {
    return {
      operation: "patch",
      projectRoot: projectRootPlan.requestedPath,
      result: "no_change",
      changedPaths: [],
      precondition: { checked: normalizedExpected !== null, expectedSha256: normalizedExpected, actualSha256: actualBaseHash, matched },
      files: prepared.map((file) => fileResult(file.path, file.original))
    };
  }

  const applied: Array<{ file: PreparedPatchFile; identity: { device: string; inode: string } }> = [];
  try {
    for (const file of changed) {
      const write = inspector.writePlanned(
        file.plan,
        file.next,
        file.originalDigest ?? undefined,
        file.originalDigest === null,
        temporaryNameFactory(),
        file.originalIdentity,
        beforeMutation
      );
      applied.push({ file, identity: { device: write.device, inode: write.inode } });
    }
  } catch (error) {
    rollbackApplied(inspector, applied, temporaryNameFactory, beforeMutation);
    throw error instanceof BrokerError ? error : new BrokerError("UNKNOWN_OUTCOME", "Patch outcome could not be verified", true);
  }

  const files = prepared.map((file) => fileResult(file.path, file.next));
  return {
    operation: "patch",
    projectRoot: projectRootPlan.requestedPath,
    result: "applied",
    changedPaths: changed.map((file) => file.relativePath),
    precondition: { checked: normalizedExpected !== null, expectedSha256: normalizedExpected, actualSha256: actualBaseHash, matched },
    files
  };
}

function assertProjectRoot(inspector: FilesystemInspector, plan: FilesystemPathPlan): void {
  const metadata = inspector.statPlanned(plan, false);
  if (metadata.type !== "directory" || metadata.isSymlink) {
    throw new BrokerError("PRECONDITION_FAILED", "Patch project root must be a regular directory");
  }
}

function readPatchTarget(
  inspector: FilesystemInspector,
  plan: FilesystemPathPlan
): { content: Buffer; digest: string | null; identity: FilesystemIdentityPrecondition } {
  let metadata: SafePathMetadata | undefined;
  try {
    metadata = inspector.statPlanned(plan, false);
  } catch {
    if (!isMissingPath(plan.requestedPath)) {
      throw new BrokerError("POLICY_DENIED", "Patch target could not be inspected safely");
    }
  }
  if (metadata === undefined) {
    const parentPlan = inspector.planPath(dirname(plan.requestedPath), "write");
    const parent = inspector.statPlanned(parentPlan, false);
    if (parent.type !== "directory" || parent.isSymlink) {
      throw new BrokerError("POLICY_DENIED", "Patch target parent is not a regular directory");
    }
    return { content: Buffer.alloc(0), digest: null, identity: { present: false, device: "0", inode: "0" } };
  }
  if (metadata.type !== "file" || metadata.isSymlink) {
    throw new BrokerError("POLICY_DENIED", "Patch target must be a regular non-symlink file");
  }
  const read = inspector.readPlanned(plan, 0, MAX_PATCH_FILE_BYTES);
  if (read.truncated || read.sizeBytes > MAX_PATCH_FILE_BYTES) {
    throw new BrokerError("OUTPUT_LIMIT", "Patch source file exceeds the supported size");
  }
  try { new TextDecoder("utf-8", { fatal: true }).decode(read.content); }
  catch { throw new BrokerError("PRECONDITION_FAILED", "Patch source file must be valid UTF-8"); }
  if (read.content.includes(0)) throw new BrokerError("PRECONDITION_FAILED", "Patch source file must be textual");
  assertContentDoesNotContainSecrets(read.content);
  return {
    content: read.content,
    digest: sha256(read.content),
    identity: { present: true, device: read.device, inode: read.inode }
  };
}

function parsePatch(value: string): readonly ParsedPatchFile[] {
  if (typeof value !== "string" || value.length < 1 || Buffer.byteLength(value, "utf8") > MAX_PATCH_BYTES || value.includes("\0") || value.includes("\r")) {
    throw new BrokerError("PRECONDITION_FAILED", "Patch text is malformed");
  }
  const lines = value.split("\n");
  if (lines.at(-1) === "") lines.pop();
  if (lines.shift() !== "*** Begin Patch" || lines.pop() !== "*** End Patch" || lines.length === 0) {
    throw new BrokerError("PRECONDITION_FAILED", "Patch envelope is malformed");
  }
  const files: ParsedPatchFile[] = [];
  const seen = new Set<string>();
  let index = 0;
  while (index < lines.length) {
    const header = lines[index]!;
    const update = /^\*\*\* Update File: (.+)$/u.exec(header);
    const add = /^\*\*\* Add File: (.+)$/u.exec(header);
    if ((!update && !add) || files.length >= MAX_PATCH_FILES) {
      throw new BrokerError("PRECONDITION_FAILED", "Patch file header is unsupported");
    }
    const relativePath = (update?.[1] ?? add?.[1])!;
    validatePatchPath(relativePath);
    if (seen.has(relativePath)) throw new BrokerError("CONFLICT", "Patch contains a duplicate file target");
    seen.add(relativePath);
    index += 1;
    const body: string[] = [];
    while (index < lines.length && !lines[index]!.startsWith("*** ")) body.push(lines[index++]!);
    if (add) {
      if (body.length === 0 || body.some((line) => !line.startsWith("+"))) {
        throw new BrokerError("PRECONDITION_FAILED", "Patch add file body is malformed");
      }
      files.push({ relativePath, kind: "add", hunks: [{ oldLines: [], newLines: body.map((line) => line.slice(1)), changed: true }] });
    } else {
      files.push({ relativePath, kind: "update", hunks: parseHunks(body) });
    }
  }
  return files;
}

function parseHunks(lines: readonly string[]): readonly PatchHunk[] {
  const hunks: PatchHunk[] = [];
  let current: { oldLines: string[]; newLines: string[]; changed: boolean } | undefined;
  for (const line of lines) {
    if (line.startsWith("@@")) {
      if (current) hunks.push(current);
      current = { oldLines: [], newLines: [], changed: false };
      continue;
    }
    if (!current || line.length === 0 || ![" ", "+", "-"].includes(line[0]!)) {
      throw new BrokerError("PRECONDITION_FAILED", "Patch hunk is malformed");
    }
    const text = line.slice(1);
    if (line[0] === " ") { current.oldLines.push(text); current.newLines.push(text); }
    else if (line[0] === "-") { current.oldLines.push(text); current.changed = true; }
    else { current.newLines.push(text); current.changed = true; }
  }
  if (current) hunks.push(current);
  if (hunks.length === 0 || hunks.some((hunk) => !hunk.changed || hunk.oldLines.length === 0)) {
    throw new BrokerError("PRECONDITION_FAILED", "Patch must contain a bounded changed hunk");
  }
  return hunks;
}

function buildAddedFile(file: ParsedPatchFile): Buffer {
  const lines = file.hunks[0]!.newLines;
  return Buffer.from(`${lines.join("\n")}\n`, "utf8");
}

function applyUpdate(file: ParsedPatchFile, source: Buffer): Buffer {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(source);
  const finalNewline = text.endsWith("\n");
  const sourceLines = text.split("\n");
  if (finalNewline) sourceLines.pop();
  let cursor = 0;
  for (const hunk of file.hunks) {
    const matches: number[] = [];
    for (let index = cursor; index <= sourceLines.length - hunk.oldLines.length; index += 1) {
      if (hunk.oldLines.every((line, offset) => sourceLines[index + offset] === line)) matches.push(index);
    }
    if (matches.length !== 1) {
      throw new BrokerError("PRECONDITION_FAILED", matches.length === 0 ? "Patch hunk context did not match" : "Patch hunk context was ambiguous");
    }
    const at = matches[0]!;
    sourceLines.splice(at, hunk.oldLines.length, ...hunk.newLines);
    cursor = at + hunk.newLines.length;
  }
  const result = sourceLines.join("\n");
  return Buffer.from(finalNewline ? `${result}\n` : result, "utf8");
}

function fileResult(path: string, content: Buffer): FilesystemPatchFileResult {
  return { path, sha256: sha256(content), sizeBytes: content.byteLength };
}

function rollbackApplied(
  inspector: FilesystemInspector,
  applied: ReadonlyArray<{ file: PreparedPatchFile; identity: { device: string; inode: string } }>,
  temporaryNameFactory: () => string,
  beforeMutation?: () => void
): void {
  for (const { file, identity } of [...applied].reverse()) {
    try {
      if (file.originalDigest === null) {
        inspector.unlinkPlanned(
          file.plan,
          { present: true, device: identity.device, inode: identity.inode },
          beforeMutation
        );
      } else {
        inspector.writePlanned(
          file.plan,
          file.original,
          sha256(file.next),
          false,
          temporaryNameFactory(),
          { present: true, device: identity.device, inode: identity.inode },
          beforeMutation
        );
      }
    } catch {
      throw new BrokerError("UNKNOWN_OUTCOME", "Patch rollback could not be verified", true);
    }
  }
}

function validatePatchPath(value: string): void {
  if (typeof value !== "string" || value.length < 1 || value.length > MAX_PATCH_PATH_LENGTH ||
      !PATCH_PATH_PATTERN.test(value) || isAbsolute(value) ||
      value.split("/").some((part) => part === "" || part === "." || part === "..")) {
    throw new BrokerError("PATH_DENIED", "Patch paths must be non-empty relative paths");
  }
  if (isAbsolute(value) || resolve("/", value) !== `/${value}`) {
    throw new BrokerError("PATH_DENIED", "Patch paths must remain inside the project root");
  }
}

function isCanonicalContainedPath(root: string, target: string): boolean {
  if (resolve(root) !== root || resolve(target) !== target) return false;
  const child = relative(root, target);
  return child !== "" && !child.startsWith(`..${sep}`) && child !== ".." && !isAbsolute(child);
}

function isMissingPath(path: string): boolean {
  try {
    lstatSync(path);
    return false;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT";
  }
}

function cryptoRandomToken(): string {
  return randomUUID();
}
