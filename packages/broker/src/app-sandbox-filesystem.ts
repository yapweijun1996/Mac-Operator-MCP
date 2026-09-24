import { constants } from "node:fs";
import { mkdir, open, writeFile, type FileHandle } from "node:fs/promises";
import { isAbsolute, join, relative, resolve } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import { loadNativePeerAdapter } from "./peer-credentials.js";
import type { FilesystemNativeAdapter } from "./filesystem-inspector.js";
import { isPlainDataRecord } from "./plain-record.js";

export const APP_SANDBOX_STAGE_MAX_DEPTH = 16;
export const APP_SANDBOX_STAGE_MAX_ENTRIES = 10_000;
export const APP_SANDBOX_STAGE_MAX_BYTES = 64 * 1024 * 1024;
export const APP_SANDBOX_STAGE_MAX_FILE_BYTES = 16 * 1024 * 1024;
export const APP_SANDBOX_STAGE_READ_CHUNK_BYTES = 1024 * 1024;

export interface AppSandboxFilesystemStage {
  readonly stagedCwdHandle: FileHandle;
  readonly stagedRoot: string;
  readonly entryCount: number;
  readonly byteCount: number;
}

interface StageOptions {
  filesystemRoots: readonly string[];
  cwdPath: string;
  runDirectory: string;
}

interface NativeMetadata {
  rootPath: string;
  path: string;
  type: "file" | "directory" | "symlink" | "other";
  sizeBytes: number;
  mode: string;
  isSymlink: boolean;
}

interface NativeListingEntry {
  name: string;
  type: "file" | "directory" | "symlink" | "other";
  sizeBytes: number;
}

interface NativeListing {
  rootPath: string;
  path: string;
  entries: readonly NativeListingEntry[];
  nextCursor: string | null;
}

interface NativeRead {
  rootPath: string;
  path: string;
  content: Buffer;
  sizeBytes: number;
  truncated: boolean;
}

interface PendingDirectory {
  sourcePath: string;
  stagedPath: string;
  depth: number;
}

/**
 * Materialize authorized host roots into a private App Sandbox container run.
 * Reads cross the Broker/native root-bound adapter; the helper receives only
 * the staged cwd descriptor, so host root pathnames never cross the boundary.
 */
export async function stageAppSandboxFilesystem(options: StageOptions): Promise<AppSandboxFilesystemStage> {
  const roots = validateRoots(options.filesystemRoots, options.cwdPath, options.runDirectory);
  const native = loadNativePeerAdapter() as unknown as FilesystemNativeAdapter;
  const stagedRoot = join(options.runDirectory, "F");
  await mkdir(stagedRoot, { recursive: false, mode: 0o700 });

  let entryCount = 0;
  let byteCount = 0;
  let cwdCandidate: string | undefined;
  try {
    for (const [index, sourceRoot] of roots.entries()) {
      const rootMetadata = parseMetadata(native.statPathWithinRoot(sourceRoot, sourceRoot, false));
      if (rootMetadata.rootPath !== sourceRoot || rootMetadata.path !== sourceRoot ||
          rootMetadata.type !== "directory" || rootMetadata.isSymlink) {
        throw denied();
      }
      const destinationRoot = join(stagedRoot, `r${index}`);
      await mkdir(destinationRoot, { recursive: false, mode: 0o700 });
      const rootResult = await copyDirectoryTree(native, sourceRoot, destinationRoot, {
        entryCount,
        byteCount
      });
      entryCount = rootResult.entryCount;
      byteCount = rootResult.byteCount;
      if (isPathWithin(sourceRoot, options.cwdPath)) {
        cwdCandidate = join(destinationRoot, relative(sourceRoot, options.cwdPath));
      }
    }
    if (cwdCandidate === undefined || !isPathWithin(stagedRoot, cwdCandidate)) throw denied();
    const cwdMetadata = parseMetadata(native.statPathWithinRoot(
      roots.find((root) => isPathWithin(root, options.cwdPath))!, options.cwdPath, false
    ));
    if (cwdMetadata.type !== "directory" || cwdMetadata.isSymlink) throw denied();
    const stagedCwdHandle = await open(cwdCandidate, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    return Object.freeze({ stagedCwdHandle, stagedRoot, entryCount, byteCount });
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw denied();
  }
}

async function copyDirectoryTree(
  native: FilesystemNativeAdapter,
  sourceRoot: string,
  destinationRoot: string,
  initial: { entryCount: number; byteCount: number }
): Promise<{ entryCount: number; byteCount: number }> {
  const pending: PendingDirectory[] = [{ sourcePath: sourceRoot, stagedPath: destinationRoot, depth: 0 }];
  let entryCount = initial.entryCount;
  let byteCount = initial.byteCount;
  while (pending.length > 0) {
    const current = pending.shift()!;
    let cursor: string | undefined;
    do {
      const listing = parseListing(native.listDirectoryWithinRoot(
        sourceRoot,
        current.sourcePath,
        true,
        cursor,
        500,
        (canonicalPath) => isPathWithin(sourceRoot, canonicalPath)
      ));
      if (listing.rootPath !== sourceRoot || listing.path !== current.sourcePath) throw denied();
      for (const entry of listing.entries) {
        entryCount += 1;
        if (entryCount > APP_SANDBOX_STAGE_MAX_ENTRIES || !isSafeEntryName(entry.name) ||
            !Number.isSafeInteger(entry.sizeBytes) || entry.sizeBytes < 0) throw denied();
        const sourcePath = join(current.sourcePath, entry.name);
        const stagedPath = join(current.stagedPath, entry.name);
        if (!isPathWithin(sourceRoot, sourcePath) || !isPathWithin(destinationRoot, stagedPath)) throw denied();
        if (entry.type === "directory") {
          if (current.depth >= APP_SANDBOX_STAGE_MAX_DEPTH) throw denied();
          await mkdir(stagedPath, { recursive: false, mode: 0o700 });
          pending.push({ sourcePath, stagedPath, depth: current.depth + 1 });
          continue;
        }
        if (entry.type !== "file" || entry.sizeBytes > APP_SANDBOX_STAGE_MAX_FILE_BYTES) throw denied();
        const metadata = parseMetadata(native.statPathWithinRoot(sourceRoot, sourcePath, false));
        if (metadata.rootPath !== sourceRoot || metadata.path !== sourcePath || metadata.type !== "file" ||
            metadata.isSymlink || metadata.sizeBytes !== entry.sizeBytes) throw denied();
        if (byteCount + metadata.sizeBytes > APP_SANDBOX_STAGE_MAX_BYTES) throw denied();
        const content = await readStableFile(native, sourceRoot, sourcePath, metadata.sizeBytes);
        const mode = (parseInt(metadata.mode, 8) & 0o111) === 0 ? 0o600 : 0o700;
        await writeFile(stagedPath, content, { mode, flag: "wx" });
        byteCount += metadata.sizeBytes;
      }
      cursor = listing.nextCursor === null ? undefined : listing.nextCursor;
    } while (cursor !== undefined);
  }
  return { entryCount, byteCount };
}

async function readStableFile(
  native: FilesystemNativeAdapter,
  sourceRoot: string,
  sourcePath: string,
  expectedSize: number
): Promise<Buffer> {
  const content = Buffer.alloc(expectedSize);
  let offset = 0;
  while (offset < expectedSize) {
    const requested = Math.min(APP_SANDBOX_STAGE_READ_CHUNK_BYTES, expectedSize - offset);
    const read = parseRead(native.readFileWithinRoot(
      sourceRoot,
      sourcePath,
      offset,
      requested,
      (canonicalPath) => {
        if (!isPathWithin(sourceRoot, canonicalPath)) throw denied();
      }
    ));
    if (read.rootPath !== sourceRoot || read.path !== sourcePath || read.sizeBytes !== expectedSize ||
        read.content.byteLength === 0 || read.content.byteLength > requested ||
        (!read.truncated && offset + read.content.byteLength !== expectedSize)) throw denied();
    read.content.copy(content, offset);
    offset += read.content.byteLength;
  }
  return content;
}

function validateRoots(roots: readonly string[], cwdPath: string, runDirectory: string): readonly string[] {
  if (!Array.isArray(roots) || roots.length < 1 || roots.length > 32 ||
      !isCanonicalAbsolutePath(cwdPath) || !isCanonicalAbsolutePath(runDirectory)) throw denied();
  const validated = roots.map((root) => {
    if (!isCanonicalAbsolutePath(root)) throw denied();
    if (isPathWithin(root, runDirectory) || isPathWithin(runDirectory, root)) throw denied();
    return root;
  });
  for (let index = 0; index < validated.length; index += 1) {
    for (let other = index + 1; other < validated.length; other += 1) {
      if (isPathWithin(validated[index]!, validated[other]!) || isPathWithin(validated[other]!, validated[index]!)) throw denied();
    }
  }
  return validated;
}

function parseMetadata(value: unknown): NativeMetadata {
  if (!isPlainDataRecord(value) || typeof value.rootPath !== "string" || typeof value.path !== "string" ||
      typeof value.type !== "string" || !["file", "directory", "symlink", "other"].includes(value.type) ||
      !Number.isSafeInteger(value.sizeBytes) || (value.sizeBytes as number) < 0 ||
      typeof value.mode !== "string" || !/^[0-7]{4}$/u.test(value.mode) || typeof value.isSymlink !== "boolean") throw denied();
  return {
    rootPath: value.rootPath,
    path: value.path,
    type: value.type as NativeMetadata["type"],
    sizeBytes: value.sizeBytes as number,
    mode: value.mode,
    isSymlink: value.isSymlink
  };
}

function parseListing(value: unknown): NativeListing {
  if (!isPlainDataRecord(value) || typeof value.rootPath !== "string" || typeof value.path !== "string" ||
      !Array.isArray(value.entries) || value.entries.length > 500 ||
      (value.nextCursor !== null && typeof value.nextCursor !== "string")) throw denied();
  const entries = value.entries.map((entry) => {
    if (!isPlainDataRecord(entry) || typeof entry.name !== "string" || typeof entry.type !== "string" ||
        !["file", "directory", "symlink", "other"].includes(entry.type) || !Number.isSafeInteger(entry.sizeBytes)) throw denied();
    const sizeBytes = entry.sizeBytes as number;
    return { name: entry.name, type: entry.type as NativeListingEntry["type"], sizeBytes };
  });
  return { rootPath: value.rootPath, path: value.path, entries, nextCursor: value.nextCursor as string | null };
}

function parseRead(value: unknown): NativeRead {
  if (!isPlainDataRecord(value)) throw denied();
  const rootPath = value.rootPath;
  const path = value.path;
  const contentValue = value.content;
  const sizeValue = value.sizeBytes;
  const truncated = value.truncated;
  if (typeof rootPath !== "string" || typeof path !== "string" || !Buffer.isBuffer(contentValue) ||
      !Number.isSafeInteger(sizeValue) || (sizeValue as number) < 0 || typeof truncated !== "boolean") throw denied();
  const content = contentValue as Buffer;
  const sizeBytes = sizeValue as number;
  return {
    rootPath,
    path,
    content,
    sizeBytes,
    truncated
  };
}

function isSafeEntryName(name: string): boolean {
  return name.length > 0 && name.length <= 255 && name !== "." && name !== ".." &&
    !name.includes("\0") && !name.includes("/") && !name.includes("\\");
}

function isCanonicalAbsolutePath(path: string): boolean {
  return isAbsolute(path) && resolve(path) === path && !path.includes("\0") && !path.includes("\n");
}

function isPathWithin(root: string, target: string): boolean {
  return target === root || target.startsWith(root.endsWith("/") ? root : `${root}/`);
}

function denied(): BrokerError {
  return new BrokerError("POLICY_DENIED", "App Sandbox filesystem staging was denied");
}
