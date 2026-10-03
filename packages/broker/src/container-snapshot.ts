import { randomBytes } from "node:crypto";
import { setImmediate as yieldToEventLoop } from "node:timers/promises";
import { lstatSync, realpathSync } from "node:fs";
import { dirname, join, posix } from "node:path";
import { BrokerError, sha256 } from "@mac-operator/contracts";
import { FilesystemInspector } from "./filesystem-inspector.js";
import { loadNativePeerAdapter } from "./peer-credentials.js";
import { assertContentDoesNotContainSecrets, assertContentPathAllowed, assertSourceWritePathAllowed } from "./secret-policy.js";

const BLOCK = 512;
const MAX_FILES = 10_000;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;
const EXCLUDED_DIRECTORIES = new Set([".git", "node_modules", ".cache", "coverage", "dist", ".next", ".venv", "venv", "__pycache__"]);
const decoder = new TextDecoder("utf-8", { fatal: true });

export interface SnapshotFile { path: string; content: Buffer; sha256: string; }
export interface ContainerSnapshot {
  root: string;
  files: readonly SnapshotFile[];
  excluded: readonly string[];
  archive: Buffer;
}

/** A snapshot carries only regular project files, never host links or Git authority. */
export function snapshotWorktree(root: string, readonlyWorkspace = false, excludedPaths: readonly string[] = []): ContainerSnapshot {
  const steps = snapshotSteps(root, readonlyWorkspace, excludedPaths);
  let step = steps.next();
  while (!step.done) step = steps.next();
  return step.value;
}

/** Yield between descriptor-backed reads so job authority, cancellation and health remain live. */
export async function snapshotWorktreeAsync(root: string, readonlyWorkspace = false, excludedPaths: readonly string[] = [], check: () => void = () => {}): Promise<ContainerSnapshot> {
  const steps = snapshotSteps(root, readonlyWorkspace, excludedPaths);
  try {
    let step = steps.next();
    while (!step.done) {
      await yieldToEventLoop();
      check();
      step = steps.next();
    }
    check();
    return step.value;
  } finally { steps.return(undefined as never); }
}

function* snapshotSteps(root: string, readonlyWorkspace: boolean, excludedPaths: readonly string[]): Generator<void, ContainerSnapshot> {
  if (!Array.isArray(excludedPaths) || excludedPaths.length > 64 || new Set(excludedPaths).size !== excludedPaths.length ||
      excludedPaths.some(path => typeof path !== "string" || !safeSnapshotPath(path))) deny("Snapshot exclusions must be approved relative source paths");
  const exclusions = [...excludedPaths];
  const inspector = scopedInspector(root);
  const identity = inspector.statPath(root, false);
  if (identity.type !== "directory" || identity.isSymlink || identity.path !== root) deny("Snapshot root must be a canonical directory");
  const pending = [""];
  const files: SnapshotFile[] = [];
  const directories: string[] = [];
  const excluded: string[] = [];
  let bytes = 0;
  while (pending.length) {
    const directory = pending.shift()!;
    let cursor: string | undefined;
    do {
      const listing = inspector.listPlanned(inspector.planPath(join(root, directory)), cursor, 500, true);
      for (const entry of listing.entries) {
        yield;
        if (files.length + directories.length + excluded.length >= MAX_FILES) limit("Snapshot exceeds its entry budget");
        const path = directory ? `${directory}/${entry.name}` : entry.name;
        if (exclusions.some(excluded => path === excluded || path.startsWith(`${excluded}/`)) || !safeSnapshotPath(path) || EXCLUDED_DIRECTORIES.has(entry.name)) { excluded.push(path); continue; }
        if (entry.type === "symlink" || entry.type === "other") { excluded.push(path); continue; }
        if (entry.type === "directory") { directories.push(path); pending.push(path); }
        else {
          const plan = inspector.planPath(join(root, path), "content_read");
          const chunks: Buffer[] = [];
          const first = inspector.readPlanned(plan, 0, 1_048_576);
          if (first.sizeBytes > MAX_FILE_BYTES) limit("Snapshot file exceeds its byte budget");
          chunks.push(first.content);
          for (let offset = first.content.length; offset < first.sizeBytes;) {
            const next = inspector.readPlanned(plan, offset, 1_048_576);
            if (!next.content.length || next.sizeBytes !== first.sizeBytes || next.device !== first.device || next.inode !== first.inode) deny("Snapshot file changed during read");
            chunks.push(next.content); offset += next.content.length;
          }
          const content = Buffer.concat(chunks);
          const hash = inspector.hashPlanned(plan, "sha256");
          if (hash.device !== first.device || hash.inode !== first.inode || hash.digest !== sha256(content)) deny("Snapshot file changed during read");
          try { assertContentDoesNotContainSecrets(content); }
          catch { excluded.push(path); continue; }
          bytes += content.length;
          if (files.length + directories.length >= MAX_FILES || bytes > MAX_ARCHIVE_BYTES / 2) limit("Snapshot exceeds its entry or byte budget");
          files.push({ path, content, sha256: hash.digest });
        }
      }
      cursor = listing.nextCursor ?? undefined;
    } while (cursor !== undefined);
  }
  const current = inspector.statPath(root, false);
  if (identity.device !== current.device || identity.inode !== current.inode) deny("Snapshot root identity changed");
  const archive = createWorkspaceArchive(files, directories, readonlyWorkspace);
  return { root, files, excluded, archive };
}

/** Construct the small USTAR subset accepted by the task input boundary. */
export function createWorkspaceArchive(files: readonly Pick<SnapshotFile, "path" | "content">[], directories: readonly string[] = [], readonlyWorkspace = false): Buffer {
  if (files.length + directories.length > MAX_FILES) limit("Archive has too many entries");
  const chunks: Buffer[] = [];
  const seen = new Set<string>();
  let total = 2 * BLOCK;
  for (const entry of [...directories.map(path => ({ path, directory: true, content: Buffer.alloc(0) })),
    ...files.map(file => ({ ...file, directory: false }))]) {
    if (!safeSnapshotPath(entry.path) || seen.has(entry.path)) deny("Archive input path is forbidden or duplicated");
    seen.add(entry.path);
    const bytes = entry.directory ? Buffer.alloc(0) : entry.content;
    if (!Buffer.isBuffer(bytes) || bytes.length > MAX_FILE_BYTES) limit("Archive file is invalid or too large");
    assertContentDoesNotContainSecrets(bytes);
    const header = Buffer.alloc(BLOCK);
    const name = entry.directory ? `${entry.path}/` : entry.path;
    writeTarName(header, name);
    writeOctal(header, 100, 8, entry.directory ? readonlyWorkspace ? 0o555 : 0o700 : readonlyWorkspace ? 0o444 : 0o600);
    writeOctal(header, 108, 8, readonlyWorkspace ? 0 : 65532);
    writeOctal(header, 116, 8, readonlyWorkspace ? 0 : 65532);
    writeOctal(header, 124, 12, bytes.length);
    writeOctal(header, 136, 12, 0);
    header.fill(32, 148, 156);
    header[156] = entry.directory ? 53 : 48;
    header.write("ustar\0", 257, "ascii"); header.write("00", 263, "ascii");
    writeOctal(header, 148, 8, header.reduce((sum, byte) => sum + byte, 0));
    chunks.push(header, bytes);
    const padding = (BLOCK - bytes.length % BLOCK) % BLOCK;
    if (padding) chunks.push(Buffer.alloc(padding));
    total += BLOCK + bytes.length + padding;
    if (total > MAX_ARCHIVE_BYTES) limit("Archive exceeds its byte budget");
  }
  chunks.push(Buffer.alloc(2 * BLOCK));
  return Buffer.concat(chunks, total);
}

/** Parse bytes without ever extracting a path on the host. */
export function parseWorkspaceArchive(archive: Buffer, stripWorkspacePrefix = true): readonly SnapshotFile[] {
  if (!Buffer.isBuffer(archive) || archive.length < 2 * BLOCK || archive.length > MAX_ARCHIVE_BYTES || archive.length % BLOCK !== 0) deny("Output archive framing is invalid");
  const files: SnapshotFile[] = [];
  const seen = new Set<string>();
  let offset = 0; let terminated = false;
  while (offset + BLOCK <= archive.length) {
    const header = archive.subarray(offset, offset + BLOCK);
    if (header.every(byte => byte === 0)) {
      if (offset + 2 * BLOCK > archive.length || !archive.subarray(offset).every(byte => byte === 0)) deny("Archive trailer is invalid");
      terminated = true; break;
    }
    const checksum = tarNumber(header, 148, 8);
    const actual = header.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
    if (actual !== checksum || tarText(header, 257, 6) !== "ustar") deny("Archive checksum or format is invalid");
    const prefix = tarText(header, 345, 155);
    const raw = `${prefix ? `${prefix}/` : ""}${tarText(header, 0, 100)}`;
    const type = header[156];
    const size = tarNumber(header, 124, 12);
    const mode = tarNumber(header, 100, 8);
    if (size > MAX_FILE_BYTES || size < 0 || offset + BLOCK + size > archive.length || mode & 0o7000) deny("Archive content budget or mode is invalid");
    if (type !== 48 && type !== 0 && type !== 53 || tarText(header, 157, 100) !== "") deny("Archive links, special files and extensions are forbidden");
    const relative = !stripWorkspacePrefix ? raw : raw === "workspace/" || raw === "workspace" ? "" : raw.startsWith("workspace/") ? raw.slice(10) : raw;
    const path = type === 53 ? relative.replace(/\/$/u, "") : relative;
    if (path === "" && type !== 53 || path && (!safeSnapshotPath(path) || seen.has(path))) deny("Archive path is forbidden or duplicated");
    if (path) seen.add(path);
    if (seen.size > MAX_FILES) limit("Output archive has too many entries");
    if (type === 53) { if (size !== 0) deny("Archive directory contains data"); }
    else {
      const content = Buffer.from(archive.subarray(offset + BLOCK, offset + BLOCK + size));
      assertContentDoesNotContainSecrets(content);
      files.push({ path, content, sha256: sha256(content) });
    }
    offset += BLOCK + Math.ceil(size / BLOCK) * BLOCK;
  }
  if (!terminated) deny("Output archive has no complete trailer");
  return files;
}

/** Validate the whole delta before changing one source file. */
export function importWorkspaceChanges(snapshot: ContainerSnapshot, output: readonly SnapshotFile[], allowedPaths: readonly string[] = [],
  hooks: { beforeWrite?: () => void; onWriteIntent?: (path: string) => void; onChangedPath?: (path: string) => void } = {}): readonly string[] {
  const inspector = scopedInspector(snapshot.root);
  const prior = new Map(snapshot.files.map(file => [file.path, file]));
  const next = new Map<string, SnapshotFile>();
  for (const file of output) {
    if (!safeSnapshotPath(file.path) || next.has(file.path) || sha256(file.content) !== file.sha256) deny("Output delta path/content is invalid");
    assertSourceWritePathAllowed(join(snapshot.root, file.path));
    assertContentDoesNotContainSecrets(file.content);
    next.set(file.path, file);
  }
  for (const path of prior.keys()) if (!next.has(path)) deny("Source deletion is not supported by the atomic import boundary");
  const changed = output.filter(file => prior.get(file.path)?.sha256 !== file.sha256);
  const missingDirectories = new Set<string>();
  for (const file of changed) {
    if (file.content.length > 1_048_576) limit("Source import exceeds atomic write limit");
    if (allowedPaths.length && !allowedPaths.some(path => file.path === path || file.path.startsWith(`${path}/`))) deny("Output changed a path outside allowed_paths");
    const before = prior.get(file.path);
    const plan = inspector.planPath(join(snapshot.root, file.path), "write");
    if (before) {
      const current = inspector.hashPlanned(plan, "sha256");
      if (current.digest !== before.sha256) deny("Worktree changed since task snapshot");
    } else {
      assertAbsent(join(snapshot.root, file.path));
    }
    let parent = dirname(join(snapshot.root, file.path));
    while (parent !== snapshot.root) {
      try {
        const metadata = lstatSync(parent);
        if (!metadata.isDirectory() || metadata.isSymbolicLink() || realpathSync.native(parent) !== parent) deny("Import parent is not a canonical directory");
        break;
      } catch (error) {
        if (!isMissing(error)) throw error;
        missingDirectories.add(parent);
        parent = dirname(parent);
      }
    }
  }
  const native = loadNativePeerAdapter() as unknown as { createDirectoryWithinRoot?: (root: string, target: string, authorize: (path: string) => void) => unknown };
  if (missingDirectories.size && typeof native.createDirectoryWithinRoot !== "function") deny("Native directory import boundary is unavailable");
  for (const directory of [...missingDirectories].sort((a, b) => a.split("/").length - b.split("/").length)) {
    hooks.beforeWrite?.();
    hooks.onWriteIntent?.(directory.slice(snapshot.root.length + 1));
    const result = native.createDirectoryWithinRoot!(snapshot.root, directory, path => {
      hooks.beforeWrite?.();
      if (path !== directory || !path.startsWith(`${snapshot.root}/`)) deny("Import directory canonical identity changed");
      assertSourceWritePathAllowed(path);
    }) as { path?: string; rootPath?: string };
    if (result.path !== directory || result.rootPath !== snapshot.root) deny("Import directory read-back failed");
    hooks.onChangedPath?.(directory.slice(snapshot.root.length + 1));
  }
  for (const file of changed) {
    const before = prior.get(file.path);
    hooks.beforeWrite?.();
    hooks.onWriteIntent?.(file.path);
    inspector.writePlanned(inspector.planPath(join(snapshot.root, file.path), "write"), file.content,
      before?.sha256, before === undefined, `.mac-operator-write-${randomBytes(16).toString("hex")}`, undefined, hooks.beforeWrite);
    hooks.onChangedPath?.(file.path);
  }
  return changed.map(file => file.path);
}

function isMissing(error: unknown): boolean { return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT"; }
function assertAbsent(path: string): void {
  try { lstatSync(path); }
  catch (error) { if (isMissing(error)) return; throw error; }
  deny("New output target already exists");
}

export function safeSnapshotPath(path: string): boolean {
  if (typeof path !== "string" || path.length < 1 || Buffer.byteLength(path) > 240 || posix.normalize(path) !== path ||
      path.startsWith("/") || path.split("/").some(part => !part || part === "." || part === ".." || part === ".git") || /[\x00-\x1f\\]/u.test(path)) return false;
  try { assertContentPathAllowed(`/workspace/${path}`); assertSourceWritePathAllowed(`/workspace/${path}`); return true; }
  catch { return false; }
}

function scopedInspector(root: string): FilesystemInspector {
  return new FilesystemInspector([{ rootId: "container-task", path: root, metadata: true, contentRead: true, write: true, denyRelativePaths: [".git"] }]);
}
function tarText(header: Buffer, offset: number, width: number): string {
  const bytes = header.subarray(offset, offset + width); const end = bytes.indexOf(0);
  if (end >= 0 && bytes.subarray(end).some(byte => byte !== 0)) deny("Archive text padding is invalid");
  try { return decoder.decode(end < 0 ? bytes : bytes.subarray(0, end)); } catch { return deny("Archive text encoding is invalid"); }
}
function tarNumber(header: Buffer, offset: number, width: number): number {
  const raw = header.subarray(offset, offset + width).toString("ascii").replace(/[\x00 ]+$/u, "").trim();
  if (!/^[0-7]+$/u.test(raw)) deny("Archive numeric field is invalid");
  const value = Number.parseInt(raw, 8); if (!Number.isSafeInteger(value)) deny("Archive numeric field overflows"); return value;
}
function writeOctal(header: Buffer, offset: number, width: number, value: number): void {
  const text = value.toString(8).padStart(width - 1, "0"); if (text.length >= width) limit("Archive numeric value overflows"); header.write(`${text}\0`, offset, width, "ascii");
}
function writeTarName(header: Buffer, path: string): void {
  if (Buffer.byteLength(path) <= 100) { header.write(path, 0, "utf8"); return; }
  const split = path.lastIndexOf("/", path.endsWith("/") ? path.length - 2 : undefined);
  if (split < 1 || Buffer.byteLength(path.slice(0, split)) > 155 || Buffer.byteLength(path.slice(split + 1)) > 100) deny("Archive path exceeds USTAR bounds");
  header.write(path.slice(split + 1), 0, "utf8"); header.write(path.slice(0, split), 345, "utf8");
}
function deny(message: string): never { throw new BrokerError("POLICY_DENIED", message); }
function limit(message: string): never { throw new BrokerError("OUTPUT_LIMIT", message); }
