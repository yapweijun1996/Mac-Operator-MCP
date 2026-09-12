import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import { assertContentDoesNotContainSecrets, assertContentPathAllowed } from "./secret-policy.js";

export interface FilesystemRootPolicy {
  rootId: string;
  path: string;
  metadata: boolean;
  contentRead: boolean;
  write?: boolean;
  denyRelativePaths: readonly string[];
}

export interface SafeFileRead {
  rootId: string;
  path: string;
  content: Buffer;
  sizeBytes: number;
  truncated: boolean;
  device: string;
  inode: string;
}

export interface SafeFileHash {
  rootId: string;
  path: string;
  algorithm: "sha256" | "sha512";
  digest: string;
  sizeBytes: number;
  device: string;
  inode: string;
}

export interface SafePathMetadata {
  rootId: string;
  path: string;
  type: "file" | "directory" | "symlink" | "other";
  sizeBytes: number;
  modifiedAt: string | null;
  mode: string;
  isSymlink: boolean;
  device: string;
  inode: string;
}

export interface FilesystemPathPlan {
  rootId: string;
  requestedPath: string;
  root: FilesystemRootPolicy;
}

interface NativePathMetadata {
  rootPath: string;
  path: string;
  type: SafePathMetadata["type"];
  sizeBytes: number;
  modifiedAtMs: number;
  mode: string;
  isSymlink: boolean;
  device: string;
  inode: string;
}

interface NativeFilesystemAdapter {
  statPathWithinRoot(rootPath: string, targetPath: string, followSymlink: boolean): unknown;
  readFileWithinRoot(
    rootPath: string,
    targetPath: string,
    offset: number,
    maxBytes: number,
    authorizeCanonicalPath: (path: string) => void
  ): unknown;
  hashFileWithinRoot(
    rootPath: string,
    targetPath: string,
    algorithm: "sha256" | "sha512",
    authorizeCanonicalPath: (path: string) => void
  ): unknown;
  writeFileAtomicWithinRoot(
    rootPath: string,
    targetPath: string,
    content: Buffer,
    createOnly: boolean,
    expectedPresent: boolean,
    expectedDevice: string,
    expectedInode: string,
    temporaryName: string
  ): unknown;
}

const ROOT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const require = createRequire(import.meta.url);

export class FilesystemInspector {
  private readonly roots: readonly FilesystemRootPolicy[];
  private readonly native: NativeFilesystemAdapter;

  constructor(roots: readonly FilesystemRootPolicy[]) {
    const rootIds = new Set<string>();
    this.roots = roots.map((root) => {
      if (!ROOT_ID_PATTERN.test(root.rootId) || rootIds.has(root.rootId)) {
        throw new Error("Filesystem root ID is malformed or duplicated");
      }
      rootIds.add(root.rootId);
      if (!isAbsolute(root.path) || root.path.includes("\0") || resolve(root.path) !== root.path) {
        throw new Error("Filesystem root path must be absolute and lexically normalized");
      }
      const denyRelativePaths = root.denyRelativePaths.map((path) => normalizeRelative(path));
      return { ...root, denyRelativePaths };
    });
    try {
      this.native = require("./peer_credentials.node") as NativeFilesystemAdapter;
    } catch {
      throw new Error("Filesystem native adapter is unavailable");
    }
  }

  statPath(requestedPath: string, followSymlink = true): SafePathMetadata {
    return this.statPlanned(this.planPath(requestedPath, "metadata"), followSymlink);
  }

  planPath(requestedPath: string, capability: "metadata" | "content_read" | "write" = "metadata"): FilesystemPathPlan {
    if (!isAbsolute(requestedPath) || requestedPath.includes("\0") || requestedPath.length > 4096) {
      throw new BrokerError("PRECONDITION_FAILED", "Filesystem path must be a bounded absolute path");
    }
    const lexicalPath = resolve(requestedPath);
    if (capability === "content_read" || capability === "write") assertContentPathAllowed(lexicalPath);
    const candidates = this.roots
      .filter((root) => (capability === "metadata" ? root.metadata : capability === "content_read" ? root.contentRead === true : root.write === true) && isContained(root.path, lexicalPath))
      .sort((left, right) => right.path.length - left.path.length);
    if (candidates.length === 0) throw new BrokerError("POLICY_DENIED", "Filesystem path is outside authorized roots");
    const root = candidates[0]!;
    const lexicalRelative = relative(root.path, lexicalPath);
    if (root.denyRelativePaths.some((denied) => isRelativeContained(denied, lexicalRelative))) {
      throw new BrokerError("POLICY_DENIED", "Filesystem path is inside a denied zone");
    }
    return { rootId: root.rootId, requestedPath: lexicalPath, root };
  }

  readPlanned(plan: FilesystemPathPlan, offset: number, maxBytes: number): SafeFileRead {
    let nativeRead: unknown;
    try {
      nativeRead = this.native.readFileWithinRoot(
        plan.root.path,
        plan.requestedPath,
        offset,
        maxBytes,
        (canonicalPath) => assertContentPathAllowed(canonicalPath)
      );
    } catch {
      throw new BrokerError("POLICY_DENIED", "Filesystem file escaped its authorized root, type, or volume");
    }
    const read = parseNativeRead(nativeRead);
    const resolvedRelative = relative(read.rootPath, read.path);
    if (resolvedRelative.startsWith(`..${sep}`) || resolvedRelative === ".." || isAbsolute(resolvedRelative)) {
      throw new BrokerError("POLICY_DENIED", "Filesystem file escaped its authorized root or volume");
    }
    if (plan.root.denyRelativePaths.some((denied) => isRelativeContained(denied, resolvedRelative))) {
      throw new BrokerError("POLICY_DENIED", "Filesystem path is inside a denied zone");
    }
    assertContentPathAllowed(read.path);
    return { rootId: plan.rootId, path: read.path, content: read.content, sizeBytes: read.sizeBytes,
      truncated: read.truncated, device: read.device, inode: read.inode };
  }

  hashPlanned(plan: FilesystemPathPlan, algorithm: "sha256" | "sha512"): SafeFileHash {
    assertContentPathAllowed(plan.requestedPath);
    let nativeHash: unknown;
    try {
      nativeHash = this.native.hashFileWithinRoot(
        plan.root.path,
        plan.requestedPath,
        algorithm,
        (canonicalPath) => assertContentPathAllowed(canonicalPath)
      );
    } catch {
      throw new BrokerError("POLICY_DENIED", "Filesystem file escaped its authorized root, type, or volume");
    }
    const hash = parseNativeHash(nativeHash);
    const resolvedRelative = relative(hash.rootPath, hash.path);
    if (resolvedRelative.startsWith(`..${sep}`) || resolvedRelative === ".." || isAbsolute(resolvedRelative)) {
      throw new BrokerError("POLICY_DENIED", "Filesystem file escaped its authorized root or volume");
    }
    if (plan.root.denyRelativePaths.some((denied) => isRelativeContained(denied, resolvedRelative))) {
      throw new BrokerError("POLICY_DENIED", "Filesystem path is inside a denied zone");
    }
    assertContentPathAllowed(hash.path);
    return {
      rootId: plan.rootId,
      path: hash.path,
      algorithm: hash.algorithm,
      digest: hash.digest,
      sizeBytes: hash.sizeBytes,
      device: hash.device,
      inode: hash.inode
    };
  }

  statPlanned(plan: FilesystemPathPlan, followSymlink = true): SafePathMetadata {
    let metadata: NativePathMetadata;
    try {
      metadata = parseNativeMetadata(this.native.statPathWithinRoot(plan.root.path, plan.requestedPath, followSymlink));
    } catch {
      throw new BrokerError("POLICY_DENIED", "Filesystem target escaped its authorized root or volume");
    }
    const resolvedRelative = relative(metadata.rootPath, metadata.path);
    if (resolvedRelative.startsWith(`..${sep}`) || resolvedRelative === ".." || isAbsolute(resolvedRelative)) {
      throw new BrokerError("POLICY_DENIED", "Filesystem target escaped its authorized root or volume");
    }
    if (plan.root.denyRelativePaths.some((denied) => isRelativeContained(denied, resolvedRelative))) {
      throw new BrokerError("POLICY_DENIED", "Filesystem path is inside a denied zone");
    }
    if (!Number.isSafeInteger(metadata.sizeBytes) || metadata.sizeBytes < 0 || metadata.sizeBytes > 1_000_000_000_000) {
      throw new BrokerError("OUTPUT_LIMIT", "Filesystem metadata exceeds the contract limit");
    }
    return {
      rootId: plan.rootId,
      path: metadata.path,
      type: metadata.type,
      sizeBytes: metadata.sizeBytes,
      modifiedAt: Number.isFinite(metadata.modifiedAtMs) ? new Date(metadata.modifiedAtMs).toISOString() : null,
      mode: metadata.mode,
      isSymlink: metadata.isSymlink,
      device: metadata.device,
      inode: metadata.inode
    };
  }

  writePlanned(
    plan: FilesystemPathPlan,
    content: Buffer,
    expectedSha256: string | undefined,
    createOnly: boolean,
    temporaryName: string
  ): {
    path: string;
    bytesWritten: number;
    sha256: string;
    created: boolean;
    expectedSha256: string | null;
    expectedMatched: boolean;
    device: string;
    inode: string;
  } {
    assertContentPathAllowed(plan.requestedPath);
    assertContentDoesNotContainSecrets(content);
    let existing: SafePathMetadata | undefined;
    try {
      existing = this.statPlanned(plan, false);
    } catch {
      existing = undefined;
    }
    if (existing && existing.type !== "file") {
      throw new BrokerError("POLICY_DENIED", "Filesystem write target must be a regular file or absent");
    }
    if (existing && createOnly) throw new BrokerError("PRECONDITION_FAILED", "Filesystem write create-only precondition failed");
    let expectedMatched = true;
    if (expectedSha256 !== undefined) {
      if (!existing) throw new BrokerError("PRECONDITION_FAILED", "Filesystem write expected hash requires an existing file");
      const prior = this.readPlanned(plan, 0, 1_048_576);
      const priorDigest = createHash("sha256").update(prior.content).digest("hex");
      expectedMatched = priorDigest === expectedSha256.toLowerCase();
      if (!expectedMatched) throw new BrokerError("PRECONDITION_FAILED", "Filesystem write expected hash did not match");
    }
    let nativeWrite: unknown;
    try {
      nativeWrite = this.native.writeFileAtomicWithinRoot(
        plan.root.path,
        plan.requestedPath,
        content,
        createOnly,
        existing !== undefined,
        existing?.device ?? "0",
        existing?.inode ?? "0",
        temporaryName
      );
    } catch {
      throw new BrokerError("POLICY_DENIED", "Filesystem write target escaped its authorized root or changed during the write");
    }
    const write = parseNativeWrite(nativeWrite);
    const resolvedRelative = relative(write.rootPath, write.path);
    if (resolvedRelative.startsWith(`..${sep}`) || resolvedRelative === ".." || isAbsolute(resolvedRelative) ||
        plan.root.denyRelativePaths.some((denied) => isRelativeContained(denied, resolvedRelative))) {
      throw new BrokerError("POLICY_DENIED", "Filesystem write result escaped its authorized root or deny zone");
    }
    assertContentPathAllowed(write.path);
    if (write.bytesWritten !== content.length) {
      throw new BrokerError("VERIFICATION_FAILED", "Filesystem write byte count did not match the request");
    }
    const readbackDigest = createHash("sha256").update(write.readback).digest("hex");
    const contentDigest = createHash("sha256").update(content).digest("hex");
    if (readbackDigest !== contentDigest || readbackDigest !== write.sha256) {
      throw new BrokerError("VERIFICATION_FAILED", "Filesystem write readback hash did not match");
    }
    return {
      path: write.path,
      bytesWritten: write.bytesWritten,
      sha256: readbackDigest,
      created: write.created,
      expectedSha256: expectedSha256?.toLowerCase() ?? null,
      expectedMatched,
      device: write.device,
      inode: write.inode
    };
  }
}

function parseNativeRead(value: unknown): { rootPath: string; path: string; content: Buffer; sizeBytes: number; truncated: boolean; device: string; inode: string } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Malformed native read");
  const record = value as Record<string, unknown>;
  if (typeof record.rootPath !== "string" || !isAbsolute(record.rootPath) ||
      typeof record.path !== "string" || !isAbsolute(record.path) || !Buffer.isBuffer(record.content) ||
      !Number.isSafeInteger(record.sizeBytes) || (record.sizeBytes as number) < 0 || (record.sizeBytes as number) > 1_000_000_000 ||
      typeof record.truncated !== "boolean" || typeof record.device !== "string" || !/^\d+$/u.test(record.device) ||
      typeof record.inode !== "string" || !/^\d+$/u.test(record.inode)) throw new Error("Malformed native read");
  return record as { rootPath: string; path: string; content: Buffer; sizeBytes: number; truncated: boolean; device: string; inode: string };
}

function parseNativeHash(value: unknown): {
  rootPath: string;
  path: string;
  algorithm: "sha256" | "sha512";
  digest: string;
  sizeBytes: number;
  device: string;
  inode: string;
} {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Malformed native hash");
  const record = value as Record<string, unknown>;
  if (typeof record.rootPath !== "string" || !isAbsolute(record.rootPath) ||
      typeof record.path !== "string" || !isAbsolute(record.path) ||
      (record.algorithm !== "sha256" && record.algorithm !== "sha512") ||
      typeof record.digest !== "string" ||
      !((record.algorithm === "sha256" && /^[a-f0-9]{64}$/u.test(record.digest)) ||
        (record.algorithm === "sha512" && /^[a-f0-9]{128}$/u.test(record.digest))) ||
      !Number.isSafeInteger(record.sizeBytes) || (record.sizeBytes as number) < 0 || (record.sizeBytes as number) > 1_000_000_000 ||
      typeof record.device !== "string" || !/^\d+$/u.test(record.device) ||
      typeof record.inode !== "string" || !/^\d+$/u.test(record.inode)) {
    throw new Error("Malformed native hash");
  }
  return record as {
    rootPath: string;
    path: string;
    algorithm: "sha256" | "sha512";
    digest: string;
    sizeBytes: number;
    device: string;
    inode: string;
  };
}

function parseNativeWrite(value: unknown): {
  rootPath: string;
  path: string;
  bytesWritten: number;
  sha256: string;
  created: boolean;
  device: string;
  inode: string;
  readback: Buffer;
} {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Malformed native write");
  const record = value as Record<string, unknown>;
  if (typeof record.rootPath !== "string" || !isAbsolute(record.rootPath) ||
      typeof record.path !== "string" || !isAbsolute(record.path) ||
      !Number.isSafeInteger(record.bytesWritten) || (record.bytesWritten as number) < 0 || (record.bytesWritten as number) > 1_048_576 ||
      typeof record.sha256 !== "string" || !/^[a-f0-9]{64}$/u.test(record.sha256) ||
      typeof record.created !== "boolean" || typeof record.device !== "string" || !/^\d+$/u.test(record.device) ||
      typeof record.inode !== "string" || !/^\d+$/u.test(record.inode) || !Buffer.isBuffer(record.readback)) {
    throw new Error("Malformed native write");
  }
  return record as unknown as { rootPath: string; path: string; bytesWritten: number; sha256: string; created: boolean; device: string; inode: string; readback: Buffer };
}

function normalizeRelative(path: string): string {
  if (path.length === 0 || path.includes("\0") || isAbsolute(path) || resolve("/", path) !== `/${path}`) {
    throw new Error("Denied filesystem path must be a normalized relative path");
  }
  return path;
}

function isContained(root: string, target: string): boolean {
  return target === root || target.startsWith(root.endsWith(sep) ? root : `${root}${sep}`);
}

function isRelativeContained(root: string, target: string): boolean {
  return target === root || target.startsWith(`${root}${sep}`);
}

function parseNativeMetadata(value: unknown): NativePathMetadata {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Malformed native metadata");
  const record = value as Record<string, unknown>;
  const allowedTypes = new Set(["file", "directory", "symlink", "other"]);
  if (
    typeof record.rootPath !== "string" || !isAbsolute(record.rootPath) ||
    typeof record.path !== "string" || !isAbsolute(record.path) ||
    typeof record.type !== "string" || !allowedTypes.has(record.type) ||
    typeof record.sizeBytes !== "number" || typeof record.modifiedAtMs !== "number" ||
    typeof record.mode !== "string" || !/^[0-7]{4}$/u.test(record.mode) ||
    typeof record.isSymlink !== "boolean" ||
    typeof record.device !== "string" || !/^\d+$/u.test(record.device) ||
    typeof record.inode !== "string" || !/^\d+$/u.test(record.inode)
  ) throw new Error("Malformed native metadata");
  return record as unknown as NativePathMetadata;
}
