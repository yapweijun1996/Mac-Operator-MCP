import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { basename, isAbsolute, join, relative, resolve, sep } from "node:path";
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

export interface SafeDirectoryEntry {
  name: string;
  type: "file" | "directory" | "symlink" | "other";
  sizeBytes: number;
  modifiedAt: string | null;
  hidden: boolean;
}

export interface SafeDirectoryListing {
  rootId: string;
  path: string;
  entries: readonly SafeDirectoryEntry[];
  nextCursor: string | null;
}

export interface SafeTreeEntry {
  path: string;
  type: SafeDirectoryEntry["type"];
  depth: number;
  sizeBytes: number;
}

export interface SafeDirectoryTree {
  rootId: string;
  root: string;
  entries: readonly SafeTreeEntry[];
  truncated: boolean;
}

export interface SafeFileMatch {
  path: string;
  type: SafeDirectoryEntry["type"];
  sizeBytes: number;
  modifiedAt: string | null;
}

export interface SafeFileSearch {
  roots: readonly string[];
  query: string;
  matches: readonly SafeFileMatch[];
  truncated: boolean;
}

export interface SafeRecentFiles {
  files: readonly SafeFileMatch[];
  truncated: boolean;
}

export interface SafeTextMatch {
  path: string;
  line: number;
  startColumn: number;
  endColumn: number;
  snippet: string;
}

export interface SafeTextSearch {
  query: string;
  matches: readonly SafeTextMatch[];
  truncated: boolean;
}

export interface SafeProject {
  root: string;
  type: string;
  indicators: readonly string[];
}

export interface SafeProjectDiscovery {
  projects: readonly SafeProject[];
  truncated: boolean;
}

export interface SafeProjectSummary {
  projectRoot: string;
  vcs: {
    system: "git" | "none" | "other";
    branch?: string;
    dirty?: boolean;
  };
  manifests: readonly string[];
  languages: readonly string[];
  treeEntries: readonly {
    path: string;
    type: SafeDirectoryEntry["type"];
    depth: number;
  }[];
  warnings: readonly string[];
  truncated: boolean;
}

export interface SafeStorageVolume {
  id: string;
  name: string;
  mountPath: string;
  totalBytes: number;
  availableBytes: number;
  usedBytes: number;
}

export interface SafeStorageConsumer {
  path: string;
  sizeBytes: number;
  type: "file" | "directory" | "other";
}

export interface SafeStorageAnalysis {
  volumes: readonly SafeStorageVolume[];
  consumers: readonly SafeStorageConsumer[];
  analyzedRoots: readonly string[];
  warnings: readonly string[];
  truncated: boolean;
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

interface NativeStorageVolume extends SafeStorageVolume {
  rootPath: string;
}

interface NativeFilesystemAdapter {
  statPathWithinRoot(rootPath: string, targetPath: string, followSymlink: boolean): unknown;
  statStorageVolumeWithinRoot(rootPath: string): unknown;
  listDirectoryWithinRoot(
    rootPath: string,
    targetPath: string,
    includeHidden: boolean,
    cursor: string | undefined,
    limit: number,
    authorizeCanonicalPath: (path: string) => boolean
  ): unknown;
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
const MAX_SEARCH_DEPTH = 32;
const MAX_SEARCH_ENTRIES = 50_000;
const MAX_TEXT_FILE_BYTES = 1_048_576;
const MAX_TEXT_SEARCH_BYTES = 64 * 1024 * 1024;
const MAX_TEXT_MATCHES_PER_FILE = 100;
const MAX_PROJECT_DEPTH = 16;
const MAX_PROJECT_DIRECTORIES = 10_000;
const MAX_PROJECT_ENTRIES = 50_000;
const MAX_PROJECT_SUMMARY_TREE_ENTRIES = 1_000;
const MAX_STORAGE_DEPTH = 8;
const MAX_STORAGE_ENTRIES = 50_000;
const MAX_STORAGE_DIRECTORIES = 10_000;
const PROJECT_SUMMARY_MANIFESTS = new Set([
  "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "tsconfig.json",
  "pyproject.toml", "setup.py", "requirements.txt", "Pipfile", "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
  "compose.yml", "compose.yaml", "Package.swift", "Cargo.toml", "go.mod", "Gemfile", "pom.xml", "build.gradle",
  "build.gradle.kts", "settings.gradle", "settings.gradle.kts"
]);
const PROJECT_MARKERS: Readonly<Record<string, readonly string[]>> = {
  git: [".git"],
  node: ["package.json"],
  python: ["pyproject.toml", "setup.py", "requirements.txt", "Pipfile"],
  docker: ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"],
  swift: ["Package.swift", ".xcodeproj", ".xcworkspace"],
  rust: ["Cargo.toml"],
  go: ["go.mod"],
  ruby: ["Gemfile"],
  java: ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"]
};
const PROJECT_SKIP_DIRECTORIES = new Set([
  ".git", ".svn", ".hg", "node_modules", ".venv", "venv", "Pods", "DerivedData", "build", "dist", "target", ".cache"
]);
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

  listPlanned(
    plan: FilesystemPathPlan,
    cursor: string | undefined,
    limit: number,
    includeHidden: boolean
  ): SafeDirectoryListing {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) {
      throw new BrokerError("PRECONDITION_FAILED", "Directory entry limit is outside the supported range");
    }
    if (cursor !== undefined && (cursor.length === 0 || cursor.length > 4096 || cursor.includes("\0") || cursor.includes("/"))) {
      throw new BrokerError("PRECONDITION_FAILED", "Directory cursor is malformed");
    }
    if (typeof includeHidden !== "boolean") {
      throw new BrokerError("PRECONDITION_FAILED", "include_hidden must be a boolean");
    }
    let canonicalRootPath: string;
    try {
      canonicalRootPath = realpathSync.native(plan.root.path);
    } catch {
      throw new BrokerError("POLICY_DENIED", "Filesystem root could not be canonicalized");
    }
    let nativeListing: unknown;
    try {
      nativeListing = this.native.listDirectoryWithinRoot(
        plan.root.path,
        plan.requestedPath,
        includeHidden,
        cursor,
        limit,
        (canonicalPath) => {
          try {
            assertContentPathAllowed(canonicalPath);
            const resolvedRelative = relative(canonicalRootPath, canonicalPath);
            if (resolvedRelative.startsWith(`..${sep}`) || resolvedRelative === ".." || isAbsolute(resolvedRelative)) return false;
            return !plan.root.denyRelativePaths.some((denied) => isRelativeContained(denied, resolvedRelative));
          } catch {
            return false;
          }
        }
      );
    } catch {
      throw new BrokerError("POLICY_DENIED", "Filesystem directory escaped its authorized root, type, or volume");
    }
    const listing = parseNativeDirectoryListing(nativeListing);
    const resolvedRelative = relative(listing.rootPath, listing.path);
    if (resolvedRelative.startsWith(`..${sep}`) || resolvedRelative === ".." || isAbsolute(resolvedRelative)) {
      throw new BrokerError("POLICY_DENIED", "Filesystem directory escaped its authorized root or volume");
    }
    if (plan.root.denyRelativePaths.some((denied) => isRelativeContained(denied, resolvedRelative))) {
      throw new BrokerError("POLICY_DENIED", "Filesystem path is inside a denied zone");
    }
    assertContentPathAllowed(listing.path);
    return {
      rootId: plan.rootId,
      path: listing.path,
      entries: listing.entries,
      nextCursor: listing.nextCursor
    };
  }

  treePlanned(plan: FilesystemPathPlan, depth: number, maxEntries: number): SafeDirectoryTree {
    if (!Number.isSafeInteger(depth) || depth < 0 || depth > 8) {
      throw new BrokerError("PRECONDITION_FAILED", "Directory tree depth is outside the supported range");
    }
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > 5000) {
      throw new BrokerError("PRECONDITION_FAILED", "Directory tree entry limit is outside the supported range");
    }

    const entries: SafeTreeEntry[] = [];
    let rootPath: string | undefined;
    let truncated = false;
    const walk = (directoryPlan: FilesystemPathPlan, currentDepth: number): void => {
      if (truncated) return;
      let cursor: string | undefined;
      while (!truncated) {
        const remaining = maxEntries - entries.length;
        if (remaining <= 0) {
          truncated = true;
          return;
        }
        const listing = this.listPlanned(directoryPlan, cursor, Math.min(500, remaining), false);
        if (rootPath === undefined) rootPath = listing.path;
        for (const entry of listing.entries) {
          if (entries.length >= maxEntries) {
            truncated = true;
            return;
          }
          const childPath = join(listing.path, entry.name);
          if (!isAbsolute(childPath) || childPath.length > 4096) {
            throw new BrokerError("OUTPUT_LIMIT", "Directory tree path exceeds the contract limit");
          }
          entries.push({ path: childPath, type: entry.type, depth: currentDepth, sizeBytes: entry.sizeBytes });
          if (entry.type === "directory" && currentDepth < depth) {
            walk({ ...directoryPlan, requestedPath: childPath }, currentDepth + 1);
            if (truncated) return;
          }
        }
        if (listing.nextCursor === null) return;
        cursor = listing.nextCursor;
      }
    };

    walk(plan, 0);
    if (rootPath === undefined) throw new BrokerError("EXECUTION_FAILED", "Directory tree returned no root identity");
    return { rootId: plan.rootId, root: rootPath, entries, truncated };
  }

  findFilesPlanned(
    plans: readonly FilesystemPathPlan[],
    query: string,
    maxResults: number
  ): SafeFileSearch {
    if (typeof query !== "string" || query.length < 1 || query.length > 256 || query.includes("\0")) {
      throw new BrokerError("PRECONDITION_FAILED", "Filesystem search query is malformed");
    }
    const normalizedQuery = query.normalize("NFKC").toLocaleLowerCase("en-US");
    const result = this.traverseMetadata(plans, maxResults, (entry) =>
      entry.path.normalize("NFKC").toLocaleLowerCase("en-US").includes(normalizedQuery) ? entry : undefined
    , (entry) => entry.path);
    return { roots: result.roots, query, matches: result.matches, truncated: result.truncated };
  }

  recentFilesPlanned(
    plans: readonly FilesystemPathPlan[],
    sinceSeconds: number,
    limit: number,
    nowMs: number
  ): SafeRecentFiles {
    if (!Number.isSafeInteger(sinceSeconds) || sinceSeconds < 1 || sinceSeconds > 31_536_000) {
      throw new BrokerError("PRECONDITION_FAILED", "Recent-file window is outside the supported range");
    }
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
      throw new BrokerError("PRECONDITION_FAILED", "Recent-file clock value is malformed");
    }
    const cutoffMs = nowMs - sinceSeconds * 1000;
    const result = this.traverseMetadata(plans, limit, (entry) => {
      const modifiedAtMs = entry.modifiedAt === null ? Number.NaN : Date.parse(entry.modifiedAt);
      return Number.isFinite(modifiedAtMs) && modifiedAtMs >= cutoffMs ? entry : undefined;
    }, (entry) => entry.path);
    return { files: result.matches, truncated: result.truncated };
  }

  searchTextPlanned(
    plans: readonly FilesystemPathPlan[],
    query: string,
    glob: string | undefined,
    maxResults: number
  ): SafeTextSearch {
    if (typeof query !== "string" || query.length < 1 || query.length > 512 || query.includes("\0")) {
      throw new BrokerError("PRECONDITION_FAILED", "Text search query is malformed");
    }
    try {
      assertContentDoesNotContainSecrets(Buffer.from(query, "utf8"));
    } catch {
      throw new BrokerError("POLICY_DENIED", "Text search query matched a protected secret signature");
    }
    const globPattern = compileSearchGlob(glob);
    let scannedBytes = 0;
    let scanBudgetExceeded = false;
    const result = this.traverseMetadata(
      plans,
      maxResults,
      (entry, plan) => {
        if (entry.type !== "file" || entry.sizeBytes > MAX_TEXT_FILE_BYTES ||
            (globPattern && !globPattern.test(basename(entry.path)))) return undefined;
        if (scannedBytes + entry.sizeBytes > MAX_TEXT_SEARCH_BYTES) {
          scanBudgetExceeded = true;
          return undefined;
        }
        scannedBytes += entry.sizeBytes;
        let content: Buffer;
        try {
          content = this.readPlanned(plan, 0, MAX_TEXT_FILE_BYTES).content;
          assertContentDoesNotContainSecrets(content);
        } catch {
          return undefined;
        }
        let text: string;
        try {
          text = new TextDecoder("utf-8", { fatal: true }).decode(content);
        } catch {
          return undefined;
        }
        if (text.includes("\0")) return undefined;
        const matches: SafeTextMatch[] = [];
        const lines = text.split(/\r?\n/u);
        for (let lineIndex = 0; lineIndex < lines.length && matches.length < MAX_TEXT_MATCHES_PER_FILE; lineIndex += 1) {
          const lineText = lines[lineIndex]!;
          let offset = lineText.indexOf(query);
          while (offset >= 0 && matches.length < MAX_TEXT_MATCHES_PER_FILE) {
            const snippetStart = Math.max(0, offset - 200);
            const snippetEnd = Math.min(lineText.length, offset + query.length + 200);
            matches.push({
              path: entry.path,
              line: lineIndex + 1,
              startColumn: offset + 1,
              endColumn: offset + query.length + 1,
              snippet: sanitizeSearchSnippet(lineText.slice(snippetStart, snippetEnd))
            });
            const nextOffset = offset + Math.max(query.length, 1);
            offset = lineText.indexOf(query, nextOffset);
          }
        }
        return matches;
      },
      (match) => `${match.path}:${match.line}:${match.startColumn}`,
      () => scanBudgetExceeded
    );
    return { query, matches: result.matches, truncated: result.truncated };
  }

  discoverProjectsPlanned(
    plans: readonly FilesystemPathPlan[],
    types: readonly string[],
    maxResults: number
  ): SafeProjectDiscovery {
    if (!Number.isSafeInteger(maxResults) || maxResults < 1 || maxResults > 500) {
      throw new BrokerError("PRECONDITION_FAILED", "Project discovery result limit is outside the supported range");
    }
    if (plans.length < 1 || plans.length > 32) {
      throw new BrokerError("PRECONDITION_FAILED", "Project discovery requires between 1 and 32 roots");
    }
    const requestedTypes = normalizeProjectTypes(types);
    const typeSet = new Set(requestedTypes);
    const projects: SafeProject[] = [];
    const visitedDirectories = new Set<string>();
    const pending: Array<{ plan: FilesystemPathPlan; depth: number }> = plans.map((plan) => ({ plan, depth: 0 }));
    let visitedEntries = 0;
    let visitedDirectoriesCount = 0;
    let truncated = false;

    while (pending.length > 0 && !truncated) {
      const current = pending.shift()!;
      let cursor: string | undefined;
      while (!truncated) {
        const listing = this.listPlanned(current.plan, cursor, 500, true);
        if (visitedDirectories.has(listing.path) && cursor === undefined) break;
        if (!visitedDirectories.has(listing.path)) {
          visitedDirectories.add(listing.path);
          visitedDirectoriesCount += 1;
          if (visitedDirectoriesCount > MAX_PROJECT_DIRECTORIES) {
            truncated = true;
            break;
          }
        }
        const markerNames = new Set(listing.entries
          .filter((entry) => entry.type !== "symlink")
          .map((entry) => entry.name));
        const foundTypes = (requestedTypes.length > 0 ? requestedTypes : Object.keys(PROJECT_MARKERS))
          .map((type) => ({ type, indicators: (PROJECT_MARKERS[type] ?? []).filter((marker) => markerNames.has(marker)) }))
          .filter((candidate) => candidate.indicators.length > 0);
        if (foundTypes.length > 0) {
          for (const found of foundTypes) {
            if (projects.length >= maxResults) {
              truncated = true;
              break;
            }
            projects.push({ root: listing.path, type: found.type, indicators: found.indicators });
          }
        }
        if (truncated) break;
        for (const entry of listing.entries) {
          visitedEntries += 1;
          if (visitedEntries > MAX_PROJECT_ENTRIES) {
            truncated = true;
            break;
          }
          if (entry.type !== "directory" || current.depth >= MAX_PROJECT_DEPTH || PROJECT_SKIP_DIRECTORIES.has(entry.name)) continue;
          const childPath = join(listing.path, entry.name);
          if (!isAbsolute(childPath) || childPath.length > 4096) {
            truncated = true;
            break;
          }
          pending.push({ plan: { ...current.plan, requestedPath: childPath }, depth: current.depth + 1 });
        }
        if (truncated || listing.nextCursor === null) break;
        cursor = listing.nextCursor;
      }
    }
    return { projects, truncated };
  }

  summarizeProjectPlanned(
    plan: FilesystemPathPlan,
    includeTree: boolean,
    treeDepth: number
  ): SafeProjectSummary {
    if (typeof includeTree !== "boolean") {
      throw new BrokerError("PRECONDITION_FAILED", "include_tree must be a boolean");
    }
    if (!Number.isSafeInteger(treeDepth) || treeDepth < 0 || treeDepth > 4) {
      throw new BrokerError("PRECONDITION_FAILED", "Project summary tree depth is outside the supported range");
    }
    const root = this.statPlanned(plan, false);
    if (root.type !== "directory") throw new BrokerError("PRECONDITION_FAILED", "Project summary root must be a directory");

    const manifests = new Set<string>();
    const languages = new Set<string>();
    const treeEntries: Array<{ path: string; type: SafeDirectoryEntry["type"]; depth: number }> = [];
    const warnings: string[] = [];
    const pending: Array<{ plan: FilesystemPathPlan; depth: number }> = [{ plan, depth: 0 }];
    const visitedDirectories = new Set<string>();
    let visitedEntries = 0;
    let visitedDirectoriesCount = 0;
    let truncated = false;
    let hasGit = false;

    while (pending.length > 0 && !truncated) {
      const current = pending.shift()!;
      let cursor: string | undefined;
      while (!truncated) {
        const listing = this.listPlanned(current.plan, cursor, 500, true);
        if (visitedDirectories.has(listing.path) && cursor === undefined) break;
        if (!visitedDirectories.has(listing.path)) {
          visitedDirectories.add(listing.path);
          visitedDirectoriesCount += 1;
          if (visitedDirectoriesCount > MAX_PROJECT_DIRECTORIES) {
            truncated = true;
            break;
          }
        }
        for (const entry of listing.entries) {
          visitedEntries += 1;
          if (visitedEntries > MAX_PROJECT_ENTRIES) {
            truncated = true;
            break;
          }
          const childPath = join(listing.path, entry.name);
          if (!isAbsolute(childPath) || childPath.length > 4096) {
            truncated = true;
            break;
          }
          if (current.depth === 0 && entry.type !== "symlink") {
            if (entry.name === ".git") hasGit = true;
            if (PROJECT_SUMMARY_MANIFESTS.has(entry.name)) manifests.add(entry.name);
          }
          addProjectLanguage(languages, entry.name, entry.type);
          if (includeTree && treeEntries.length < MAX_PROJECT_SUMMARY_TREE_ENTRIES) {
            treeEntries.push({ path: childPath, type: entry.type, depth: current.depth });
          } else if (includeTree) {
            truncated = true;
            break;
          }
          if (!includeTree || entry.type !== "directory" || current.depth >= treeDepth || PROJECT_SKIP_DIRECTORIES.has(entry.name)) continue;
          pending.push({ plan: { ...current.plan, requestedPath: childPath }, depth: current.depth + 1 });
        }
        if (truncated || listing.nextCursor === null) break;
        cursor = listing.nextCursor;
      }
    }
    if (hasGit) warnings.push("VCS branch and dirty state are omitted by the metadata-only summary");
    if (truncated) warnings.push("Project summary traversal was truncated by fixed metadata budgets");
    return {
      projectRoot: root.path,
      vcs: { system: hasGit ? "git" : "none" },
      manifests: [...manifests].sort(),
      languages: [...languages].sort(),
      treeEntries,
      warnings: warnings.slice(0, 32),
      truncated
    };
  }

  analyzeStoragePlanned(
    plans: readonly FilesystemPathPlan[],
    topN: number,
    maxDepth: number
  ): SafeStorageAnalysis {
    if (plans.length < 1 || plans.length > 32) {
      throw new BrokerError("PRECONDITION_FAILED", "Storage analysis requires between 1 and 32 roots");
    }
    if (!Number.isSafeInteger(topN) || topN < 1 || topN > 100) {
      throw new BrokerError("PRECONDITION_FAILED", "Storage top_n must be an integer between 1 and 100");
    }
    if (!Number.isSafeInteger(maxDepth) || maxDepth < 0 || maxDepth > MAX_STORAGE_DEPTH) {
      throw new BrokerError("PRECONDITION_FAILED", "Storage max_depth must be an integer between 0 and 8");
    }

    const volumes = new Map<string, SafeStorageVolume>();
    const analyzedRoots: string[] = [];
    const warnings: string[] = [];
    const pending: Array<{ plan: FilesystemPathPlan; depth: number }> = [];
    const visitedDirectories = new Set<string>();
    const parentByPath = new Map<string, string>();
    const typeByPath = new Map<string, SafeStorageConsumer["type"]>();
    const sizeByPath = new Map<string, number>();
    let visitedEntries = 0;
    let visitedDirectoriesCount = 0;
    let truncated = false;

    for (const plan of plans) {
      const root = this.statPlanned(plan, false);
      if (root.type !== "directory" || root.isSymlink) {
        throw new BrokerError("PRECONDITION_FAILED", "Storage analysis roots must be non-symlink directories");
      }
      if (!analyzedRoots.includes(root.path)) analyzedRoots.push(root.path);
      const nativeVolume = this.native.statStorageVolumeWithinRoot(plan.root.path);
      const volume = parseNativeStorageVolume(nativeVolume);
      let canonicalPolicyRoot: string;
      try { canonicalPolicyRoot = realpathSync.native(plan.root.path); }
      catch { throw new BrokerError("POLICY_DENIED", "Filesystem volume root could not be canonicalized"); }
      if (volume.rootPath !== canonicalPolicyRoot || !volume.id.startsWith(`dev:${root.device}:`)) {
        throw new BrokerError("POLICY_DENIED", "Filesystem volume identity changed during authorization");
      }
      if (!volumes.has(volume.id)) volumes.set(volume.id, volume);
      pending.push({ plan: { ...plan, requestedPath: root.path }, depth: 0 });
    }

    const addWarning = (warning: string): void => {
      if (!warnings.includes(warning) && warnings.length < 32) warnings.push(warning);
    };
    while (pending.length > 0 && !truncated) {
      const current = pending.shift()!;
      let cursor: string | undefined;
      while (!truncated) {
        const listing = this.listPlanned(current.plan, cursor, 500, true);
        if (visitedDirectories.has(listing.path) && cursor === undefined) break;
        if (!visitedDirectories.has(listing.path)) {
          visitedDirectories.add(listing.path);
          visitedDirectoriesCount += 1;
          if (visitedDirectoriesCount > MAX_STORAGE_DIRECTORIES) {
            truncated = true;
            addWarning("Storage traversal exceeded the fixed directory budget");
            break;
          }
        }
        for (const entry of listing.entries) {
          visitedEntries += 1;
          if (visitedEntries > MAX_STORAGE_ENTRIES) {
            truncated = true;
            addWarning("Storage traversal exceeded the fixed entry budget");
            break;
          }
          const childPath = join(listing.path, entry.name);
          if (!isAbsolute(childPath) || childPath.length > 4096) {
            truncated = true;
            addWarning("Storage traversal encountered a path outside the contract limit");
            break;
          }
          const childPlan = { ...current.plan, requestedPath: childPath };
          let child: SafePathMetadata;
          try {
            child = this.statPlanned(childPlan, false);
          } catch {
            addWarning("Some storage entries could not be verified during traversal");
            continue;
          }
          if (child.isSymlink || child.type === "symlink") continue;
          if (child.type === "directory") {
            typeByPath.set(child.path, "directory");
            parentByPath.set(child.path, listing.path);
            sizeByPath.set(child.path, child.sizeBytes);
            if (current.depth >= maxDepth) {
              truncated = true;
              addWarning("Storage traversal was truncated at max_depth");
              continue;
            }
            pending.push({ plan: childPlan, depth: current.depth + 1 });
          } else {
            const consumerType = child.type === "file" ? "file" : "other";
            typeByPath.set(child.path, consumerType);
            parentByPath.set(child.path, listing.path);
            sizeByPath.set(child.path, child.sizeBytes);
          }
        }
        if (truncated || listing.nextCursor === null) break;
        cursor = listing.nextCursor;
      }
    }

    const aggregateSizes = new Map(sizeByPath);
    const pathsByDepth = [...parentByPath.keys()].sort((left, right) => right.length - left.length || right.localeCompare(left));
    for (const path of pathsByDepth) {
      const parent = parentByPath.get(path);
      if (parent === undefined || !typeByPath.has(parent)) continue;
      const currentSize = aggregateSizes.get(parent) ?? 0;
      const childSize = aggregateSizes.get(path) ?? 0;
      aggregateSizes.set(parent, Math.min(Math.max(currentSize, currentSize + childSize), 100_000_000_000_000));
    }
    const consumers = [...typeByPath.entries()]
      .filter(([path]) => !analyzedRoots.includes(path))
      .map(([path, type]) => ({ path, type, sizeBytes: aggregateSizes.get(path) ?? 0 }))
      .sort((left, right) => right.sizeBytes - left.sizeBytes || left.path.localeCompare(right.path))
      .slice(0, topN);
    return {
      volumes: [...volumes.values()].sort((left, right) => left.id.localeCompare(right.id)),
      consumers,
      analyzedRoots,
      warnings,
      truncated
    };
  }

  private traverseMetadata<T>(
    plans: readonly FilesystemPathPlan[],
    maxResults: number,
    select: (entry: SafeFileMatch, plan: FilesystemPathPlan) => T | readonly T[] | undefined,
    keyOf?: (value: T) => string,
    shouldStop?: () => boolean
  ): { roots: string[]; matches: T[]; truncated: boolean } {
    if (plans.length < 1 || plans.length > 32) {
      throw new BrokerError("PRECONDITION_FAILED", "Filesystem search requires between 1 and 32 roots");
    }
    if (!Number.isSafeInteger(maxResults) || maxResults < 1 || maxResults > 1000) {
      throw new BrokerError("PRECONDITION_FAILED", "Filesystem search result limit is outside the supported range");
    }
    const roots: string[] = [];
    for (const plan of plans) {
      const root = this.statPlanned(plan, false);
      if (root.type !== "directory") {
        throw new BrokerError("PRECONDITION_FAILED", "Filesystem search roots must be directories");
      }
      if (!roots.includes(root.path)) roots.push(root.path);
    }

    const matches: T[] = [];
    const matchKeys = new Set<string>();
    const visitedDirectories = new Set<string>();
    const pending: Array<{ plan: FilesystemPathPlan; depth: number }> = plans.map((plan) => ({ plan, depth: 0 }));
    let visitedEntries = 0;
    let truncated = false;
    while (pending.length > 0 && !truncated) {
      const current = pending.shift()!;
      let cursor: string | undefined;
      while (!truncated) {
        const listing = this.listPlanned(current.plan, cursor, 500, false);
        if (!visitedDirectories.has(listing.path)) visitedDirectories.add(listing.path);
        else if (cursor === undefined) break;
        for (const entry of listing.entries) {
          visitedEntries += 1;
          if (visitedEntries > MAX_SEARCH_ENTRIES) {
            truncated = true;
            break;
          }
          const childPath = join(listing.path, entry.name);
          if (!isAbsolute(childPath) || childPath.length > 4096) {
            truncated = true;
            break;
          }
          const candidate: SafeFileMatch = {
            path: childPath,
            type: entry.type,
            sizeBytes: entry.sizeBytes,
            modifiedAt: entry.modifiedAt
          };
          const childPlan = { ...current.plan, requestedPath: childPath };
          const selected = select(candidate, childPlan);
          if (selected !== undefined) {
            const selectedValues = Array.isArray(selected) ? selected : [selected];
            for (const value of selectedValues) {
              const key = keyOf ? keyOf(value) : `${childPath}:${matches.length}`;
              if (matchKeys.has(key)) continue;
              matchKeys.add(key);
              matches.push(value);
              if (matches.length >= maxResults) {
                truncated = true;
                break;
              }
            }
          }
          if (truncated || shouldStop?.()) {
            truncated = true;
            break;
          }
          if (entry.type === "directory") {
            if (current.depth >= MAX_SEARCH_DEPTH) {
              truncated = true;
              break;
            }
            pending.push({ plan: childPlan, depth: current.depth + 1 });
          }
        }
        if (truncated || listing.nextCursor === null) break;
        cursor = listing.nextCursor;
      }
    }
    if (roots.length === 0) throw new BrokerError("EXECUTION_FAILED", "Filesystem search returned no root identity");
    return { roots, matches, truncated };
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

function parseNativeDirectoryListing(value: unknown): {
  rootPath: string;
  path: string;
  entries: SafeDirectoryEntry[];
  nextCursor: string | null;
} {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Malformed native directory listing");
  const record = value as Record<string, unknown>;
  if (typeof record.rootPath !== "string" || !isAbsolute(record.rootPath) ||
      typeof record.path !== "string" || !isAbsolute(record.path) ||
      !Array.isArray(record.entries) || record.entries.length > 501 ||
      (record.nextCursor !== null && typeof record.nextCursor !== "string")) {
    throw new Error("Malformed native directory listing");
  }
  const entries: SafeDirectoryEntry[] = [];
  for (const value of record.entries) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Malformed native directory entry");
    const entry = value as Record<string, unknown>;
    if (typeof entry.name !== "string" || entry.name.length === 0 || entry.name.length > 1024 ||
        entry.name.includes("\0") || entry.name.includes("/") ||
        (entry.type !== "file" && entry.type !== "directory" && entry.type !== "symlink" && entry.type !== "other") ||
        !Number.isSafeInteger(entry.sizeBytes) || (entry.sizeBytes as number) < 0 || (entry.sizeBytes as number) > 1_000_000_000_000 ||
        typeof entry.modifiedAtMs !== "number" || !Number.isFinite(entry.modifiedAtMs) ||
        typeof entry.hidden !== "boolean") {
      throw new Error("Malformed native directory entry");
    }
    entries.push({
      name: entry.name,
      type: entry.type,
      sizeBytes: entry.sizeBytes as number,
      modifiedAt: new Date(entry.modifiedAtMs).toISOString(),
      hidden: entry.hidden
    });
  }
  return {
    rootPath: record.rootPath,
    path: record.path,
    entries,
    nextCursor: record.nextCursor as string | null
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

export function normalizeProjectTypes(types: readonly string[]): string[] {
  if (!Array.isArray(types) || types.length > 32) {
    throw new BrokerError("PRECONDITION_FAILED", "Project types must contain at most 32 values");
  }
  const normalized = new Set<string>();
  for (const type of types) {
    if (typeof type !== "string" || type.length < 1 || type.length > 64 || type.includes("\0")) {
      throw new BrokerError("PRECONDITION_FAILED", "Project type is malformed");
    }
    const value = type.normalize("NFKC").toLocaleLowerCase("en-US");
    if (!Object.hasOwn(PROJECT_MARKERS, value)) throw new BrokerError("PRECONDITION_FAILED", "Project type is unsupported");
    normalized.add(value);
  }
  return [...normalized].sort();
}

function addProjectLanguage(languages: Set<string>, name: string, type: SafeDirectoryEntry["type"]): void {
  if (type === "directory" && !PROJECT_SUMMARY_MANIFESTS.has(name)) return;
  const lowerName = name.normalize("NFKC").toLocaleLowerCase("en-US");
  const extension = lowerName.includes(".") ? lowerName.slice(lowerName.lastIndexOf(".")) : "";
  const language = lowerName === "package.json" || [".js", ".jsx", ".mjs", ".cjs"].includes(extension)
    ? "javascript"
    : ["tsconfig.json", ".ts", ".tsx", ".mts", ".cts"].includes(lowerName) || [".ts", ".tsx", ".mts", ".cts"].includes(extension)
      ? "typescript"
      : ["pyproject.toml", "setup.py", "requirements.txt", "pipfile", ".py"].includes(lowerName) || extension === ".py"
        ? "python"
        : ["packages.swift", "package.swift", ".swift"].includes(lowerName) || extension === ".swift"
          ? "swift"
          : ["cargo.toml", ".rs"].includes(lowerName) || extension === ".rs"
            ? "rust"
            : ["go.mod", ".go"].includes(lowerName) || extension === ".go"
              ? "go"
              : ["gemfile", ".rb"].includes(lowerName) || extension === ".rb"
                ? "ruby"
                : ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", ".java", ".kt"].includes(lowerName) || [".java", ".kt"].includes(extension)
                  ? "jvm"
                  : ["dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"].includes(lowerName)
                    ? "docker"
                    : undefined;
  if (language !== undefined && languages.size < 64) languages.add(language);
}

function compileSearchGlob(glob: string | undefined): RegExp | undefined {
  if (glob === undefined) return undefined;
  if (glob.length < 1 || glob.length > 256 || glob.includes("\0")) {
    throw new BrokerError("PRECONDITION_FAILED", "glob is malformed");
  }
  let pattern = "^";
  for (const character of glob) {
    if (character === "*") pattern += ".*";
    else if (character === "?") pattern += ".";
    else pattern += character.replace(/[\\^$+?.()|[\]{}]/gu, "\\$&");
  }
  try {
    return new RegExp(`${pattern}$`, "u");
  } catch {
    throw new BrokerError("PRECONDITION_FAILED", "glob is malformed");
  }
}

function sanitizeSearchSnippet(value: string): string {
  return value
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/gu, "�")
    .slice(0, 2_000);
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

function parseNativeStorageVolume(value: unknown): NativeStorageVolume {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Malformed native storage volume");
  const record = value as Record<string, unknown>;
  if (typeof record.rootPath !== "string" || !isAbsolute(record.rootPath) ||
      typeof record.id !== "string" || !/^[A-Za-z0-9._:/-]{1,256}$/u.test(record.id) ||
      typeof record.name !== "string" || record.name.length < 1 || record.name.length > 256 || record.name.includes("\0") ||
      typeof record.mountPath !== "string" || !isAbsolute(record.mountPath) || record.mountPath.length > 4096 ||
      !Number.isSafeInteger(record.totalBytes) || (record.totalBytes as number) < 0 || (record.totalBytes as number) > 100_000_000_000_000 ||
      !Number.isSafeInteger(record.availableBytes) || (record.availableBytes as number) < 0 || (record.availableBytes as number) > 100_000_000_000_000 ||
      !Number.isSafeInteger(record.usedBytes) || (record.usedBytes as number) < 0 || (record.usedBytes as number) > 100_000_000_000_000 ||
      (record.availableBytes as number) > (record.totalBytes as number) || (record.usedBytes as number) > (record.totalBytes as number)) {
    throw new Error("Malformed native storage volume");
  }
  return {
    rootPath: record.rootPath,
    id: record.id,
    name: record.name,
    mountPath: record.mountPath,
    totalBytes: record.totalBytes as number,
    availableBytes: record.availableBytes as number,
    usedBytes: record.usedBytes as number
  };
}
