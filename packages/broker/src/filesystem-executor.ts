import { Worker } from "node:worker_threads";
import { randomUUID } from "node:crypto";
import { isAbsolute } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import type { FilesystemPathPlan } from "./filesystem-inspector.js";
import type { FilesystemPatchResult } from "./filesystem-patch.js";
import type { FilesystemWorkerCommand, FilesystemWorkerResult } from "./filesystem-worker-protocol.js";
import { BoundedWorkerExecutor } from "./worker-executor.js";

export interface FilesystemExecutionControl {
  timeoutMs: number;
  shouldCancel: () => boolean;
}

export interface WorkerFilesystemExecutorOptions {
  /** Controlled host-test worker only; production uses the fixed worker below. */
  workerUrl?: URL;
}

export interface FilesystemExecutor {
  /** Stop accepting work and terminate owned worker threads during Broker shutdown. */
  close?(): Promise<void>;
  stat(plan: FilesystemPathPlan, followSymlink: boolean, control: FilesystemExecutionControl): Promise<FilesystemWorkerResult>;
  read(
    plan: FilesystemPathPlan,
    offset: number,
    maxBytes: number,
    encoding: "utf8" | "base64" | "metadata",
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult>;
  hash?(
    plan: FilesystemPathPlan,
    algorithm: "sha256" | "sha512",
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult>;
  list?(
    plan: FilesystemPathPlan,
    cursor: string | undefined,
    limit: number,
    includeHidden: boolean,
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult>;
  tree?(
    plan: FilesystemPathPlan,
    depth: number,
    maxEntries: number,
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult>;
  find?(
    plans: readonly FilesystemPathPlan[],
    query: string,
    maxResults: number,
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult>;
  recent?(
    plans: readonly FilesystemPathPlan[],
    sinceSeconds: number,
    limit: number,
    nowMs: number,
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult>;
  searchText?(
    plans: readonly FilesystemPathPlan[],
    query: string,
    glob: string | undefined,
    maxResults: number,
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult>;
  discoverProjects?(
    plans: readonly FilesystemPathPlan[],
    types: readonly string[],
    maxResults: number,
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult>;
  summarizeProject?(
    plan: FilesystemPathPlan,
    includeTree: boolean,
    treeDepth: number,
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult>;
  analyzeStorage?(
    plans: readonly FilesystemPathPlan[],
    topN: number,
    maxDepth: number,
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult>;
  write?(
    plan: FilesystemPathPlan,
    content: Buffer,
    expectedSha256: string | undefined,
    createOnly: boolean,
    control: FilesystemExecutionControl,
    temporaryName?: string
  ): Promise<FilesystemWorkerResult>;
  applyPatch?(
    plan: FilesystemPathPlan,
    patch: string,
    expectedBaseHash: string | undefined,
    control: FilesystemExecutionControl
  ): Promise<FilesystemPatchResult>;
}

export class WorkerFilesystemExecutor implements FilesystemExecutor {
  private readonly executor: BoundedWorkerExecutor<FilesystemWorkerCommand, FilesystemWorkerResult>;

  constructor(maxConcurrent = 4, options: WorkerFilesystemExecutorOptions = {}) {
    const workerUrl = options.workerUrl ?? new URL("./filesystem-worker.js", import.meta.url);
    this.executor = new BoundedWorkerExecutor(
      (command) => new Worker(workerUrl, {
        workerData: command,
        argv: [],
        execArgv: [],
        env: {},
        resourceLimits: { maxOldGenerationSizeMb: 32, maxYoungGenerationSizeMb: 8, stackSizeMb: 2 },
        trackUnmanagedFds: true
      }),
      maxConcurrent
    );
  }

  close(): Promise<void> {
    return this.executor.close();
  }

  activeCount(): number {
    return this.executor.activeCount();
  }

  stat(plan: FilesystemPathPlan, followSymlink: boolean, control: FilesystemExecutionControl): Promise<FilesystemWorkerResult> {
    return this.executor.run({ operation: "stat", plan, followSymlink }, control.timeoutMs, control.shouldCancel)
      .then(validateFilesystemWorkerResult);
  }

  read(
    plan: FilesystemPathPlan,
    offset: number,
    maxBytes: number,
    encoding: "utf8" | "base64" | "metadata",
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult> {
    return this.executor.run({ operation: "read", plan, offset, maxBytes, encoding }, control.timeoutMs, control.shouldCancel)
      .then(validateFilesystemWorkerResult);
  }

  hash(
    plan: FilesystemPathPlan,
    algorithm: "sha256" | "sha512",
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult> {
    return this.executor.run({ operation: "hash", plan, algorithm }, control.timeoutMs, control.shouldCancel)
      .then(validateFilesystemWorkerResult);
  }

  list(
    plan: FilesystemPathPlan,
    cursor: string | undefined,
    limit: number,
    includeHidden: boolean,
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult> {
    return this.executor.run({ operation: "list", plan, cursor, limit, includeHidden }, control.timeoutMs, control.shouldCancel)
      .then(validateFilesystemWorkerResult);
  }

  tree(
    plan: FilesystemPathPlan,
    depth: number,
    maxEntries: number,
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult> {
    return this.executor.run({ operation: "tree", plan, depth, maxEntries }, control.timeoutMs, control.shouldCancel)
      .then(validateFilesystemWorkerResult);
  }

  find(
    plans: readonly FilesystemPathPlan[],
    query: string,
    maxResults: number,
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult> {
    return this.executor.run({ operation: "find", plans, query, maxResults }, control.timeoutMs, control.shouldCancel)
      .then(validateFilesystemWorkerResult);
  }

  recent(
    plans: readonly FilesystemPathPlan[],
    sinceSeconds: number,
    limit: number,
    nowMs: number,
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult> {
    return this.executor.run({ operation: "recent", plans, sinceSeconds, limit, nowMs }, control.timeoutMs, control.shouldCancel)
      .then(validateFilesystemWorkerResult);
  }

  searchText(
    plans: readonly FilesystemPathPlan[],
    query: string,
    glob: string | undefined,
    maxResults: number,
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult> {
    return this.executor.run({ operation: "search_text", plans, query, glob, maxResults }, control.timeoutMs, control.shouldCancel)
      .then(validateFilesystemWorkerResult);
  }

  discoverProjects(
    plans: readonly FilesystemPathPlan[],
    types: readonly string[],
    maxResults: number,
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult> {
    return this.executor.run({ operation: "project_discover", plans, types, maxResults }, control.timeoutMs, control.shouldCancel)
      .then(validateFilesystemWorkerResult);
  }

  summarizeProject(
    plan: FilesystemPathPlan,
    includeTree: boolean,
    treeDepth: number,
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult> {
    return this.executor.run({ operation: "project_summary", plan, includeTree, treeDepth }, control.timeoutMs, control.shouldCancel)
      .then(validateFilesystemWorkerResult);
  }

  analyzeStorage(
    plans: readonly FilesystemPathPlan[],
    topN: number,
    maxDepth: number,
    control: FilesystemExecutionControl
  ): Promise<FilesystemWorkerResult> {
    return this.executor.run({ operation: "storage_analysis", plans, topN, maxDepth }, control.timeoutMs, control.shouldCancel)
      .then(validateFilesystemWorkerResult);
  }

  write(
    plan: FilesystemPathPlan,
    content: Buffer,
    expectedSha256: string | undefined,
    createOnly: boolean,
    control: FilesystemExecutionControl,
    temporaryName?: string
  ): Promise<FilesystemWorkerResult> {
    return this.executor.run({
      operation: "write",
      plan,
      content,
      expectedSha256,
      createOnly,
      tempName: temporaryName ?? `.mac-operator-write-${randomUUID()}`
    }, control.timeoutMs, control.shouldCancel).then(validateFilesystemWorkerResult);
  }

  applyPatch(
    plan: FilesystemPathPlan,
    patch: string,
    expectedBaseHash: string | undefined,
    control: FilesystemExecutionControl
  ): Promise<FilesystemPatchResult> {
    return this.executor.run({ operation: "patch", plan, patch, expectedBaseHash }, control.timeoutMs, control.shouldCancel)
      .then(validateFilesystemWorkerResult)
      .then((value) => {
        if (value.operation !== "patch") throw new BrokerError("EXECUTION_FAILED", "Filesystem worker returned the wrong result type");
        return value;
      });
  }
}

function validateFilesystemWorkerResult(value: FilesystemWorkerResult): FilesystemWorkerResult {
  if (value === null || typeof value !== "object") throw malformed();
  if (value.operation === "stat") {
    const metadata = value.metadata;
    if (metadata === null || typeof metadata !== "object" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(metadata.rootId) ||
        !isAbsolute(metadata.path) || metadata.path.length > 4096 ||
        !["file", "directory", "symlink", "other"].includes(metadata.type) ||
        !Number.isSafeInteger(metadata.sizeBytes) || metadata.sizeBytes < 0 || metadata.sizeBytes > 1_000_000_000_000 ||
        (metadata.modifiedAt !== null && (typeof metadata.modifiedAt !== "string" || !Number.isFinite(Date.parse(metadata.modifiedAt)))) ||
        typeof metadata.mode !== "string" || !/^[0-7]{4}$/u.test(metadata.mode) ||
        typeof metadata.isSymlink !== "boolean" || !/^\d+$/u.test(metadata.device) || !/^\d+$/u.test(metadata.inode)) {
      throw malformed();
    }
    return value;
  }
  if (value.operation === "write") {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value.rootId) ||
        !isAbsolute(value.path) || value.path.length > 4096 ||
        !Number.isSafeInteger(value.bytesWritten) || value.bytesWritten < 0 || value.bytesWritten > 1_048_576 ||
        !/^[a-f0-9]{64}$/u.test(value.sha256) || typeof value.created !== "boolean" ||
        (value.expectedSha256 !== null && !/^[a-f0-9]{64}$/u.test(value.expectedSha256)) ||
        typeof value.expectedMatched !== "boolean" || !/^\d+$/u.test(value.device) || !/^\d+$/u.test(value.inode)) {
      throw malformed();
    }
    return value;
  }
  if (value.operation === "patch") {
    if (typeof value.projectRoot !== "string" || !isAbsolute(value.projectRoot) || value.projectRoot.length > 4096 || value.projectRoot.includes("\0") ||
        (value.result !== "applied" && value.result !== "no_change") || !Array.isArray(value.changedPaths) || value.changedPaths.length > 64 ||
        value.changedPaths.some((path) => !isSafePatchRelativePath(path)) ||
        value.precondition === null || typeof value.precondition !== "object" || Array.isArray(value.precondition) ||
        typeof value.precondition.checked !== "boolean" || typeof value.precondition.matched !== "boolean" ||
        typeof value.precondition.actualSha256 !== "string" || !/^[a-f0-9]{64}$/u.test(value.precondition.actualSha256) ||
        (value.precondition.expectedSha256 !== null && (typeof value.precondition.expectedSha256 !== "string" || !/^[a-f0-9]{64}$/u.test(value.precondition.expectedSha256))) ||
        !Array.isArray(value.files) || value.files.length > 64) {
      throw malformed();
    }
    for (const file of value.files) {
      if (file === null || typeof file !== "object" || typeof file.path !== "string" || !isAbsolute(file.path) || file.path.length > 4096 || file.path.includes("\0") ||
          !/^[a-f0-9]{64}$/u.test(file.sha256) || !Number.isSafeInteger(file.sizeBytes) || file.sizeBytes < 0 || file.sizeBytes > 1_048_576) {
        throw malformed();
      }
    }
    return value;
  }
  if (value.operation === "hash") {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value.rootId) ||
        !isAbsolute(value.path) || value.path.length > 4096 ||
        (value.algorithm !== "sha256" && value.algorithm !== "sha512") ||
        (value.algorithm === "sha256" ? !/^[a-f0-9]{64}$/u.test(value.digest) : !/^[a-f0-9]{128}$/u.test(value.digest)) ||
        !Number.isSafeInteger(value.sizeBytes) || value.sizeBytes < 0 || value.sizeBytes > 1_000_000_000 ||
        !/^\d+$/u.test(value.device) || !/^\d+$/u.test(value.inode)) {
      throw malformed();
    }
    return value;
  }
  if (value.operation === "list") {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value.rootId) ||
        !isAbsolute(value.path) || value.path.length > 4096 ||
        !Array.isArray(value.entries) || value.entries.length > 501 ||
        (value.nextCursor !== null && (typeof value.nextCursor !== "string" || value.nextCursor.length === 0 || value.nextCursor.length > 1024))) {
      throw malformed();
    }
    for (const entry of value.entries) {
      if (entry === null || typeof entry !== "object" ||
          typeof entry.name !== "string" || entry.name.length === 0 || entry.name.length > 1024 ||
          entry.name.includes("\0") || entry.name.includes("/") ||
          !["file", "directory", "symlink", "other"].includes(entry.type) ||
          !Number.isSafeInteger(entry.sizeBytes) || entry.sizeBytes < 0 || entry.sizeBytes > 1_000_000_000_000 ||
          typeof entry.modifiedAt !== "string" || !Number.isFinite(Date.parse(entry.modifiedAt)) ||
          typeof entry.hidden !== "boolean") {
        throw malformed();
      }
    }
    return value;
  }
  if (value.operation === "tree") {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value.rootId) ||
        !isAbsolute(value.root) || value.root.length > 4096 ||
        !Array.isArray(value.entries) || value.entries.length > 5000 || typeof value.truncated !== "boolean") {
      throw malformed();
    }
    for (const entry of value.entries) {
      if (entry === null || typeof entry !== "object" ||
          typeof entry.path !== "string" || !isAbsolute(entry.path) || entry.path.length > 4096 ||
          !["file", "directory", "symlink", "other"].includes(entry.type) ||
          !Number.isSafeInteger(entry.depth) || entry.depth < 0 || entry.depth > 8 ||
          !Number.isSafeInteger(entry.sizeBytes) || entry.sizeBytes < 0 || entry.sizeBytes > 1_000_000_000_000) {
        throw malformed();
      }
    }
    return value;
  }
  if (value.operation === "find") {
    if (!Array.isArray(value.roots) || value.roots.length < 1 || value.roots.length > 32 ||
        typeof value.query !== "string" || value.query.length < 1 || value.query.length > 256 || value.query.includes("\0") ||
        !Array.isArray(value.matches) || value.matches.length > 1000 || typeof value.truncated !== "boolean") {
      throw malformed();
    }
    for (const root of value.roots) {
      if (typeof root !== "string" || !isAbsolute(root) || root.length > 4096 || root.includes("\0")) throw malformed();
    }
    for (const match of value.matches) {
      if (match === null || typeof match !== "object" ||
          typeof match.path !== "string" || !isAbsolute(match.path) || match.path.length > 4096 || match.path.includes("\0") ||
          !["file", "directory", "symlink", "other"].includes(match.type) ||
          !Number.isSafeInteger(match.sizeBytes) || match.sizeBytes < 0 || match.sizeBytes > 1_000_000_000_000 ||
          (match.modifiedAt !== null && (typeof match.modifiedAt !== "string" || !Number.isFinite(Date.parse(match.modifiedAt))))) {
        throw malformed();
      }
    }
    return value;
  }
  if (value.operation === "recent") {
    if (!Array.isArray(value.files) || value.files.length > 1000 || typeof value.truncated !== "boolean") throw malformed();
    for (const file of value.files) {
      if (file === null || typeof file !== "object" ||
          typeof file.path !== "string" || !isAbsolute(file.path) || file.path.length > 4096 || file.path.includes("\0") ||
          !["file", "directory", "symlink", "other"].includes(file.type) ||
          !Number.isSafeInteger(file.sizeBytes) || file.sizeBytes < 0 || file.sizeBytes > 1_000_000_000_000 ||
          typeof file.modifiedAt !== "string" || !Number.isFinite(Date.parse(file.modifiedAt))) {
        throw malformed();
      }
    }
    return value;
  }
  if (value.operation === "search_text") {
    if (typeof value.query !== "string" || value.query.length < 1 || value.query.length > 512 || value.query.includes("\0") ||
        !Array.isArray(value.matches) || value.matches.length > 1000 || typeof value.truncated !== "boolean") {
      throw malformed();
    }
    for (const match of value.matches) {
      if (match === null || typeof match !== "object" ||
          typeof match.path !== "string" || !isAbsolute(match.path) || match.path.length > 4096 || match.path.includes("\0") ||
          !Number.isSafeInteger(match.line) || match.line < 1 || match.line > 1_000_000_000 ||
          !Number.isSafeInteger(match.startColumn) || match.startColumn < 1 || match.startColumn > 1_000_000_000 ||
          !Number.isSafeInteger(match.endColumn) || match.endColumn < match.startColumn || match.endColumn > 1_000_000_000 ||
          typeof match.snippet !== "string" || match.snippet.length > 2000 || /[\u0000-\u001f\u007f]/u.test(match.snippet)) {
        throw malformed();
      }
    }
    return value;
  }
  if (value.operation === "project_discover") {
    if (!Array.isArray(value.projects) || value.projects.length > 500 || typeof value.truncated !== "boolean") throw malformed();
    for (const project of value.projects) {
      if (project === null || typeof project !== "object" ||
          typeof project.root !== "string" || !isAbsolute(project.root) || project.root.length > 4096 || project.root.includes("\0") ||
          typeof project.type !== "string" || !/^[a-z][a-z0-9_-]{0,63}$/u.test(project.type) ||
          !Array.isArray(project.indicators) || project.indicators.length > 32) {
        throw malformed();
      }
      for (const indicator of project.indicators) {
        if (typeof indicator !== "string" || indicator.length < 1 || indicator.length > 128 || indicator.includes("\0") || indicator.includes("/")) {
          throw malformed();
        }
      }
    }
    return value;
  }
  if (value.operation === "project_summary") {
    if (typeof value.projectRoot !== "string" || !isAbsolute(value.projectRoot) || value.projectRoot.length > 4096 || value.projectRoot.includes("\0") ||
        value.vcs === null || typeof value.vcs !== "object" || !["git", "none", "other"].includes(value.vcs.system) ||
        (value.vcs.branch !== undefined && (typeof value.vcs.branch !== "string" || value.vcs.branch.length > 256 || value.vcs.branch.includes("\0"))) ||
        (value.vcs.dirty !== undefined && typeof value.vcs.dirty !== "boolean") ||
        !Array.isArray(value.manifests) || value.manifests.length > 64 ||
        !Array.isArray(value.languages) || value.languages.length > 64 ||
        !Array.isArray(value.treeEntries) || value.treeEntries.length > 1000 ||
        !Array.isArray(value.warnings) || value.warnings.length > 32 || typeof value.truncated !== "boolean") {
      throw malformed();
    }
    for (const manifest of value.manifests) {
      if (typeof manifest !== "string" || manifest.length < 1 || manifest.length > 256 || manifest.includes("\0")) throw malformed();
    }
    for (const language of value.languages) {
      if (typeof language !== "string" || language.length < 1 || language.length > 64 || language.includes("\0")) throw malformed();
    }
    for (const entry of value.treeEntries) {
      if (entry === null || typeof entry !== "object" || typeof entry.path !== "string" || !isAbsolute(entry.path) || entry.path.length > 4096 || entry.path.includes("\0") ||
          !["file", "directory", "symlink", "other"].includes(entry.type) || !Number.isSafeInteger(entry.depth) || entry.depth < 0 || entry.depth > 4) throw malformed();
    }
    for (const warning of value.warnings) {
      if (typeof warning !== "string" || warning.length < 1 || warning.length > 512 || warning.includes("\0")) throw malformed();
    }
    return value;
  }
  if (value.operation === "storage_analysis") {
    if (!Array.isArray(value.volumes) || value.volumes.length > 64 ||
        !Array.isArray(value.consumers) || value.consumers.length > 100 ||
        !Array.isArray(value.analyzedRoots) || value.analyzedRoots.length > 32 ||
        !Array.isArray(value.warnings) || value.warnings.length > 32 || typeof value.truncated !== "boolean") {
      throw malformed();
    }
    for (const volume of value.volumes) {
      if (volume === null || typeof volume !== "object" ||
          typeof volume.id !== "string" || !/^[A-Za-z0-9._:/-]{1,256}$/u.test(volume.id) ||
          typeof volume.name !== "string" || volume.name.length < 1 || volume.name.length > 256 || volume.name.includes("\0") ||
          typeof volume.mountPath !== "string" || !isAbsolute(volume.mountPath) || volume.mountPath.length > 4096 ||
          !Number.isSafeInteger(volume.totalBytes) || volume.totalBytes < 0 || volume.totalBytes > 100_000_000_000_000 ||
          !Number.isSafeInteger(volume.availableBytes) || volume.availableBytes < 0 || volume.availableBytes > volume.totalBytes ||
          !Number.isSafeInteger(volume.usedBytes) || volume.usedBytes < 0 || volume.usedBytes > volume.totalBytes) throw malformed();
    }
    for (const consumer of value.consumers) {
      if (consumer === null || typeof consumer !== "object" ||
          typeof consumer.path !== "string" || !isAbsolute(consumer.path) || consumer.path.length > 4096 || consumer.path.includes("\0") ||
          !Number.isSafeInteger(consumer.sizeBytes) || consumer.sizeBytes < 0 || consumer.sizeBytes > 100_000_000_000_000 ||
          !["file", "directory", "other"].includes(consumer.type)) throw malformed();
    }
    for (const path of value.analyzedRoots) {
      if (typeof path !== "string" || !isAbsolute(path) || path.length > 4096 || path.includes("\0")) throw malformed();
    }
    for (const warning of value.warnings) {
      if (typeof warning !== "string" || warning.length < 1 || warning.length > 512 || warning.includes("\0")) throw malformed();
    }
    return value;
  }
  if (value.operation !== "read" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value.rootId) ||
      !isAbsolute(value.path) || value.path.length > 4096 ||
      !["utf8", "base64", "metadata"].includes(value.encoding) ||
      !Number.isSafeInteger(value.sizeBytes) || value.sizeBytes < 0 || value.sizeBytes > 1_000_000_000 ||
      !/^[a-f0-9]{64}$/u.test(value.sha256) || typeof value.truncated !== "boolean" ||
      !/^\d+$/u.test(value.device) || !/^\d+$/u.test(value.inode) ||
      !Number.isSafeInteger(value.bytesReturned) || value.bytesReturned < 0 || value.bytesReturned > 1_048_576 ||
      (value.encoding === "metadata" ? value.content !== undefined : typeof value.content !== "string") ||
      (typeof value.content === "string" && value.content.length > 1_048_576)) {
    throw malformed();
  }
  return value;
}

function malformed(): BrokerError {
  return new BrokerError("EXECUTION_FAILED", "Filesystem worker returned a malformed result");
}

function isSafePatchRelativePath(value: unknown): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= 4096 && !value.includes("\0") &&
    !value.startsWith("/") && !value.includes("\\") &&
    !value.split("/").some((part) => part === "" || part === "." || part === "..");
}
