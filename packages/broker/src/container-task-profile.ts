import { lstat, realpath } from "node:fs/promises";
import { isAbsolute, join, posix, relative, resolve, sep } from "node:path";
import { BrokerError, parseJsonUtf8Strict, sha256 } from "@mac-operator/contracts";
import { FilesystemInspector } from "./filesystem-inspector.js";
import { isPlainDataRecord } from "./plain-record.js";
import { assertArgumentsDoNotContainSecrets, assertContentDoesNotContainSecrets, assertContentPathAllowed, assertSourceWritePathAllowed } from "./secret-policy.js";
import { freezeResolvedTaskProfile, TaskProfileRegistry, type ResolvedTaskProfile, type TaskRunRequest } from "./task-profile.js";
import type { CodexControllerPreflight } from "./codex-controller.js";

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const OWNER = /^[A-Za-z0-9._:@/-]{1,128}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const MAX_MANIFEST_BYTES = 1_048_576;
const MAX_RUNTIME_MS = 600_000;
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const REQUEST_KEYS = ["profile", "cwd", "args", "asynchronous", "idempotencyKey", "taskId", "maxRuntimeMs"];

export interface ApprovedContainerTask {
  profile: string;
  projectRoot: string;
  manifestPath: string;
  manifestSha256: string;
  scriptName: string;
  scriptValue: string;
  command: readonly string[];
  timeoutMs: number;
  outputCapBytes: number;
}

export interface ContainerWorkspaceAuthorization {
  owner: string;
  isWorktree: boolean;
}

export interface ContainerTaskProfileOptions {
  imageId: string;
  engineId: string;
  entries: readonly ApprovedContainerTask[];
  validateWorkspace: (cwd: string, projectRoot: string, taskId: string) => Promise<ContainerWorkspaceAuthorization>;
  /** Inspect only the fixed image's runtime; never execute a project command here. */
  validateRuntime: (imageId: string, engineId: string, command: readonly string[]) => Promise<boolean>;
  preflight?: () => Promise<CodexControllerPreflight>;
}

export interface ContainerAgentRequest {
  cwd: string;
  taskId: string;
  task: string;
  model?: string;
  executionProfile: "readonly" | "workspace-write" | "test-only";
  maxRuntimeMs: number;
  allowedPaths?: readonly string[];
  projectRoot?: string;
}

/** Manifest approval and workspace ownership stay separate from Engine execution. */
export class ContainerTaskProfileRegistry extends TaskProfileRegistry {
  private readonly options: ContainerTaskProfileOptions;
  private readonly entries = new Map<string, ApprovedContainerTask>();

  constructor(options: ContainerTaskProfileOptions) {
    super([]);
    if (!isPlainDataRecord(options) || !allowedKeys(options, ["imageId", "engineId", "entries", "validateWorkspace", "validateRuntime", "preflight"]) ||
        typeof options.imageId !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(options.imageId) ||
        typeof options.engineId !== "string" || !ID.test(options.engineId) ||
        !dataArray(options.entries, 256) || typeof options.validateWorkspace !== "function" || typeof options.validateRuntime !== "function" ||
        options.preflight !== undefined && typeof options.preflight !== "function") malformed("Container profile configuration is malformed");
    this.options = { ...options, entries: [] };
    for (const entry of options.entries) {
      const safe = snapshotEntry(entry);
      if (this.entries.has(safe.profile)) malformed("Container task profile is duplicated");
      this.entries.set(safe.profile, safe);
    }
  }

  override names(): readonly string[] { return Object.freeze([...this.entries.keys()].sort()); }

  override async resolve(request: TaskRunRequest): Promise<ResolvedTaskProfile> {
    const safe = snapshotRequest(request);
    const entry = this.entries.get(safe.profile);
    if (!entry) throw new BrokerError("TARGET_NOT_FOUND", "Named container task profile was not found");
    if (safe.maxRuntimeMs !== undefined && safe.maxRuntimeMs > entry.timeoutMs) deny(`Task runtime ${safe.maxRuntimeMs} ms exceeds the approved budget of ${entry.timeoutMs} ms for profile ${entry.profile}; max_runtime is in milliseconds and the budget includes workspace staging`);
    const owner = await this.authorize(safe.cwd, entry.projectRoot, safe.taskId!);
    await validateManifest(entry.projectRoot, entry);
    if (safe.cwd !== entry.projectRoot) await validateManifest(safe.cwd, entry);
    if (!await this.options.validateRuntime(this.options.imageId, this.options.engineId, entry.command)) deny("CONTAINER_RUNTIME_UNAVAILABLE");
    return this.resolved(entry.profile, safe.cwd, safe.taskId!, owner, entry.command,
      safe.maxRuntimeMs ?? entry.timeoutMs, entry.outputCapBytes, false, entry.projectRoot);
  }

  /** Read-only readiness provider; no agent turn or task command is started. */
  async agentPreflight(): Promise<CodexControllerPreflight> {
    if (this.options.preflight === undefined) deny("CODEX_CONTROLLER_UNAVAILABLE");
    return await this.options.preflight();
  }

  async resolveAgent(request: ContainerAgentRequest): Promise<ResolvedTaskProfile> {
    const safe = snapshotAgentRequest(request);
    const candidates = [...new Set([...this.entries.values()].map(entry => entry.projectRoot))];
    if (safe.projectRoot !== undefined && !candidates.includes(safe.projectRoot)) deny("Agent project is outside the approved registry");
    let owner: string | undefined;
    let selectedProject: string | undefined;
    for (const projectRoot of safe.projectRoot === undefined ? candidates : [safe.projectRoot]) {
      try { owner = await this.authorize(safe.cwd, projectRoot, safe.taskId); selectedProject = projectRoot; break; }
      catch (error) {
        if (!(error instanceof BrokerError) || !["POLICY_DENIED", "TARGET_NOT_FOUND"].includes(error.errorClass)) throw error;
      }
    }
    if (owner === undefined) deny("Agent workspace is outside the approved managed worktrees");
    const ready = await this.agentPreflight();
    if (!ready.installed || ready.authentication !== "authenticated" || ready.reasonCodes.length || ready.supportedModels.length === 0) deny("CODEX_CONTROLLER_NOT_READY");
    if (safe.model !== undefined && !ready.supportedModels.includes(safe.model)) deny("CODEX_MODEL_UNAVAILABLE");
    const command = ["/usr/local/bin/node"];
    if (!await this.options.validateRuntime(this.options.imageId, this.options.engineId, command)) deny("CONTAINER_RUNTIME_UNAVAILABLE");
    return this.resolved("container.codex", safe.cwd, safe.taskId, owner, command, safe.maxRuntimeMs, 16_384,
      safe.executionProfile !== "workspace-write", selectedProject!, {
        task: safe.task, executionProfile: safe.executionProfile, allowedPaths: safe.allowedPaths ?? [],
        ...(safe.model === undefined ? {} : { model: safe.model })
      });
  }

  private async authorize(cwd: string, projectRoot: string, taskId: string): Promise<string> {
    const authorization = await this.options.validateWorkspace(cwd, projectRoot, taskId);
    if (!isPlainDataRecord(authorization) || !allowedKeys(authorization, ["owner", "isWorktree"]) ||
        typeof authorization.owner !== "string" || !OWNER.test(authorization.owner) || typeof authorization.isWorktree !== "boolean") deny("Workspace authorization is malformed");
    if (!authorization.isWorktree || cwd === projectRoot) deny("AGENT_RUN requires an owned isolated worktree");
    await canonicalDirectory(projectRoot);
    await canonicalDirectory(cwd);
    return authorization.owner;
  }

  private resolved(profile: string, cwd: string, taskId: string, owner: string, command: readonly string[], timeoutMs: number,
    outputCapBytes: number, readonlyWorkspace: boolean, projectRoot: string, agent?: NonNullable<ResolvedTaskProfile["containerExecution"]>["agent"]): ResolvedTaskProfile {
    return freezeResolvedTaskProfile({
      profile, cwd,
      process: { executable: command[0]!, args: command.slice(1), cwd, environment: {}, timeoutMs, outputCapBytes },
      filesystemRoots: [cwd], networkPolicy: "none", networkAllowlist: [], credentialPolicy: "none",
      processTreePolicy: "owned_group", sandboxProfile: "docker-container",
      verificationStrategy: "exit_status_and_declared_task_verification",
      containerExecution: { projectRoot, imageId: this.options.imageId, engineId: this.options.engineId, taskId, owner, readonlyWorkspace,
        ...(agent === undefined ? {} : { agent }) }
    });
  }
}

function snapshotEntry(value: unknown): ApprovedContainerTask {
  if (!isPlainDataRecord(value) || !allowedKeys(value, ["profile", "projectRoot", "manifestPath", "manifestSha256", "scriptName", "scriptValue", "command", "timeoutMs", "outputCapBytes"]) ||
      typeof value.profile !== "string" || !ID.test(value.profile) || !canonicalPath(value.projectRoot) ||
      typeof value.manifestPath !== "string" || typeof value.manifestSha256 !== "string" || !DIGEST.test(value.manifestSha256) ||
      typeof value.scriptName !== "string" || !ID.test(value.scriptName) ||
      typeof value.scriptValue !== "string" || value.scriptValue.length < 1 || value.scriptValue.length > 16_384 || value.scriptValue.includes("\0") ||
      !stringArray(value.command, 64) || value.command.length === 0 || !guestExecutable(value.command[0]) ||
      !budget(value.timeoutMs, MAX_RUNTIME_MS) || !budget(value.outputCapBytes, MAX_OUTPUT_BYTES)) malformed("Approved container task is malformed");
  if (isAbsolute(value.manifestPath) && !canonicalPath(value.manifestPath)) deny("Approved manifest path must be canonical");
  const manifestPath = isAbsolute(value.manifestPath) ? relative(value.projectRoot, value.manifestPath) : value.manifestPath;
  if (!safeRelativePath(manifestPath)) deny("Approved manifest is outside project source");
  assertArgumentsDoNotContainSecrets(value.command);
  assertContentDoesNotContainSecrets(Buffer.from(value.scriptValue));
  return Object.freeze({
    profile: value.profile, projectRoot: value.projectRoot, manifestPath, manifestSha256: value.manifestSha256,
    scriptName: value.scriptName, scriptValue: value.scriptValue, command: Object.freeze([...value.command]),
    timeoutMs: value.timeoutMs as number, outputCapBytes: value.outputCapBytes as number
  });
}

function snapshotRequest(value: unknown): TaskRunRequest {
  if (!isPlainDataRecord(value) || !allowedKeys(value, REQUEST_KEYS) || typeof value.profile !== "string" || !ID.test(value.profile) ||
      !canonicalPath(value.cwd) || typeof value.taskId !== "string" || !ID.test(value.taskId) ||
      value.args !== undefined && (!stringArray(value.args, 0) || value.args.length !== 0) ||
      value.asynchronous !== undefined && typeof value.asynchronous !== "boolean" ||
      value.idempotencyKey !== undefined && (typeof value.idempotencyKey !== "string" || !ID.test(value.idempotencyKey)) ||
      value.maxRuntimeMs !== undefined && !budget(value.maxRuntimeMs, MAX_RUNTIME_MS)) malformed("Container task request is malformed");
  return { profile: value.profile, cwd: value.cwd, taskId: value.taskId,
    ...(value.maxRuntimeMs === undefined ? {} : { maxRuntimeMs: value.maxRuntimeMs as number }) };
}

function snapshotAgentRequest(value: unknown): ContainerAgentRequest {
  if (!isPlainDataRecord(value) || !allowedKeys(value, ["cwd", "taskId", "task", "model", "executionProfile", "maxRuntimeMs", "allowedPaths", "projectRoot"]) ||
      !canonicalPath(value.cwd) || typeof value.taskId !== "string" || !ID.test(value.taskId) ||
      typeof value.task !== "string" || !value.task.trim() || value.task.length > 32_768 || value.task.includes("\0") ||
      value.model !== undefined && (typeof value.model !== "string" || !ID.test(value.model)) ||
      typeof value.executionProfile !== "string" || !["readonly", "workspace-write", "test-only"].includes(value.executionProfile) || !budget(value.maxRuntimeMs, MAX_RUNTIME_MS) ||
      value.allowedPaths !== undefined && (!stringArray(value.allowedPaths, 128) || value.allowedPaths.some(path => !safeRelativePath(path))) ||
      value.projectRoot !== undefined && !canonicalPath(value.projectRoot)) malformed("Container agent request is malformed");
  assertContentDoesNotContainSecrets(Buffer.from(value.task));
  return {
    cwd: value.cwd, taskId: value.taskId, task: value.task,
    executionProfile: value.executionProfile as ContainerAgentRequest["executionProfile"], maxRuntimeMs: value.maxRuntimeMs as number,
    ...(value.model === undefined ? {} : { model: value.model as string }),
    ...(value.projectRoot === undefined ? {} : { projectRoot: value.projectRoot as string }),
    ...(value.allowedPaths === undefined ? {} : { allowedPaths: [...value.allowedPaths as string[]] })
  };
}

async function validateManifest(root: string, entry: ApprovedContainerTask): Promise<void> {
  const path = join(root, entry.manifestPath);
  assertSourceWritePathAllowed(path);
  const inspector = new FilesystemInspector([{ rootId: "container-manifest", path: root, metadata: true, contentRead: true, denyRelativePaths: [] }]);
  const rootBefore = inspector.statPath(root, false);
  const metadata = inspector.statPath(path, false);
  if (metadata.type !== "file" || metadata.isSymlink || metadata.sizeBytes > MAX_MANIFEST_BYTES) deny("Approved manifest must be a bounded regular file");
  const read = inspector.readPlanned(inspector.planPath(path, "content_read"), 0, MAX_MANIFEST_BYTES);
  if (read.truncated || read.sizeBytes > MAX_MANIFEST_BYTES || read.device !== metadata.device || read.inode !== metadata.inode) deny("Approved manifest identity changed");
  assertContentDoesNotContainSecrets(read.content);
  if (sha256(read.content) !== entry.manifestSha256) deny("APPROVED_MANIFEST_CHANGED");
  let manifest: unknown;
  try { manifest = parseJsonUtf8Strict(read.content); } catch { malformed("Approved task manifest must be strict JSON"); }
  if (!isPlainDataRecord(manifest) || !isPlainDataRecord(manifest.scripts) ||
      !Object.hasOwn(manifest.scripts, entry.scriptName) || manifest.scripts[entry.scriptName] !== entry.scriptValue) deny("APPROVED_SCRIPT_CHANGED");
  const rootAfter = inspector.statPath(root, false);
  if (rootBefore.device !== rootAfter.device || rootBefore.inode !== rootAfter.inode) deny("Approved workspace identity changed");
}

async function canonicalDirectory(path: string): Promise<void> {
  assertContentPathAllowed(path);
  try {
    const stat = await lstat(path);
    if (!stat.isDirectory() || stat.isSymbolicLink() || await realpath(path) !== path) deny("Workspace must be a canonical non-symlink directory");
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("TARGET_NOT_FOUND", "Workspace directory was not found");
  }
}

function canonicalPath(value: unknown): value is string {
  return typeof value === "string" && value.length > 1 && value.length <= 4096 && !value.includes("\0") && !value.includes("\n") && isAbsolute(value) && resolve(value) === value;
}

function safeRelativePath(value: string): boolean {
  if (!value || value.length > 4096 || value.includes("\0") || value.includes("\n") || value.includes("\\") || isAbsolute(value) ||
      posix.normalize(value) !== value || value.split("/").some(part => !part || part === "." || part === ".." || part === ".git" || part === "node_modules")) return false;
  try { assertSourceWritePathAllowed(join(sep, "workspace", value)); return true; } catch { return false; }
}

function guestExecutable(value: unknown): value is string {
  return typeof value === "string" && /^\/(?:usr\/local\/bin|usr\/bin|bin|usr\/local\/go\/bin|usr\/local\/cargo\/bin)\/[A-Za-z0-9._-]+$/u.test(value) &&
    !["sudo", "su", "sh", "bash", "zsh", "fish", "env"].includes(posix.basename(value));
}

function dataArray(value: unknown, limit: number): value is unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > limit || Object.getOwnPropertySymbols(value).length ||
      Object.keys(value).length !== value.length || Object.getOwnPropertyNames(value).length !== value.length + 1) return false;
  return Array.from({ length: value.length }, (_, index) => Object.getOwnPropertyDescriptor(value, String(index))).every(descriptor => descriptor !== undefined && "value" in descriptor);
}
function stringArray(value: unknown, limit: number): value is string[] {
  return dataArray(value, limit) && value.every(item => typeof item === "string" && item.length <= 16_384 && !item.includes("\0") && !item.includes("\n")) &&
    value.reduce<number>((total, item) => total + Buffer.byteLength(item as string), 0) <= 64 * 1024;
}
function allowedKeys(value: Record<string, unknown>, keys: readonly string[]): boolean { return Object.keys(value).every(key => keys.includes(key)); }
function budget(value: unknown, max: number): value is number { return Number.isSafeInteger(value) && (value as number) >= 1 && (value as number) <= max; }
function malformed(message: string): never { throw new BrokerError("PRECONDITION_FAILED", message); }
function deny(message: string): never { throw new BrokerError("POLICY_DENIED", message); }
