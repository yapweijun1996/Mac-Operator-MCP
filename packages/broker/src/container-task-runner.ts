import { randomBytes } from "node:crypto";
import { isAbsolute, resolve } from "node:path";
import { BrokerError, parseJsonUtf8Strict } from "@mac-operator/contracts";
import {
  type ContainerTaskHandle, type DockerContainerEngine, type ContainerExecResult
} from "./container-engine.js";
import {
  snapshotWorktreeAsync, parseWorkspaceArchive, importWorkspaceChanges, safeSnapshotPath,
  type ContainerSnapshot, type SnapshotFile
} from "./container-snapshot.js";
import { validateContainerTaskJobMetadata, type ContainerTaskJobMetadata } from "./container-job-metadata.js";
import { type CodexController, type CodexControllerResult, type CodexDynamicTool } from "./codex-controller.js";
import { freezeResolvedTaskProfile, type ResolvedTaskProfile, type ContainerExecutionDescriptor } from "./task-profile.js";
import {
  requireTaskIsolationProof, validateTaskIsolationProof,
  type TaskRunner, type TaskExecutionControl, type TaskExecutionResult, type TaskIsolationProof, type TaskPhaseMs
} from "./task-runner.js";
import { assertContentDoesNotContainSecrets, assertArgumentsDoNotContainSecrets, redactBoundedText } from "./secret-policy.js";
import { isPlainDataRecord } from "./plain-record.js";

const COMMAND_KINDS = new Set(["test", "build", "lint", "typecheck", "package_script"]);
const FORBIDDEN_EXECUTABLES = new Set(["sudo", "su", "doas", "env", "sh", "bash", "zsh", "dash", "csh", "tcsh", "fish"]);
const MAX_RUNTIME_MS = 600_000;
const TOOL_OUTPUT_BYTES = 128 * 1024;
const TOOL_ARGUMENT_BYTES = 48 * 1024;
const FILE_BYTES = 16 * 1024;

type ExecutionPhase = "create" | "ownership" | "start" | "snapshot" | "stage" | "controller" | "command" | "export" | "import";
// Reported timing groups the phases that are one cost to an operator: creation and its ownership record, then the task body.
const PHASE_TIMING_KEY: Record<ExecutionPhase, Exclude<keyof TaskPhaseMs, "cleanup">> = {
  create: "prepare", ownership: "prepare", start: "start", snapshot: "snapshot", stage: "stage",
  controller: "command", command: "command", export: "export", import: "import"
};

type Engine = Pick<DockerContainerEngine, "info" | "inspectImage" | "create" | "start" | "inspect" | "exec" | "uploadArchive" | "downloadArchive" | "kill" | "remove">;
export interface RegisteredContainerCommand {
  name: string;
  projectRoot?: string;
  executable: string;
  args: readonly string[];
  kind?: "test" | "build" | "lint" | "typecheck" | "package_script";
}
export interface ContainerTaskRunnerOptions {
  engine?: Engine;
  imageId?: string;
  engineId?: string;
  enabled?: boolean;
  hostEvidenceAccepted?: boolean;
  isolationProof?: TaskIsolationProof;
  controller?: Pick<CodexController, "run">;
  registeredCommands?: readonly RegisteredContainerCommand[];
  snapshotExcludedPaths?: readonly string[];
  maxConcurrent?: number;
  /** Trusted test seams; none is selected by an MCP argument. */
  snapshotProvider?: (root: string, readonlyWorkspace: boolean, excludedPaths: readonly string[], check: () => void) => ContainerSnapshot | Promise<ContainerSnapshot>;
  parseArchive?: typeof parseWorkspaceArchive;
  importChanges?: typeof importWorkspaceChanges;
}

/** Each task has an owned disposable cgroup and carries no host filesystem mount or credentials. */
export class ContainerTaskRunner implements TaskRunner {
  readonly available: boolean;
  readonly publicEnablement: "production" | "unavailable";
  readonly mechanism = "docker-container" as const;
  readonly isolationProof: TaskIsolationProof | null;
  private readonly engine: Engine | undefined;
  private readonly imageId: string | undefined;
  private readonly engineId: string | undefined;
  private readonly controller: Pick<CodexController, "run"> | undefined;
  private readonly commands: ReadonlyMap<string, RegisteredContainerCommand>;
  private readonly snapshotExcludedPaths: readonly string[];
  private readonly snapshotProvider: NonNullable<ContainerTaskRunnerOptions["snapshotProvider"]>;
  private readonly parseArchive: typeof parseWorkspaceArchive;
  private readonly importChanges: typeof importWorkspaceChanges;
  private readonly maxConcurrent: number;
  private readonly active = new Map<string, { abort: AbortController; finished: Promise<TaskExecutionResult> }>();
  private closed = false;

  constructor(options: ContainerTaskRunnerOptions = {}) {
    this.engine = options.engine;
    this.imageId = options.imageId;
    this.engineId = options.engineId;
    this.controller = options.controller;
    this.isolationProof = options.isolationProof === undefined ? null : validateTaskIsolationProof(options.isolationProof);
    this.available = options.enabled === true && options.hostEvidenceAccepted === true && this.engine !== undefined &&
      this.isolationProof?.sandboxMechanism === this.mechanism && this.isolationProof.processTree === "owned" &&
      this.isolationProof.containerImage?.imageId === this.imageId && this.isolationProof.containerImage?.engineId === this.engineId;
    this.publicEnablement = this.available ? "production" : "unavailable";
    const excluded = options.snapshotExcludedPaths ?? [];
    if (!Array.isArray(excluded) || excluded.length > 64 || excluded.some(path => !safeSnapshotPath(path)) || new Set(excluded).size !== excluded.length) {
      deny("Trusted snapshot exclusions must be unique canonical source-relative paths");
    }
    this.snapshotExcludedPaths = Object.freeze([...excluded]);
    this.maxConcurrent = options.maxConcurrent ?? 2;
    if (!Number.isSafeInteger(this.maxConcurrent) || this.maxConcurrent < 1 || this.maxConcurrent > 8) deny("Container task concurrency is invalid");
    const commands = new Map<string, RegisteredContainerCommand>();
    for (const command of options.registeredCommands ?? []) {
      if (!isPlainDataRecord(command) || Object.keys(command).some(key => !["name", "projectRoot", "executable", "args", "kind"].includes(key)) ||
          typeof command.name !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(command.name) || commands.has(command.name) ||
          command.projectRoot !== undefined && !canonicalProjectRoot(command.projectRoot) ||
          !Array.isArray(command.args) || command.args.length > 64 || !COMMAND_KINDS.has(command.kind ?? "test")) deny("Container command registration is invalid");
      validateCommand(command.executable, command.args);
      commands.set(command.name, Object.freeze({ ...command, args: Object.freeze([...command.args]), kind: command.kind ?? "test" }));
    }
    this.commands = commands;
    this.snapshotProvider = options.snapshotProvider ?? snapshotWorktreeAsync;
    this.parseArchive = options.parseArchive ?? parseWorkspaceArchive;
    this.importChanges = options.importChanges ?? importWorkspaceChanges;
  }

  run(profile: ResolvedTaskProfile, control: TaskExecutionControl): Promise<TaskExecutionResult> {
    if (!this.available || this.closed) return Promise.reject(new BrokerError("POLICY_DENIED", "Accepted container task isolation is unavailable"));
    profile = freezeResolvedTaskProfile(structuredClone(profile));
    control = Object.freeze({ ...control });
    this.validateProfile(profile, control);
    if (this.active.has(profile.cwd)) return Promise.reject(new BrokerError("CONFLICT", "A task already owns this worktree"));
    if (this.active.size >= this.maxConcurrent) return Promise.reject(new BrokerError("CONFLICT", "Container task concurrency limit was reached"));
    const abort = new AbortController();
    const finished = this.execute(profile, control, abort).finally(() => { this.active.delete(profile.cwd); });
    this.active.set(profile.cwd, { abort, finished });
    return finished;
  }

  async close(): Promise<void> {
    this.closed = true;
    for (const entry of this.active.values()) entry.abort.abort();
    const results = await Promise.allSettled([...this.active.values()].map(entry => entry.finished));
    if (results.some(result => result.status === "rejected" || result.value.containerCleanupVerified !== true)) {
      throw new BrokerError("UNKNOWN_OUTCOME", "Container task shutdown remains unverified");
    }
  }

  async recoverContainerTask(metadata: ContainerTaskJobMetadata): Promise<boolean> {
    validateContainerTaskJobMetadata(metadata);
    if (!this.available || metadata.engineId !== this.engineId || metadata.imageId !== this.imageId) return false;
    const handle: ContainerTaskHandle = Object.freeze({ id: metadata.containerId, engineId: metadata.engineId, imageId: metadata.imageId,
      taskId: metadata.taskId, owner: metadata.owner, nonce: metadata.nonce, readonlyWorkspace: metadata.readonlyWorkspace,
      maxRuntimeMs: metadata.maxRuntimeMs, memoryBytes: metadata.memoryBytes, nanoCpus: metadata.nanoCpus, pidsLimit: metadata.pidsLimit });
    return this.cleanup(handle);
  }

  private validateProfile(profile: ResolvedTaskProfile, control: TaskExecutionControl): void {
    requireTaskIsolationProof(this.isolationProof, profile, this.mechanism);
    const descriptor = profile.containerExecution;
    if (!descriptor || !isPlainDataRecord(descriptor) || Object.keys(descriptor).some(key => !["imageId", "engineId", "taskId", "owner", "readonlyWorkspace", "projectRoot", "agent"].includes(key)) ||
        descriptor.imageId !== this.imageId || descriptor.engineId !== this.engineId || typeof descriptor.readonlyWorkspace !== "boolean" ||
        descriptor.projectRoot !== undefined && !canonicalProjectRoot(descriptor.projectRoot) ||
        typeof descriptor.taskId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(descriptor.taskId) || typeof descriptor.owner !== "string" || !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(descriptor.owner) ||
        !isAbsolute(profile.cwd) || resolve(profile.cwd) !== profile.cwd || /[\x00\r\n]/u.test(profile.cwd) || profile.process.cwd !== profile.cwd || profile.filesystemRoots.length !== 1 || profile.filesystemRoots[0] !== profile.cwd ||
        profile.credentialPolicy !== "none" || profile.networkPolicy !== "none" || profile.networkAllowlist.length !== 0 ||
        profile.processTreePolicy !== "owned_group" || profile.executionKind !== undefined && profile.executionKind !== "binary" ||
        profile.process.environment !== undefined && Object.keys(profile.process.environment).length > 0 ||
        typeof control.onContainerCreated !== "function" || typeof control.shouldCancel !== "function" ||
        !Number.isSafeInteger(control.timeoutMs) || control.timeoutMs < 1 || control.timeoutMs > MAX_RUNTIME_MS ||
        !Number.isSafeInteger(profile.process.timeoutMs) || profile.process.timeoutMs < 1 || profile.process.timeoutMs > MAX_RUNTIME_MS ||
        !Number.isSafeInteger(profile.process.outputCapBytes) || profile.process.outputCapBytes < 1 || profile.process.outputCapBytes > 2 * 1024 * 1024) {
      deny("Container task authority, bounds, filesystem or credential profile is invalid");
    }
    if (descriptor.agent !== undefined) {
      const agent = descriptor.agent;
      if (!this.controller || !isPlainDataRecord(agent) || Object.keys(agent).some(key => !["task", "model", "executionProfile", "allowedPaths"].includes(key)) ||
          typeof agent.task !== "string" || agent.task.length < 1 || agent.task.length > 16_384 ||
          !["readonly", "workspace-write", "test-only"].includes(agent.executionProfile) ||
          agent.executionProfile === "workspace-write" && typeof control.onWorkspaceImport !== "function" ||
          descriptor.readonlyWorkspace !== (agent.executionProfile !== "workspace-write") || !Array.isArray(agent.allowedPaths) || agent.allowedPaths.length > 128 ||
          agent.allowedPaths.some(path => !safeSnapshotPath(path)) || agent.model !== undefined && (typeof agent.model !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(agent.model))) deny("Container coding authority is invalid");
      assertContentDoesNotContainSecrets(Buffer.from(agent.task));
    } else {
      const command = this.commands.get(profile.profile);
      if (!command || command.projectRoot !== undefined && command.projectRoot !== descriptor.projectRoot || command.executable !== profile.process.executable || !sameArguments(command.args, profile.process.args)) deny("Task command is absent from the approved container registry");
    }
  }

  private async execute(profile: ResolvedTaskProfile, control: TaskExecutionControl, abort: AbortController): Promise<TaskExecutionResult> {
    const started = Date.now();
    const timeoutMs = Math.min(control.timeoutMs, profile.process.timeoutMs);
    const deadline = started + timeoutMs;
    const changedPaths = new Set<string>();
    let handle: ContainerTaskHandle | undefined;
    let createAttempted = false;
    let snapshot: ContainerSnapshot | undefined;
    let result = outcome("unknown", "UNKNOWN_OUTCOME", null, "", "Task result has not been established", 0);
    let phase: ExecutionPhase = "create";
    let reason: "timeout" | "cancel" | undefined;
    // Each lap books the time since the previous lap to the phase that just ended; a stepped clock cannot make it negative.
    const phaseMs: TaskPhaseMs = {};
    let lapped = started;
    const lap = (): void => {
      const now = Date.now(), key = PHASE_TIMING_KEY[phase];
      phaseMs[key] = (phaseMs[key] ?? 0) + Math.max(0, now - lapped);
      lapped = now;
    };
    const enter = (next: ExecutionPhase): void => { lap(); phase = next; };
    const check = (): void => {
      if (Date.now() >= deadline) { reason = "timeout"; abort.abort(); }
      if (this.closed || control.shouldCancel()) { reason = "cancel"; abort.abort(); }
      if (abort.signal.aborted) throw new BrokerError(reason === "timeout" ? "TIMEOUT" : "CANCELLED", "Container task authority expired or was cancelled");
    };
    const timer = setTimeout(() => { reason = "timeout"; abort.abort(); }, timeoutMs);
    const monitor = setInterval(() => { try { check(); } catch { abort.abort(); } }, 25);
    try {
      check();
      const currentEngine = await this.engine!.info();
      if (currentEngine.id !== this.engineId) deny("Container Engine changed after accepted host evidence");
      const image = await this.engine!.inspectImage(this.imageId!);
      if (image.id !== this.imageId) deny("Container image changed after accepted host evidence");
      check();
      createAttempted = true;
      handle = await this.engine!.create({ image: this.imageId!, taskId: profile.containerExecution!.taskId,
        owner: profile.containerExecution!.owner, nonce: randomBytes(32).toString("hex"), maxRuntimeMs: timeoutMs,
        readonlyWorkspace: profile.containerExecution!.readonlyWorkspace });
      const recordedAtMs = Date.now();
      const metadata: Omit<ContainerTaskJobMetadata, "taskDescriptorDigest"> = {
        schemaVersion: "0.1", containerId: handle.id, engineId: handle.engineId, imageId: handle.imageId, taskId: handle.taskId,
        owner: handle.owner, nonce: handle.nonce, maxRuntimeMs: handle.maxRuntimeMs, readonlyWorkspace: handle.readonlyWorkspace,
        memoryBytes: handle.memoryBytes, nanoCpus: handle.nanoCpus, pidsLimit: handle.pidsLimit,
        recordedAtMs, deadlineAtMs: Math.max(recordedAtMs + 1, Math.min(deadline, recordedAtMs + handle.maxRuntimeMs))
      };
      // Async acknowledgements cannot prove durable ownership before guest code starts.
      enter("ownership");
      const acknowledged = control.onContainerCreated!(Object.freeze(metadata));
      if (acknowledged !== undefined) throw new BrokerError("AUDIT_UNAVAILABLE", "Container ownership persistence must complete synchronously");
      check();
      enter("start");
      await this.engine!.start(handle, { signal: abort.signal, timeoutMs: remaining(deadline) });
      check();
      enter("snapshot");
      snapshot = await this.snapshotProvider(profile.cwd, handle.readonlyWorkspace, this.snapshotExcludedPaths, check);
      check();
      enter("stage");
      await this.engine!.uploadArchive(handle, snapshot.archive, { signal: abort.signal, timeoutMs: remaining(deadline) });
      check();
      if (profile.containerExecution!.agent) {
        const agent = profile.containerExecution!.agent;
        enter("controller");
        const coding = await raceAbort(this.controller!.run({ cwd: profile.cwd, task: agent.task,
          ...(agent.model === undefined ? {} : { model: agent.model }), maxRuntimeMs: remaining(deadline), executionProfile: agent.executionProfile,
          dynamicTools: this.dynamicTools(handle, profile.containerExecution!, deadline, abort.signal, check), signal: abort.signal }), abort.signal);
        result = mapCoding(coding, profile.process.outputCapBytes);
      } else {
        enter("command");
        const executed = await this.engine!.exec(handle, { command: [profile.process.executable, ...profile.process.args],
          timeoutMs: remaining(deadline), outputCapBytes: profile.process.outputCapBytes }, { signal: abort.signal });
        result = outcome(executed.exitCode === 0 ? "completed" : "failed", executed.exitCode === 0 ? "SUCCEEDED" : "EXECUTION_FAILED",
          executed.exitCode, executed.stdout, executed.stderr, 0);
      }
      check();
      if (result.state === "completed" && profile.containerExecution!.agent?.executionProfile === "workspace-write") {
        enter("export");
        const archive = await this.engine!.downloadArchive(handle, { signal: abort.signal, timeoutMs: remaining(deadline) });
        check();
        const files = this.parseArchive(archive, false);
        if (files.some(file => this.isExcluded(file.path))) deny("Task output cannot recreate an excluded snapshot path");
        check();
        enter("import");
        this.importChanges(snapshot, files, profile.containerExecution!.agent?.allowedPaths ?? [], {
          beforeWrite: check,
          onWriteIntent: path => notifyImport(control, path, "intent"),
          onChangedPath: path => { changedPaths.add(path); notifyImport(control, path, "verified"); }
        });
      }
    } catch (error) {
      result = mapError(error, abort.signal.aborted ? reason ?? "cancel" : undefined, phase, timeoutMs);
    } finally {
      clearTimeout(timer); clearInterval(monitor);
      abort.abort();
      lap();
      const cleanupStarted = Date.now();
      const cleanupVerified = handle === undefined ? !createAttempted : await this.cleanup(handle);
      if (handle !== undefined) phaseMs.cleanup = Math.max(0, Date.now() - cleanupStarted);
      if (!cleanupVerified) result = outcome("unknown", "UNKNOWN_OUTCOME", null, "", "Owned container teardown remains unverified", 0);
      const stdout = redactBoundedText(result.stdout, profile.process.outputCapBytes);
      const stderrBudget = Math.max(0, profile.process.outputCapBytes - Buffer.byteLength(stdout.text));
      const stderr = stderrBudget > 0 ? redactBoundedText(result.stderr, stderrBudget) : { text: "", truncated: result.stderr.length > 0 };
      result = { ...result, stdout: stdout.text, stderr: stderr.text, truncated: result.truncated || stdout.truncated || stderr.truncated,
        durationMs: Date.now() - started, containerCleanupVerified: cleanupVerified, changedPaths: [...changedPaths], phaseMs };
    }
    return result;
  }

  private async cleanup(handle: ContainerTaskHandle): Promise<boolean> {
    try {
      const engine = await this.engine!.info({ timeoutMs: 10_000 });
      if (engine.id !== handle.engineId) return false;
      await this.engine!.kill(handle, { timeoutMs: 10_000 });
      await this.engine!.remove(handle, { timeoutMs: 10_000 });
      return true;
    } catch (error) {
      // Absence proves teardown only after a successful exact Engine readback;
      // a missing container never proves that its development task succeeded.
      if (error instanceof BrokerError && error.errorClass === "TARGET_NOT_FOUND") {
        try { return (await this.engine!.info({ timeoutMs: 10_000 })).id === handle.engineId; } catch { return false; }
      }
      return false;
    }
  }

  private dynamicTools(handle: ContainerTaskHandle, descriptor: ContainerExecutionDescriptor, deadline: number, signal: AbortSignal, check: () => void): CodexDynamicTool[] {
    const agent = descriptor.agent!;
    const allowed = (path: string, directory = false): void => {
      if (path !== "" && (!safeSnapshotPath(path) || this.isExcluded(path)) || path === "" && !directory ||
          agent.allowedPaths.length && !agent.allowedPaths.some(scope => path === scope || path.startsWith(`${scope}/`) || directory && (path === "" || scope.startsWith(`${path}/`)))) deny("Coding tool path is outside authorized source paths");
    };
    const fileOperation = async (op: "list" | "read" | "write" | "edit", value: Record<string, unknown>, contextSignal: AbortSignal): Promise<unknown> => {
      check();
      if (typeof value.path !== "string") deny("Coding file path is invalid");
      allowed(value.path, op === "list");
      if (op === "write" || op === "edit") {
        if (agent.executionProfile !== "workspace-write") deny("This coding profile cannot write source");
        for (const text of [value.content, value.oldText, value.newText]) if (text !== undefined) {
          if (typeof text !== "string") deny("Coding source content is invalid");
          assertContentDoesNotContainSecrets(Buffer.from(text));
        }
      }
      const body = JSON.stringify({ ...value, op });
      if (Buffer.byteLength(body) > TOOL_ARGUMENT_BYTES) throw new BrokerError("OUTPUT_LIMIT", "Coding file arguments exceed their byte budget");
      const executed = await this.engine!.exec(handle, { command: ["/usr/local/bin/node", "-e", GUEST_FILE_SCRIPT, body],
        timeoutMs: remaining(deadline), outputCapBytes: TOOL_OUTPUT_BYTES }, { signal: AbortSignal.any([signal, contextSignal]) });
      check();
      if (executed.exitCode !== 0 || executed.stderr) throw new BrokerError("EXECUTION_FAILED", "Isolated coding file operation failed");
      let data: unknown;
      try { data = parseJsonUtf8Strict(Buffer.from(executed.stdout)); } catch { deny("Isolated coding file response is malformed"); }
      if (!isPlainDataRecord(data)) deny("Isolated coding file response is invalid");
      if (op === "read") {
        if (typeof data.content !== "string") deny("Coding read response is invalid");
        assertContentDoesNotContainSecrets(Buffer.from(data.content));
      }
      if (op === "list") {
        if (!Array.isArray(data.entries)) deny("Coding directory response is invalid");
        data.entries = data.entries.filter(entry => {
          if (!isPlainDataRecord(entry) || typeof entry.path !== "string" || !safeSnapshotPath(entry.path)) return false;
          try { allowed(entry.path, entry.type === "directory"); return true; } catch { return false; }
        });
      }
      return data;
    };
    const path = { type: "string", maxLength: 240, description: "Workspace-relative path. Never prefix /workspace or /. Root directory listing uses an empty string." };
    const tools: CodexDynamicTool[] = [
      tool("list_files", "List authorized source files in the isolated workspace.", { path, offset: { type: "integer", minimum: 0, maximum: 10_000 }, limit: { type: "integer", minimum: 1, maximum: 100 } }, ["path"], (value, context) => fileOperation("list", value, context.signal)),
      tool("read_file", "Read a bounded UTF-8 source segment from the isolated workspace.", { path, offset: { type: "integer", minimum: 0, maximum: 8 * 1024 * 1024 }, maxBytes: { type: "integer", minimum: 1, maximum: FILE_BYTES } }, ["path"], (value, context) => fileOperation("read", value, context.signal))
    ];
    if (agent.executionProfile === "workspace-write") {
      tools.push(tool("write_file", "Atomically write authorized source text in the isolated workspace.", { path, content: { type: "string", maxLength: 32_768 } }, ["path", "content"], (value, context) => fileOperation("write", value, context.signal)),
        tool("edit_file", "Replace one exact text occurrence in an authorized source file.", { path, oldText: { type: "string", minLength: 1, maxLength: 16_384 }, newText: { type: "string", maxLength: 16_384 } }, ["path", "oldText", "newText"], (value, context) => fileOperation("edit", value, context.signal)));
    }
    const commands = [...this.commands.values()].filter(command => descriptor.projectRoot !== undefined && command.projectRoot === descriptor.projectRoot &&
      (agent.executionProfile === "workspace-write" || agent.executionProfile === "test-only" && command.kind === "test"));
    if (commands.length) tools.push(tool("run_registered_command", "Run one existing approved validation command in the isolated workspace.", { name: { type: "string", enum: commands.map(command => command.name) } }, ["name"], async (value, context) => {
      check();
      const command = commands.find(command => command.name === value.name);
      if (!command) deny("Coding command is not registered for this execution profile");
      const output = await this.engine!.exec(handle, { command: [command.executable, ...command.args], timeoutMs: remaining(deadline), outputCapBytes: TOOL_OUTPUT_BYTES },
        { signal: AbortSignal.any([signal, context.signal]) });
      check();
      return { exitCode: output.exitCode, stdout: redactBoundedText(output.stdout, 32_768).text, stderr: redactBoundedText(output.stderr, 16_384).text };
    }));
    return tools;
  }

  private isExcluded(path: string): boolean {
    return this.snapshotExcludedPaths.some(excluded => path === excluded || path.startsWith(`${excluded}/`));
  }
}

function tool(name: string, description: string, properties: Record<string, unknown>, required: string[], handler: CodexDynamicTool["handler"]): CodexDynamicTool {
  return { name, description, inputSchema: { type: "object", properties, required, additionalProperties: false }, handler };
}
function validateCommand(executable: string, args: readonly string[]): void {
  if (typeof executable !== "string" || !isAbsolute(executable) || executable.includes("\0") || FORBIDDEN_EXECUTABLES.has(executable.split("/").at(-1)!) ||
      args.some(value => typeof value !== "string" || value.includes("\0")) || Buffer.byteLength(args.join("\0")) > 32 * 1024) deny("Container command must be approved argv without shell or privilege escalation");
  assertArgumentsDoNotContainSecrets(args);
}
function sameArguments(left: readonly string[], right: readonly string[]): boolean { return left.length === right.length && left.every((value, index) => value === right[index]); }
function canonicalProjectRoot(value: unknown): boolean { return typeof value === "string" && isAbsolute(value) && resolve(value) === value && !/[\x00\r\n]/u.test(value); }
function notifyImport(control: TaskExecutionControl, path: string, phase: "intent" | "verified"): void {
  const acknowledged = control.onWorkspaceImport!(path, phase);
  if (acknowledged !== undefined) throw new BrokerError("AUDIT_UNAVAILABLE", "Workspace import audit must persist synchronously");
}
function remaining(deadline: number): number { const ms = deadline - Date.now(); if (ms < 1) throw new BrokerError("TIMEOUT", "Container task deadline expired"); return ms; }
function deny(message: string): never { throw new BrokerError("POLICY_DENIED", message); }
function outcome(state: TaskExecutionResult["state"], resultClass: TaskExecutionResult["resultClass"], exitCode: number | null, stdout: string, stderr: string, durationMs: number): TaskExecutionResult {
  return { state, resultClass, exitCode, stdout, stderr, durationMs, truncated: false, verification: { status: state === "completed" ? "verified" : state === "unknown" ? "unknown" : "failed" } };
}
function mapCoding(result: CodexControllerResult, cap: number): TaskExecutionResult {
  const classes = { completed: "SUCCEEDED", failed: "EXECUTION_FAILED", cancelled: "CANCELLED", timed_out: "TIMEOUT" } as const;
  const output = redactBoundedText(result.output, cap);
  return { ...outcome(result.status, classes[result.status], result.status === "completed" ? 0 : null, output.text, result.reasonCodes.join(","), 0), truncated: output.truncated };
}
function mapError(error: unknown, aborted?: "timeout" | "cancel", phase?: string, timeoutMs?: number): TaskExecutionResult {
  const name = aborted === "timeout" ? "TIMEOUT" : aborted === "cancel" ? "CANCELLED" : error instanceof BrokerError ? error.errorClass : "UNKNOWN_OUTCOME";
  if (name === "TIMEOUT") {
    // The deadline covers Engine checks, start, staging and the command; naming the phase shows which one consumed it.
    const detail = timeoutMs === undefined ? "" : ` of ${timeoutMs} ms in phase "${phase ?? "unknown"}"; it covers Engine checks, container start, workspace staging and the command, so if max_runtime is below the profile's approved maximum, raising it may help`;
    return outcome("timed_out", "TIMEOUT", null, "", `Container task exceeded its deadline${detail}`, 0);
  }
  if (name === "CANCELLED") return outcome("cancelled", "CANCELLED", null, "", "Container task was cancelled", 0);
  if (name === "OUTPUT_LIMIT") return outcome("failed", "OUTPUT_LIMIT", null, "", "Container task exceeded its output limit", 0);
  if (name === "UNKNOWN_OUTCOME" || name === "AUDIT_UNAVAILABLE") return outcome("unknown", "UNKNOWN_OUTCOME", null, "", "Container task outcome could not be verified", 0);
  return outcome("failed", "EXECUTION_FAILED", null, "", `Container task failed a validation or execution check [${name}${phase === undefined ? "" : `/${phase}`}${safeFailureDetail(error)}]`, 0);
}
function safeFailureDetail(error: unknown): string {
  if (!(error instanceof BrokerError)) return "";
  const messages: Record<string, string> = {
    "Container Engine response transport failed": "ENGINE_RESPONSE_TRANSPORT",
    "Container Engine response ended unexpectedly": "ENGINE_RESPONSE_ABORTED",
    "Container Engine request transport failed": "ENGINE_REQUEST_TRANSPORT",
    "Fixed workspace staging did not verify": "STAGING_ACK_DENIED",
    "Task exec identity, user or exit state did not verify": "EXEC_READBACK_DENIED"
  };
  const fixed = Object.hasOwn(messages, error.message) ? messages[error.message] : undefined;
  if (fixed) return `/${fixed}`;
  const transport = /^Container Engine request transport failed \((ECONNRESET|EPIPE|EMFILE|ENFILE|ENOBUFS|EACCES|ENOENT|ECONNREFUSED)(?:\/(info|inspect|exec-create|exec-start|control))?\)$/u.exec(error.message);
  if (transport !== null) return `/ENGINE_REQUEST_${transport[1]}${transport[2] === undefined ? "" : `/${transport[2]}`}`;
  const status = /^Container Engine operation failed with status ([1-5][0-9]{2})$/u.exec(error.message)?.[1];
  return status === undefined ? "" : `/ENGINE_HTTP_${status}`;
}
async function raceAbort<T>(pending: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) throw new BrokerError("CANCELLED", "Container coding request was cancelled");
  let rejectAbort: ((error: BrokerError) => void) | undefined;
  const cancelled = new Promise<T>((_resolve, reject) => { rejectAbort = reject; });
  const onAbort = (): void => rejectAbort?.(new BrokerError("CANCELLED", "Container coding request was cancelled"));
  signal.addEventListener("abort", onAbort, { once: true });
  try { return await Promise.race([pending, cancelled]); } finally { signal.removeEventListener("abort", onAbort); }
}

// Descriptor paths pin every directory to this process's own Linux fd table.
// Source operations never follow user-created links, and output is one bounded JSON object.
const GUEST_FILE_SCRIPT = String.raw`
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const q=JSON.parse(process.argv[1]),C=fs.constants,fds=[];
const fail=()=>{throw Error('ISOLATED_FILE_OPERATION_DENIED')};
const valid=p=>typeof p==='string'&&p.length<=240&&path.posix.normalize(p)===p&&!p.startsWith('/')&&!/[\x00-\x1f\\]/.test(p)&&p.split('/').every(s=>s&&s!=='.'&&s!=='..'&&s!=='.git');
const openDir=(p,create=false)=>{let fd=fs.openSync('/workspace',C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW);fds.push(fd);for(const part of p){pinned(fd);const at='/proc/self/fd/'+fd+'/'+part;if(create){try{fs.mkdirSync(at,{mode:0o700});fs.fsyncSync(fd);}catch(e){if(e.code!=='EEXIST')throw e;}}fd=fs.openSync(at,C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW);fds.push(fd);pinned(fd);}return fd;};
const pinned=fd=>{const p=fs.readlinkSync('/proc/self/fd/'+fd);if(p!=='/workspace'&&!p.startsWith('/workspace/'))fail();};
try{
if(q.path!==''&&!valid(q.path)||q.path===''&&q.op!=='list')fail();
let result;
if(q.op==='list'){
const parts=q.path?q.path.split('/'):[],fd=openDir(parts);pinned(fd);
const offset=q.offset??0,limit=q.limit??100;if(!Number.isSafeInteger(offset)||offset<0||offset>10000||!Number.isSafeInteger(limit)||limit<1||limit>100)fail();
const names=fs.readdirSync('/proc/self/fd/'+fd).sort(),entries=[];
for(const name of names.slice(offset,offset+limit)){const p=q.path?q.path+'/'+name:name;if(!valid(p))continue;const s=fs.lstatSync('/proc/self/fd/'+fd+'/'+name);if(s.isSymbolicLink()||!s.isFile()&&!s.isDirectory())continue;entries.push({path:p,type:s.isDirectory()?'directory':'file',size:s.size});}
pinned(fd);result={entries,nextOffset:offset+limit<names.length?offset+limit:null};
}else{
const parts=q.path.split('/'),name=parts.pop(),fd=openDir(parts,q.op==='write'),target='/proc/self/fd/'+fd+'/'+name;pinned(fd);
if(q.op==='read'){
const offset=q.offset??0,max=q.maxBytes??16384;if(!Number.isSafeInteger(offset)||offset<0||offset>8388608||!Number.isSafeInteger(max)||max<1||max>16384)fail();
const file=fs.openSync(target,C.O_RDONLY|C.O_NOFOLLOW);fds.push(file);const stat=fs.fstatSync(file);if(!stat.isFile()||stat.size>8388608)fail();
const bytes=Buffer.alloc(max),n=fs.readSync(file,bytes,0,max,offset);pinned(fd);result={path:q.path,content:new TextDecoder('utf-8',{fatal:true}).decode(bytes.subarray(0,n)),nextOffset:offset+n<stat.size?offset+n:null};
}else if(q.op==='write'||q.op==='edit'){
let content=q.content;
if(q.op==='edit'){
if(typeof q.oldText!=='string'||!q.oldText||typeof q.newText!=='string')fail();const file=fs.openSync(target,C.O_RDONLY|C.O_NOFOLLOW);fds.push(file);const stat=fs.fstatSync(file);if(!stat.isFile()||stat.size>8388608)fail();
const bytes=Buffer.alloc(stat.size+1),n=fs.readSync(file,bytes,0,bytes.length,0);if(n!==stat.size)fail();const before=new TextDecoder('utf-8',{fatal:true}).decode(bytes.subarray(0,n));const at=before.indexOf(q.oldText);if(at<0||before.indexOf(q.oldText,at+1)>=0)fail();content=before.slice(0,at)+q.newText+before.slice(at+q.oldText.length);
}
if(typeof content!=='string'||Buffer.byteLength(content)>8388608)fail();try{const s=fs.lstatSync(target);if(!s.isFile()||s.isSymbolicLink())fail();}catch(e){if(e.code!=='ENOENT')throw e;}
pinned(fd);const temp='/proc/self/fd/'+fd+'/.mops-edit-'+crypto.randomBytes(16).toString('hex');let file;
try{file=fs.openSync(temp,C.O_WRONLY|C.O_CREAT|C.O_EXCL|C.O_NOFOLLOW,0o600);fs.writeFileSync(file,content);fs.fsyncSync(file);pinned(fd);fs.renameSync(temp,target);fs.fsyncSync(fd);pinned(fd);}finally{if(file!==undefined)fs.closeSync(file);try{fs.unlinkSync(temp);}catch(e){if(e.code!=='ENOENT')throw e;}}
result={path:q.path,writtenBytes:Buffer.byteLength(content)};
}else fail();
}
process.stdout.write(JSON.stringify(result));
}catch{process.stderr.write('ISOLATED_FILE_OPERATION_DENIED');process.exitCode=1;}finally{for(const fd of fds.reverse())try{fs.closeSync(fd);}catch{}}
`;
