import { spawn, type ChildProcess } from "node:child_process";
import { lstat, realpath } from "node:fs/promises";
import { createRequire } from "node:module";
import { isAbsolute, resolve } from "node:path";
import { BrokerError } from "@mac-operator/contracts";

const MAX_ARGUMENTS = 128;
const MAX_ARGUMENT_BYTES = 64 * 1024;
const MAX_ENVIRONMENT_KEYS = 64;
const MAX_ENVIRONMENT_BYTES = 64 * 1024;
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_TIMEOUT_MS = 600_000;
const DEFAULT_POLL_INTERVAL_MS = 25;
const DEFAULT_TERMINATION_GRACE_MS = 250;
const SECRET_ENV_KEY = /(?:API|AUTH|COOKIE|CREDENTIAL|KEY|PASSWORD|PASSWD|SECRET|TOKEN|AWS|GITHUB|OPENAI|SSH)/iu;
const require = createRequire(import.meta.url);

interface NativeProcessTreeAdapter {
  listDescendantProcesses(pid: number): unknown;
  isProcessIdentityAlive(pid: number, startTimeMicros: number): unknown;
  getProcessIdentity(pid: number): unknown;
}

interface ProcessTreeIdentity {
  pid: number;
  startTimeMicros: number;
}

export interface ProcessExecutionRequest {
  /** Broker-resolved executable; shell strings and relative paths are rejected. */
  executable: string;
  args: readonly string[];
  /** Broker-authorized, canonical working directory. */
  cwd: string;
  /** Explicit profile environment. Omitted means an empty environment. */
  environment?: Readonly<Record<string, string>>;
  timeoutMs: number;
  outputCapBytes: number;
  shouldCancel?: () => boolean;
}

export interface ProcessSupervisorOptions {
  maxConcurrent?: number;
  pollIntervalMs?: number;
  terminationGraceMs?: number;
  allowedEnvironmentKeys?: readonly string[];
}

export type ProcessExecutionState = "completed" | "failed" | "cancelled" | "timed_out" | "unknown";

export interface ProcessExecutionResult {
  state: ProcessExecutionState;
  resultClass: "SUCCEEDED" | "EXECUTION_FAILED" | "CANCELLED" | "TIMEOUT" | "OUTPUT_LIMIT" | "UNKNOWN_OUTCOME";
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  /** Bounded raw output; callers must redact before audit or persistence. */
  stdout: string;
  /** Bounded raw output; callers must redact before audit or persistence. */
  stderr: string;
  truncated: boolean;
  durationMs: number;
  processId: number;
  processGroupId: number;
  terminationObserved: boolean;
}

export class ProcessSupervisor {
  private activeProcesses = 0;
  private readonly maxConcurrent: number;
  private readonly pollIntervalMs: number;
  private readonly terminationGraceMs: number;
  private readonly allowedEnvironmentKeys: ReadonlySet<string>;

  constructor(options: ProcessSupervisorOptions = {}) {
    this.maxConcurrent = options.maxConcurrent ?? 4;
    this.pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    this.terminationGraceMs = options.terminationGraceMs ?? DEFAULT_TERMINATION_GRACE_MS;
    this.allowedEnvironmentKeys = new Set(options.allowedEnvironmentKeys ?? []);
    if (!Number.isSafeInteger(this.maxConcurrent) || this.maxConcurrent < 1 || this.maxConcurrent > 64 ||
        !Number.isSafeInteger(this.pollIntervalMs) || this.pollIntervalMs < 5 || this.pollIntervalMs > 1_000 ||
        !Number.isSafeInteger(this.terminationGraceMs) || this.terminationGraceMs < 25 || this.terminationGraceMs > 10_000) {
      throw new Error("Process supervisor limits are outside the supported range");
    }
    for (const key of this.allowedEnvironmentKeys) validateEnvironmentKey(key);
  }

  async run(request: ProcessExecutionRequest): Promise<ProcessExecutionResult> {
    await validateRequest(request, this.allowedEnvironmentKeys);
    if (this.cancelled(request.shouldCancel)) {
      throw new BrokerError("CANCELLED", "Process authority was revoked before execution");
    }
    if (this.activeProcesses >= this.maxConcurrent) {
      throw new BrokerError("CONFLICT", "Process capacity is exhausted", true);
    }

    const environment = Object.fromEntries(Object.entries(request.environment ?? {}));
    const startedAtMs = Date.now();
    let child: ChildProcess;
    try {
      child = spawn(request.executable, [...request.args], {
        cwd: request.cwd,
        env: environment,
        shell: false,
        detached: true,
        stdio: ["ignore", "pipe", "pipe"]
      });
    } catch {
      throw new BrokerError("EXECUTION_FAILED", "Child process could not be started");
    }
    const childPid = child.pid;
    if (typeof childPid !== "number" || !Number.isSafeInteger(childPid) || childPid <= 0) {
      child.kill("SIGKILL");
      throw new BrokerError("EXECUTION_FAILED", "Child process did not expose a valid process identity");
    }
    const processId = childPid;
    const processTree = createProcessTreeTracker(processId);
    if (process.platform === "darwin" && processTree === undefined) {
      signalProcessGroup(child, processId, "SIGKILL");
      throw new BrokerError("POLICY_DENIED", "Process tree observer is unavailable");
    }
    this.activeProcesses += 1;
    return this.observe(child, request, processId, startedAtMs, processTree);
  }

  activeCount(): number {
    return this.activeProcesses;
  }

  private observe(
    child: ChildProcess,
    request: ProcessExecutionRequest,
    processId: number,
    startedAtMs: number,
    processTree: ProcessTreeTracker | undefined
  ): Promise<ProcessExecutionResult> {
    return new Promise((resolveResult) => {
      let settled = false;
      let terminationReason: "cancelled" | "timed_out" | "output_limit" | "orphaned" | null = null;
      let terminationRequested = false;
      let terminationTimer: NodeJS.Timeout | undefined;
      let groupDrainTimer: NodeJS.Timeout | undefined;
      let orphanReaperTimer: NodeJS.Timeout | undefined;
      let timeoutTimer: NodeJS.Timeout | undefined;
      let cancellationPoll: NodeJS.Timeout | undefined;
      let groupDrainDeadlineMs: number | undefined;
      let childExitCode: number | null = null;
      let childExitSignal: NodeJS.Signals | null = null;
      let released = false;
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let stdout: Buffer<ArrayBufferLike> = Buffer.alloc(0);
      let stderr: Buffer<ArrayBufferLike> = Buffer.alloc(0);
      let spawnError = false;

      processTree?.sample();

      const clearTimers = () => {
        if (timeoutTimer) clearTimeout(timeoutTimer);
        if (cancellationPoll) clearInterval(cancellationPoll);
        if (terminationTimer) clearTimeout(terminationTimer);
        if (groupDrainTimer) clearTimeout(groupDrainTimer);
      };
      const release = () => {
        if (released) return;
        released = true;
        this.activeProcesses -= 1;
      };
      const append = (current: Buffer, chunk: Buffer, currentBytes: number): { value: Buffer; bytes: number; overflow: boolean } => {
        const remaining = request.outputCapBytes - stdoutBytes - stderrBytes;
        if (remaining <= 0) return { value: current, bytes: currentBytes, overflow: chunk.byteLength > 0 };
        const accepted = chunk.subarray(0, Math.min(remaining, chunk.byteLength));
        return {
          value: accepted.byteLength === 0 ? current : Buffer.concat([current, accepted]),
          bytes: currentBytes + accepted.byteLength,
          overflow: accepted.byteLength < chunk.byteLength
        };
      };
      const groupState = (): "alive" | "none" | "unknown" => {
        const rootState = processTree?.rootState() ?? "alive";
        if (rootState === "unknown") return "unknown";
        if (!processGroupAlive(processId)) return "none";
        return processTree?.rootIdentityUnavailable ? "unknown" : "alive";
      };
      const terminate = (reason: "cancelled" | "timed_out" | "output_limit" | "orphaned") => {
        if (terminationReason === null) terminationReason = reason;
        if (terminationRequested) return;
        terminationRequested = true;
        processTree?.sample();
        const rootState = processTree?.rootState() ?? "alive";
        if (rootState === "unknown") {
          finishUnknown();
          return;
        }
        if (rootState === "alive") signalProcessGroup(child, processId, "SIGTERM");
        processTree?.signal("SIGTERM");
        groupDrainDeadlineMs ??= Date.now() + Math.max(this.terminationGraceMs * 3, 1_000);
        terminationTimer = setTimeout(() => {
          const currentRootState = processTree?.rootState() ?? "alive";
          if (currentRootState === "alive") signalProcessGroup(child, processId, "SIGKILL");
          processTree?.signal("SIGKILL");
          waitForGroupDrain();
        }, this.terminationGraceMs);
        terminationTimer.unref();
      };
      const waitForGroupDrain = () => {
        if (settled) return;
        processTree?.sample();
        const rootState = processTree?.rootState() ?? "alive";
        const descendantState = processTree?.aliveState() ?? "none";
        const currentGroupState = groupState();
        if (rootState === "unknown" || processTree?.observationFailed || descendantState === "unknown" || currentGroupState === "unknown") {
          finishUnknown();
          return;
        }
        if (currentGroupState === "none" && descendantState === "none") {
          finish(childExitCode, childExitSignal);
          return;
        }
        if (descendantState === "alive" && terminationReason === null) terminate("orphaned");
        if (groupDrainDeadlineMs !== undefined && Date.now() >= groupDrainDeadlineMs) {
          finishUnknown();
          return;
        }
        groupDrainTimer = setTimeout(waitForGroupDrain, this.pollIntervalMs);
        groupDrainTimer.unref();
      };
      const finish = (code: number | null, signal: NodeJS.Signals | null) => {
        if (settled) return;
        settled = true;
        clearTimers();
        release();
        const durationMs = Math.max(0, Date.now() - startedAtMs);
        const state = terminationReason === "cancelled" ? "cancelled" :
          terminationReason === "timed_out" ? "timed_out" :
          terminationReason === "orphaned" ? "unknown" :
          terminationReason === "output_limit" ? "failed" :
          spawnError || code !== 0 ? "failed" : "completed";
        const resultClass = terminationReason === "cancelled" ? "CANCELLED" :
          terminationReason === "timed_out" ? "TIMEOUT" :
          terminationReason === "orphaned" ? "UNKNOWN_OUTCOME" :
          terminationReason === "output_limit" ? "OUTPUT_LIMIT" :
          spawnError || code !== 0 ? "EXECUTION_FAILED" : "SUCCEEDED";
        resolveResult({
          state,
          resultClass,
          exitCode: code,
          signal,
          stdout: stdout.toString("utf8"),
          stderr: stderr.toString("utf8"),
          truncated: terminationReason === "output_limit",
          durationMs,
          processId,
          processGroupId: processId,
          terminationObserved: true
        });
      };
      const finishUnknown = () => {
        if (settled) return;
        settled = true;
        clearTimers();
        const rootState = processTree?.rootState() ?? "alive";
        const currentGroupState = groupState();
        const descendantState = processTree?.aliveState() ?? "none";
        if (rootState !== "unknown" && currentGroupState === "none" && descendantState === "none") release();
        else {
          orphanReaperTimer = setInterval(() => {
            processTree?.sample();
            const currentRootState = processTree?.rootState() ?? "alive";
            const currentGroupState = groupState();
            const currentDescendantState = processTree?.aliveState() ?? "none";
            if (currentRootState !== "unknown" && currentGroupState === "none" && currentDescendantState === "none") {
              if (orphanReaperTimer) clearInterval(orphanReaperTimer);
              orphanReaperTimer = undefined;
              release();
            }
          }, this.pollIntervalMs);
          orphanReaperTimer.unref();
        }
        resolveResult({
          state: "unknown",
          resultClass: "UNKNOWN_OUTCOME",
          exitCode: null,
          signal: null,
          stdout: stdout.toString("utf8"),
          stderr: stderr.toString("utf8"),
          truncated: terminationReason === "output_limit",
          durationMs: Math.max(0, Date.now() - startedAtMs),
          processId,
          processGroupId: processId,
          terminationObserved: false
        });
      };

      child.stdout?.on("data", (chunk: Buffer | string) => {
        if (settled) return;
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        const appended = append(stdout, bytes, stdoutBytes);
        stdout = appended.value;
        stdoutBytes = appended.bytes;
        if (appended.overflow) terminate("output_limit");
      });
      child.stderr?.on("data", (chunk: Buffer | string) => {
        if (settled) return;
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        const appended = append(stderr, bytes, stderrBytes);
        stderr = appended.value;
        stderrBytes = appended.bytes;
        if (appended.overflow) terminate("output_limit");
      });
      child.once("error", () => { spawnError = true; });
      child.once("close", (code, signal) => {
        childExitCode = code;
        childExitSignal = signal;
        if (settled) return;
        processTree?.sample();
        const rootState = processTree?.rootState() ?? "alive";
        const descendantState = processTree?.aliveState() ?? "none";
        const currentGroupState = groupState();
        if (rootState === "unknown" || processTree?.observationFailed || descendantState === "unknown" || currentGroupState === "unknown") {
          finishUnknown();
        } else if (currentGroupState === "alive" || descendantState === "alive") {
          if (terminationReason === null) {
            groupDrainDeadlineMs ??= Date.now() + Math.max(this.terminationGraceMs * 3, 1_000);
            terminate("orphaned");
          }
          waitForGroupDrain();
        } else {
          finish(code, signal);
        }
      });

      timeoutTimer = setTimeout(() => terminate("timed_out"), request.timeoutMs);
      cancellationPoll = setInterval(() => {
        processTree?.sample();
        if (this.cancelled(request.shouldCancel)) terminate("cancelled");
      }, this.pollIntervalMs);
      timeoutTimer.unref();
      cancellationPoll.unref();
    });
  }

  private cancelled(check: (() => boolean) | undefined): boolean {
    if (!check) return false;
    try { return check(); }
    catch { return true; }
  }
}

async function validateRequest(request: ProcessExecutionRequest, allowedEnvironmentKeys: ReadonlySet<string>): Promise<void> {
  if (!isCanonicalAbsolutePath(request.executable) || !isCanonicalAbsolutePath(request.cwd) ||
      !Array.isArray(request.args) || request.args.length > MAX_ARGUMENTS ||
      !Number.isSafeInteger(request.timeoutMs) || request.timeoutMs < 1 || request.timeoutMs > MAX_TIMEOUT_MS ||
      !Number.isSafeInteger(request.outputCapBytes) || request.outputCapBytes < 1 || request.outputCapBytes > MAX_OUTPUT_BYTES) {
    throw new BrokerError("PRECONDITION_FAILED", "Process request limits or paths are invalid");
  }
  const argumentBytes = request.args.reduce((total, argument) => {
    if (typeof argument !== "string" || argument.includes("\0") || argument.length > 4_096) {
      throw new BrokerError("PRECONDITION_FAILED", "Process argument is invalid");
    }
    return total + Buffer.byteLength(argument, "utf8");
  }, 0);
  if (argumentBytes > MAX_ARGUMENT_BYTES) throw new BrokerError("PRECONDITION_FAILED", "Process arguments exceed the supported size");
  const environmentEntries = Object.entries(request.environment ?? {});
  if (environmentEntries.length > MAX_ENVIRONMENT_KEYS) {
    throw new BrokerError("PRECONDITION_FAILED", "Process environment exceeds the supported size");
  }
  let environmentBytes = 0;
  for (const [key, value] of environmentEntries) {
    validateEnvironmentKey(key);
    if (!allowedEnvironmentKeys.has(key)) throw new BrokerError("POLICY_DENIED", "Process environment key is not profile-allowlisted");
    if (typeof value !== "string") throw new BrokerError("PRECONDITION_FAILED", "Process environment value is invalid");
    if (value.includes("\0") || value.length > 4_096) throw new BrokerError("PRECONDITION_FAILED", "Process environment value is invalid");
    environmentBytes += Buffer.byteLength(key, "utf8") + Buffer.byteLength(value, "utf8") + 2;
    if (environmentBytes > MAX_ENVIRONMENT_BYTES) {
      throw new BrokerError("PRECONDITION_FAILED", "Process environment exceeds the supported size");
    }
  }
  try {
    await validateExecutable(request.executable);
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("TARGET_NOT_FOUND", "Broker-resolved executable was not found");
  }
  try {
    await validateDirectory(request.cwd);
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("TARGET_NOT_FOUND", "Broker-resolved process cwd was not found");
  }
}

function isCanonicalAbsolutePath(value: string): boolean {
  return typeof value === "string" && value.length >= 1 && value.length <= 4_096 &&
    isAbsolute(value) && resolve(value) === value && !value.includes("\0") && !value.includes("\n");
}

async function validateExecutable(path: string): Promise<void> {
  const stat = await lstat(path);
  if (stat.isSymbolicLink()) throw new BrokerError("POLICY_DENIED", "Executable symlinks are not allowed");
  if (!stat.isFile() || (stat.mode & 0o111) === 0) throw new BrokerError("POLICY_DENIED", "Executable must be a regular executable file");
  if ((await realpath(path)) !== path) throw new BrokerError("POLICY_DENIED", "Executable symlinks are not allowed");
}

async function validateDirectory(path: string): Promise<void> {
  const stat = await lstat(path);
  if (!stat.isDirectory() || (await realpath(path)) !== path) throw new BrokerError("POLICY_DENIED", "Process cwd must be a canonical directory");
}

function validateEnvironmentKey(key: string): void {
  if (!/^[A-Z_][A-Z0-9_]{0,63}$/u.test(key) || SECRET_ENV_KEY.test(key)) {
    throw new BrokerError("POLICY_DENIED", "Process environment key is not safe");
  }
}

function signalProcessGroup(child: ChildProcess, processId: number, signal: NodeJS.Signals): void {
  try {
    if (process.platform !== "win32") process.kill(-processId, signal);
    else child.kill(signal);
  } catch {
    try { child.kill(signal); } catch { /* The child may have exited between observation and signalling. */ }
  }
}

function processGroupAlive(processId: number): boolean {
  if (process.platform === "win32") return false;
  try {
    process.kill(-processId, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

function createProcessTreeTracker(processId: number): ProcessTreeTracker | undefined {
  if (process.platform !== "darwin") return undefined;
  try {
    const native = require("./peer_credentials.node") as Partial<NativeProcessTreeAdapter>;
    if (typeof native.listDescendantProcesses !== "function" || typeof native.isProcessIdentityAlive !== "function" ||
        typeof native.getProcessIdentity !== "function") return undefined;
    return new ProcessTreeTracker(native as NativeProcessTreeAdapter, processId);
  } catch {
    return undefined;
  }
}

class ProcessTreeTracker {
  private readonly descendants = new Map<number, ProcessTreeIdentity>();
  private failed = false;
  private readonly rootIdentity: ProcessTreeIdentity | undefined;

  constructor(private readonly native: NativeProcessTreeAdapter, private readonly processId: number) {
    try {
      const identity = parseProcessIdentity(native.getProcessIdentity(processId));
      if (identity.pid === processId) this.rootIdentity = identity;
    } catch {
      // A very short-lived process can exit before its root identity is read.
      // Descendant tracking remains useful, but group signalling must stay disabled.
      this.rootIdentity = undefined;
    }
  }

  get observationFailed(): boolean {
    return this.failed;
  }

  get rootIdentityUnavailable(): boolean {
    return this.rootIdentity === undefined;
  }

  rootState(): "alive" | "dead" | "unknown" {
    if (this.failed) return "unknown";
    if (this.rootIdentity === undefined) return "dead";
    try {
      const alive = this.native.isProcessIdentityAlive(this.rootIdentity.pid, this.rootIdentity.startTimeMicros);
      if (alive === true) return "alive";
      if (alive === false) return "dead";
      return "unknown";
    } catch {
      return "unknown";
    }
  }

  sample(): void {
    if (this.failed) return;
    try {
      const snapshot = parseProcessTreeSnapshot(this.native.listDescendantProcesses(this.processId));
      if (snapshot.truncated) {
        this.failed = true;
        return;
      }
      for (const identity of snapshot.processes) this.descendants.set(identity.pid, identity);
    } catch {
      this.failed = true;
    }
  }

  aliveState(): "none" | "alive" | "unknown" {
    if (this.failed) return "unknown";
    for (const identity of this.descendants.values()) {
      try {
        const alive = this.native.isProcessIdentityAlive(identity.pid, identity.startTimeMicros);
        if (alive === true) return "alive";
        if (alive !== false) return "unknown";
      } catch {
        return "unknown";
      }
    }
    return "none";
  }

  signal(signal: NodeJS.Signals): void {
    if (this.failed) return;
    for (const identity of this.descendants.values()) {
      try {
        if (this.native.isProcessIdentityAlive(identity.pid, identity.startTimeMicros) === true) process.kill(identity.pid, signal);
      } catch {
        // A descendant may exit between identity verification and signalling.
      }
    }
  }
}

function parseProcessIdentity(value: unknown): ProcessTreeIdentity {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Malformed process identity");
  const identity = value as Record<string, unknown>;
  const pid = identity.pid;
  const parentPid = identity.parentPid;
  const startTimeMicros = identity.startTimeMicros;
  if (typeof pid !== "number" || !Number.isSafeInteger(pid) || pid < 1 || pid > 99_999_999 ||
      typeof parentPid !== "number" || !Number.isSafeInteger(parentPid) || parentPid < 1 || parentPid > 99_999_999 ||
      typeof startTimeMicros !== "number" || !Number.isSafeInteger(startTimeMicros) || startTimeMicros < 1) {
    throw new Error("Malformed process identity");
  }
  return { pid, startTimeMicros };
}

function parseProcessTreeSnapshot(value: unknown): { processes: ProcessTreeIdentity[]; truncated: boolean } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Malformed process tree snapshot");
  const record = value as Record<string, unknown>;
  if (!Array.isArray(record.processes) || record.processes.length > 256 || typeof record.truncated !== "boolean") {
    throw new Error("Malformed process tree snapshot");
  }
  const processes: ProcessTreeIdentity[] = [];
  const seen = new Set<number>();
  for (const value of record.processes) {
    const identity = parseProcessIdentity(value);
    if (seen.has(identity.pid)) throw new Error("Malformed process identity");
    seen.add(identity.pid);
    processes.push(identity);
  }
  return { processes, truncated: record.truncated };
}
