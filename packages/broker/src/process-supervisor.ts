import { spawn, type ChildProcess } from "node:child_process";
import { lstat, realpath } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import { loadNativePeerAdapter } from "./peer-credentials.js";
import { isSafeProcessEnvironmentKey } from "./process-environment.js";

const MAX_ARGUMENTS = 128;
const MAX_ARGUMENT_BYTES = 64 * 1024;
const MAX_ENVIRONMENT_KEYS = 64;
const MAX_ENVIRONMENT_BYTES = 64 * 1024;
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_TIMEOUT_MS = 600_000;
const DEFAULT_POLL_INTERVAL_MS = 25;
const DEFAULT_TERMINATION_GRACE_MS = 250;
interface NativeProcessTreeAdapter {
  listDescendantProcesses(pid: number): unknown;
  isProcessIdentityAlive(pid: number, startTimeMicros: number): unknown;
  getProcessIdentity(pid: number): unknown;
}

interface ProcessTreeIdentity {
  pid: number;
  startTimeMicros: number;
}

interface ActiveProcessRun {
  stop: () => void;
  drained: Promise<void>;
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
  /** Synchronous hook used to persist verified ownership before work proceeds. */
  onStarted?: (snapshot: ProcessOwnershipSnapshot) => void;
  /** Synchronous hook used to persist newly observed descendants. */
  onOwnershipChanged?: (snapshot: ProcessOwnershipSnapshot) => void;
}

export interface ProcessOwnershipIdentity {
  pid: number;
  processGroupId: number;
  startTimeMicros: number;
}

export interface ProcessDescendantIdentity {
  pid: number;
  startTimeMicros: number;
}

export interface ProcessOwnershipSnapshot {
  identity: ProcessOwnershipIdentity;
  descendants: readonly ProcessDescendantIdentity[];
}

export type ProcessRecoveryOutcome = "drained" | "absent" | "identity_mismatch" | "unknown";

export interface ProcessRecoveryResult {
  outcome: ProcessRecoveryOutcome;
  processId: number;
  processGroupId: number;
  terminationObserved: boolean;
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
  private readonly activeRuns = new Set<ActiveProcessRun>();
  private readonly maxConcurrent: number;
  private readonly pollIntervalMs: number;
  private readonly terminationGraceMs: number;
  private readonly allowedEnvironmentKeys: ReadonlySet<string>;
  private closing = false;
  private closePromise: Promise<void> | undefined;

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
    if (this.closing) {
      throw new BrokerError("CANCELLED", "Process authority is closed");
    }
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
      const drained = await this.abortUnownedProcess(child, processId, processTree);
      if (!drained) throw new BrokerError("UNKNOWN_OUTCOME", "Process startup cleanup could not be verified", true);
      throw new BrokerError("POLICY_DENIED", "Process tree observer is unavailable");
    }
    if (request.onStarted !== undefined) {
      const startTimeMicros = processTree === undefined
        ? undefined
        : await waitForRootProcessIdentity(processTree, child);
      if (processTree === undefined || startTimeMicros === undefined) {
        const drained = await this.abortUnownedProcess(child, processId, processTree);
        if (!drained) throw new BrokerError("UNKNOWN_OUTCOME", "Process startup cleanup could not be verified", true);
        throw new BrokerError("POLICY_DENIED", "Process identity could not be captured");
      }
      try {
        processTree.sample();
        if (processTree.observationFailed) {
          throw new BrokerError("POLICY_DENIED", "Process descendants could not be captured");
        }
        request.onStarted({
          identity: { pid: processId, processGroupId: processId, startTimeMicros },
          descendants: processTree.snapshotDescendants()
        });
      } catch (error) {
        const drained = await this.abortUnownedProcess(child, processId, processTree);
        if (!drained) throw new BrokerError("UNKNOWN_OUTCOME", "Process startup cleanup could not be verified", true);
        if (error instanceof BrokerError) throw error;
        throw new BrokerError("AUDIT_UNAVAILABLE", "Process identity could not be persisted");
      }
    }
    if (this.closing || this.cancelled(request.shouldCancel)) {
      const drained = await this.abortUnownedProcess(child, processId, processTree);
      if (!drained) throw new BrokerError("UNKNOWN_OUTCOME", "Process startup cleanup could not be verified", true);
      throw new BrokerError("CANCELLED", "Process authority was revoked before execution");
    }
    this.activeProcesses += 1;
    let stopRun: (() => void) | undefined;
    let resolveDrained!: () => void;
    let drained = false;
    const drainedPromise = new Promise<void>((resolve) => { resolveDrained = resolve; });
    const activeRun: ActiveProcessRun = {
      stop: () => stopRun?.(),
      drained: drainedPromise
    };
    // Register before observing: an ownership callback can fail synchronously
    // during the first sample, and release() must then be able to remove the
    // run from the active set instead of leaving a close-time ghost entry.
    this.activeRuns.add(activeRun);
    return this.observe(
      child,
      request,
      processId,
      startedAtMs,
      processTree,
      (stop) => { stopRun = stop; },
      () => {
        if (drained) return;
        drained = true;
        resolveDrained();
        this.activeRuns.delete(activeRun);
      }
    );
  }

  activeCount(): number {
    return this.activeProcesses;
  }

  /**
   * A startup ownership callback runs before the process enters activeRuns.
   * If it fails, kill the detached group and prove that the root and every
   * observed descendant disappeared before returning the callback error.
   */
  private async abortUnownedProcess(
    child: ChildProcess,
    processId: number,
    processTree: ProcessTreeTracker | undefined
  ): Promise<boolean> {
    if (processTree === undefined) {
      signalProcessGroup(child, processId, "SIGKILL");
    } else {
      processTree.sample();
      if (processTree.rootState() === "alive") signalProcessGroup(child, processId, "SIGKILL");
      processTree.signal("SIGKILL");
    }
    const deadline = Date.now() + Math.max(this.terminationGraceMs * 3, 1_000);
    while (Date.now() < deadline) {
      processTree?.sample();
      const rootState = processTree?.rootState() ?? "dead";
      const descendants = processTree?.aliveState() ?? "none";
      const groupAlive = processGroupAlive(processId);
      if (rootState !== "unknown" && processTree?.observationFailed !== true && descendants === "none" && !groupAlive) {
        return true;
      }
      await new Promise((resolve) => setTimeout(resolve, this.pollIntervalMs));
    }
    return false;
  }

  /**
   * Recover a process owned by a prior Broker instance. Recovery is deliberately
   * identity-bound and never infers success from a missing process.
   */
  async recoverOwnedProcess(
    persisted: ProcessOwnershipIdentity | ProcessOwnershipSnapshot,
    timeoutMs = 5_000
  ): Promise<ProcessRecoveryResult> {
    const persistedValue = persisted as unknown;
    const snapshot: ProcessOwnershipSnapshot = persistedValue !== null && typeof persistedValue === "object" && "identity" in persistedValue
      ? persisted as ProcessOwnershipSnapshot
      : { identity: persisted as ProcessOwnershipIdentity, descendants: [] };
    validateProcessOwnershipSnapshot(snapshot);
    const identity = snapshot.identity;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 25 || timeoutMs > MAX_TIMEOUT_MS) {
      throw new BrokerError("PRECONDITION_FAILED", "Process recovery timeout is outside the supported range");
    }
    if (process.platform !== "darwin") {
      return {
        outcome: "unknown",
        processId: identity.pid,
        processGroupId: identity.processGroupId,
        terminationObserved: false
      };
    }
    let native: NativeProcessTreeAdapter;
    try {
      native = loadNativePeerAdapter() as unknown as NativeProcessTreeAdapter;
      if (typeof native.listDescendantProcesses !== "function" ||
          typeof native.isProcessIdentityAlive !== "function" ||
          typeof native.getProcessIdentity !== "function") {
        throw new Error("Process tree observer is unavailable");
      }
    } catch {
      return {
        outcome: "unknown",
        processId: identity.pid,
        processGroupId: identity.processGroupId,
        terminationObserved: false
      };
    }

    let rootAlive: unknown;
    try { rootAlive = native.isProcessIdentityAlive(identity.pid, identity.startTimeMicros); }
    catch { rootAlive = undefined; }
    if (rootAlive === false) {
      try {
        const currentIdentity = parseProcessIdentity(native.getProcessIdentity(identity.pid));
        if (currentIdentity.startTimeMicros !== identity.startTimeMicros) {
          return {
            outcome: "identity_mismatch",
            processId: identity.pid,
            processGroupId: identity.processGroupId,
            terminationObserved: false
          };
        }
      } catch {
        // The process may have exited; group state below distinguishes absence
        // from an unresolved descendant group.
      }
      const descendantState = persistedDescendantState(native, snapshot.descendants);
      if (descendantState === "unknown") {
        return {
          outcome: "unknown",
          processId: identity.pid,
          processGroupId: identity.processGroupId,
          terminationObserved: false
        };
      }
      if (descendantState === "alive") {
        const descendantRecovery = await recoverPersistedDescendants(
          native,
          snapshot.descendants,
          this.pollIntervalMs,
          this.terminationGraceMs,
          timeoutMs
        );
        return {
          outcome: descendantRecovery ? "drained" : "unknown",
          processId: identity.pid,
          processGroupId: identity.processGroupId,
          terminationObserved: descendantRecovery
        };
      }
      const groupAlive = processGroupAlive(identity.processGroupId);
      return {
        // An empty persisted snapshot cannot prove that no descendant was
        // created after the last observation and escaped the process group.
        // Keep the outcome unresolved rather than inferring absence.
        outcome: groupAlive || snapshot.descendants.length === 0 ? "unknown" : "absent",
        processId: identity.pid,
        processGroupId: identity.processGroupId,
        terminationObserved: !groupAlive && snapshot.descendants.length > 0
      };
    }
    if (rootAlive !== true) {
      return {
        outcome: "unknown",
        processId: identity.pid,
        processGroupId: identity.processGroupId,
        terminationObserved: false
      };
    }

    const processTree = new ProcessTreeTracker(native, identity.pid, identity, snapshot.descendants);
    processTree.sample();
    if (processTree.observationFailed) {
      return {
        outcome: "unknown",
        processId: identity.pid,
        processGroupId: identity.processGroupId,
        terminationObserved: false
      };
    }
    if (processTree.rootState() !== "alive") {
      return {
        outcome: "unknown",
        processId: identity.pid,
        processGroupId: identity.processGroupId,
        terminationObserved: false
      };
    }
    signalProcessGroupId(identity.processGroupId, "SIGTERM");
    processTree.signal("SIGTERM");
    const killAt = Date.now() + this.terminationGraceMs;
    const deadline = Date.now() + timeoutMs;
    let killSent = false;
    while (Date.now() < deadline) {
      processTree.sample();
      const rootState = processTree.rootState();
      const descendantState = processTree.aliveState();
      const groupAlive = processGroupAlive(identity.processGroupId);
      if (rootState === "unknown" || descendantState === "unknown" || processTree.observationFailed) {
        return {
          outcome: "unknown",
          processId: identity.pid,
          processGroupId: identity.processGroupId,
          terminationObserved: false
        };
      }
      if (rootState === "dead" && descendantState === "none" && !groupAlive) {
        return {
          outcome: "drained",
          processId: identity.pid,
          processGroupId: identity.processGroupId,
          terminationObserved: true
        };
      }
      if (!killSent && Date.now() >= killAt) {
        killSent = true;
        if (rootState === "alive") signalProcessGroupId(identity.processGroupId, "SIGKILL");
        processTree.signal("SIGKILL");
      }
      await new Promise((resolve) => setTimeout(resolve, this.pollIntervalMs));
    }
    return {
      outcome: "unknown",
      processId: identity.pid,
      processGroupId: identity.processGroupId,
      terminationObserved: false
    };
  }

  /**
   * Stop accepting new child processes, terminate all owned process groups,
   * and wait until every owned process tree has drained.
   */
  close(): Promise<void> {
    if (this.closePromise !== undefined) return this.closePromise;
    this.closing = true;
    const activeRuns = [...this.activeRuns];
    for (const run of activeRuns) run.stop();
    this.closePromise = Promise.all(activeRuns.map((run) => run.drained)).then(() => undefined);
    return this.closePromise;
  }

  private observe(
    child: ChildProcess,
    request: ProcessExecutionRequest,
    processId: number,
    startedAtMs: number,
    processTree: ProcessTreeTracker | undefined,
    registerStop: (stop: () => void) => void,
    onDrained: () => void
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
      let reportedDescendantCount = -1;

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
        onDrained();
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
      registerStop(() => terminate("cancelled"));
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
        const abnormalExit = spawnError || code !== 0 || signal !== null;
        const state = terminationReason === "cancelled" ? "cancelled" :
          terminationReason === "timed_out" ? "timed_out" :
          terminationReason === "orphaned" ? "unknown" :
          terminationReason === "output_limit" ? "failed" :
          abnormalExit ? "failed" : "completed";
        const resultClass = terminationReason === "cancelled" ? "CANCELLED" :
          terminationReason === "timed_out" ? "TIMEOUT" :
          terminationReason === "orphaned" ? "UNKNOWN_OUTCOME" :
          terminationReason === "output_limit" ? "OUTPUT_LIMIT" :
          abnormalExit ? "EXECUTION_FAILED" : "SUCCEEDED";
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

      const notifyOwnership = () => {
        if (request.onOwnershipChanged === undefined || processTree === undefined || processTree.observationFailed) return;
        const descendants = processTree.snapshotDescendants();
        if (descendants.length <= reportedDescendantCount) return;
        reportedDescendantCount = descendants.length;
        const startTimeMicros = processTree.rootStartTimeMicros;
        if (startTimeMicros === undefined) {
          terminate("orphaned");
          return;
        }
        try {
          request.onOwnershipChanged({
            identity: {
              pid: processId,
              processGroupId: processId,
              startTimeMicros
            },
            descendants
          });
        } catch {
          terminate("orphaned");
        }
      };
      notifyOwnership();

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
        notifyOwnership();
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
        notifyOwnership();
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
  if (!isSafeProcessEnvironmentKey(key, true)) {
    throw new BrokerError("POLICY_DENIED", "Process environment key is not safe");
  }
}

function signalProcessGroup(child: ChildProcess, processId: number, signal: NodeJS.Signals): void {
  try {
    if (process.platform !== "win32") signalProcessGroupId(processId, signal);
    else child.kill(signal);
  } catch {
    try { child.kill(signal); } catch { /* The child may have exited between observation and signalling. */ }
  }
}

function signalProcessGroupId(processGroupId: number, signal: NodeJS.Signals): void {
  if (process.platform !== "win32") process.kill(-processGroupId, signal);
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

function validateProcessOwnershipIdentity(identity: ProcessOwnershipIdentity): void {
  if (identity === null || typeof identity !== "object" ||
      !Number.isSafeInteger(identity.pid) || identity.pid < 1 || identity.pid > 99_999_999 ||
      !Number.isSafeInteger(identity.processGroupId) || identity.processGroupId !== identity.pid ||
      !Number.isSafeInteger(identity.startTimeMicros) || identity.startTimeMicros < 1) {
    throw new BrokerError("PRECONDITION_FAILED", "Process ownership identity is malformed");
  }
}

function validateProcessOwnershipSnapshot(snapshot: ProcessOwnershipSnapshot): void {
  if (snapshot === null || typeof snapshot !== "object" || !Array.isArray(snapshot.descendants)) {
    throw new BrokerError("PRECONDITION_FAILED", "Process ownership snapshot is malformed");
  }
  validateProcessOwnershipIdentity(snapshot.identity);
  if (snapshot.descendants.length > 256) {
    throw new BrokerError("PRECONDITION_FAILED", "Process ownership snapshot is too large");
  }
  let previousPid = 0;
  for (const descendant of snapshot.descendants) {
    if (descendant === null || typeof descendant !== "object" ||
        !Number.isSafeInteger(descendant.pid) || descendant.pid < 1 || descendant.pid > 99_999_999 ||
        descendant.pid === snapshot.identity.pid || descendant.pid <= previousPid ||
        !Number.isSafeInteger(descendant.startTimeMicros) || descendant.startTimeMicros < 1) {
      throw new BrokerError("PRECONDITION_FAILED", "Process ownership snapshot is malformed");
    }
    previousPid = descendant.pid;
  }
}

function persistedDescendantState(
  native: NativeProcessTreeAdapter,
  descendants: readonly ProcessDescendantIdentity[]
): "none" | "alive" | "unknown" {
  for (const descendant of descendants) {
    try {
      const alive = native.isProcessIdentityAlive(descendant.pid, descendant.startTimeMicros);
      if (alive === true) return "alive";
      if (alive !== false) return "unknown";
    } catch {
      return "unknown";
    }
  }
  return "none";
}

function signalPersistedDescendants(
  native: NativeProcessTreeAdapter,
  descendants: readonly ProcessDescendantIdentity[],
  signal: NodeJS.Signals
): void {
  for (const descendant of descendants) {
    try {
      if (native.isProcessIdentityAlive(descendant.pid, descendant.startTimeMicros) === true) {
        process.kill(descendant.pid, signal);
      }
    } catch {
      // A descendant may exit between identity verification and signalling.
    }
  }
}

async function recoverPersistedDescendants(
  native: NativeProcessTreeAdapter,
  descendants: readonly ProcessDescendantIdentity[],
  pollIntervalMs: number,
  terminationGraceMs: number,
  timeoutMs: number
): Promise<boolean> {
  signalPersistedDescendants(native, descendants, "SIGTERM");
  const killAt = Date.now() + terminationGraceMs;
  const deadline = Date.now() + timeoutMs;
  let killSent = false;
  while (Date.now() < deadline) {
    const state = persistedDescendantState(native, descendants);
    if (state === "none") return true;
    if (state === "unknown") return false;
    if (!killSent && Date.now() >= killAt) {
      killSent = true;
      signalPersistedDescendants(native, descendants, "SIGKILL");
    }
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }
  return false;
}

function createProcessTreeTracker(processId: number): ProcessTreeTracker | undefined {
  if (process.platform !== "darwin") return undefined;
  try {
    const native = loadNativePeerAdapter() as unknown as Partial<NativeProcessTreeAdapter>;
    if (typeof native.listDescendantProcesses !== "function" || typeof native.isProcessIdentityAlive !== "function" ||
        typeof native.getProcessIdentity !== "function") return undefined;
    return new ProcessTreeTracker(native as NativeProcessTreeAdapter, processId);
  } catch {
    return undefined;
  }
}

async function waitForRootProcessIdentity(
  processTree: ProcessTreeTracker,
  child: ChildProcess,
  timeoutMs = 100
): Promise<number | undefined> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const identity = processTree.captureRootIdentity();
    if (identity !== undefined) return identity;
    if (child.exitCode !== null || child.signalCode !== null) break;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  return processTree.captureRootIdentity();
}

class ProcessTreeTracker {
  private readonly descendants = new Map<number, ProcessTreeIdentity>();
  private failed = false;
  private rootIdentity: ProcessTreeIdentity | undefined;

  constructor(
    private readonly native: NativeProcessTreeAdapter,
    private readonly processId: number,
    expectedRootIdentity?: ProcessOwnershipIdentity,
    initialDescendants: readonly ProcessDescendantIdentity[] = []
  ) {
    for (const identity of initialDescendants) this.descendants.set(identity.pid, identity);
    if (expectedRootIdentity !== undefined) {
      this.rootIdentity = {
        pid: expectedRootIdentity.pid,
        startTimeMicros: expectedRootIdentity.startTimeMicros
      };
      return;
    }
    try {
      const identity = parseProcessIdentity(native.getProcessIdentity(processId));
      if (identity.pid === processId) this.rootIdentity = identity;
    } catch {
      // A very short-lived process can exit before its root identity is read.
      // Descendant tracking remains useful, but group signalling must stay disabled.
      this.rootIdentity = undefined;
    }
  }

  get rootStartTimeMicros(): number | undefined {
    return this.rootIdentity?.startTimeMicros;
  }

  captureRootIdentity(): number | undefined {
    if (this.rootIdentity !== undefined || this.failed) return this.rootIdentity?.startTimeMicros;
    try {
      const identity = parseProcessIdentity(this.native.getProcessIdentity(this.processId));
      if (identity.pid === this.processId) this.rootIdentity = identity;
    } catch {
      // A short-lived process may not be visible in the native process table yet.
    }
    return this.rootIdentity?.startTimeMicros;
  }

  snapshotDescendants(): readonly ProcessDescendantIdentity[] {
    return [...this.descendants.values()]
      .sort((left, right) => left.pid - right.pid)
      .map((identity) => ({ pid: identity.pid, startTimeMicros: identity.startTimeMicros }));
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
