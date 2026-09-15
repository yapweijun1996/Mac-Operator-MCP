import { createHash } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import { loadNativePeerAdapter } from "./peer-credentials.js";
import { isSafeProcessEnvironmentKey } from "./process-environment.js";
import { isPlainDataRecord } from "./plain-record.js";
import { assertArgumentsDoNotContainSecrets, assertEnvironmentValuesDoNotContainSecrets } from "./secret-policy.js";

const MAX_ARGUMENTS = 128;
const MAX_ARGUMENT_BYTES = 64 * 1024;
const MAX_ENVIRONMENT_KEYS = 64;
const MAX_ENVIRONMENT_BYTES = 64 * 1024;
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_EXECUTABLE_DIGEST_BYTES = 64 * 1024 * 1024;
const EXECUTABLE_DIGEST_READ_CHUNK_BYTES = 1024 * 1024;
const MAX_TIMEOUT_MS = 600_000;
const DEFAULT_POLL_INTERVAL_MS = 25;
const DEFAULT_TERMINATION_GRACE_MS = 250;
const DEFAULT_MAX_CONCURRENT_PER_EXECUTABLE = 4;
interface NativeProcessTreeAdapter {
  listDescendantProcesses(pid: number): unknown;
  listProcessGroupMembers(processGroupId: number): unknown;
  isProcessIdentityAlive(pid: number, startTimeMicros: number): unknown;
  getProcessIdentity(pid: number): unknown;
}

interface ProcessTreeIdentity {
  pid: number;
  startTimeMicros: number;
  processGroupId?: number;
}

interface ActiveProcessRun {
  stop: () => void;
  drained: Promise<void>;
}

/**
 * Captures child events immediately after spawn, before asynchronous path and
 * ownership checks can yield to a short-lived child. The observer attaches
 * callbacks later and consumes this bounded state without losing exit/output
 * events.
 */
interface ChildProcessCapture {
  stdout: Buffer<ArrayBufferLike>;
  stderr: Buffer<ArrayBufferLike>;
  stdoutBytes: number;
  stderrBytes: number;
  outputOverflow: boolean;
  spawnError: boolean;
  exited: boolean;
  exitCode: number | null;
  exitSignal: NodeJS.Signals | null;
  closed: boolean;
  onOutput?: () => void;
  onError?: () => void;
  onExit?: () => void;
  onClose?: () => void;
}

export interface ProcessPathIdentity {
  device: number;
  inode: number;
  ownerUid: number;
  ownerGid: number;
  mode: number;
  /** Metadata that changes on ordinary in-place content mutation. */
  size: number;
  mtimeMs: number;
  ctimeMs: number;
  /** SHA-256 content identity for regular executable files. */
  contentSha256?: string;
}

export type ProcessPathKind = "executable" | "directory";

interface ValidatedProcessPaths {
  executable: ProcessPathIdentity;
  cwd: ProcessPathIdentity;
}

export interface ProcessExecutionRequest {
  /** Broker-resolved executable; shell strings and relative paths are rejected. */
  executable: string;
  args: readonly string[];
  /** Broker-authorized, canonical working directory. */
  cwd: string;
  /** Explicit profile environment. Omitted means an empty environment. */
  environment?: Readonly<Record<string, string>>;
  /** Bounded, non-persisted stdin payload. Never appears in argv or audit metadata. */
  stdin?: string;
  timeoutMs: number;
  outputCapBytes: number;
  /**
   * Require a bounded final native process-tree observation window before a
   * successful exit may be published. Governed task runners set this only
   * when their sandbox proof forbids process creation; ordinary fixed adapters
   * keep the legacy bounded child-exit behavior.
   */
  requireCleanExitProof?: boolean;
  shouldCancel?: () => boolean;
  /** Hook used to persist verified ownership before work proceeds. */
  onStarted?: (snapshot: ProcessOwnershipSnapshot) => void | Promise<void>;
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
  /**
   * Host-owned proof that no post-snapshot descendant can be created. This
   * marker is set only by a validated no-fork sandbox runner; it is not a
   * caller-controlled permission.
   */
  ownershipProof?: "sandbox-exec-no-fork-v1";
}

export type ProcessRecoveryOutcome = "drained" | "absent" | "identity_mismatch" | "unknown";

export interface ProcessRecoveryResult {
  outcome: ProcessRecoveryOutcome;
  processId: number;
  processGroupId: number;
  terminationObserved: boolean;
}

/**
 * Returns true when a descendant PID observed in a later snapshot has a
 * different start-time identity. PID reuse is an ownership boundary failure;
 * callers must stop signalling and keep the outcome unresolved.
 */
export function detectProcessIdentityReplacement(
  tracked: readonly ProcessDescendantIdentity[],
  observed: readonly ProcessDescendantIdentity[]
): boolean {
  const trackedStartTimes = new Map(tracked.map((identity) => [identity.pid, identity.startTimeMicros]));
  return observed.some((identity) => {
    const previousStartTime = trackedStartTimes.get(identity.pid);
    return previousStartTime !== undefined && previousStartTime !== identity.startTimeMicros;
  });
}

export interface ProcessSupervisorOptions {
  maxConcurrent?: number;
  /** Maximum active or pending starts for one canonical executable path. */
  maxConcurrentPerExecutable?: number;
  pollIntervalMs?: number;
  terminationGraceMs?: number;
  allowedEnvironmentKeys?: readonly string[];
  /** Require executable files to be owned by root for fixed host adapters. */
  requireRootOwnedExecutable?: boolean;
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
  private readonly activeProcessesByExecutable = new Map<string, number>();
  private readonly activeRuns = new Set<ActiveProcessRun>();
  private readonly pendingStarts = new Set<Promise<void>>();
  private readonly pendingStartsByExecutable = new Map<string, number>();
  private readonly maxConcurrent: number;
  private readonly maxConcurrentPerExecutable: number;
  private readonly pollIntervalMs: number;
  private readonly terminationGraceMs: number;
  private readonly allowedEnvironmentKeys: ReadonlySet<string>;
  private readonly requireRootOwnedExecutable: boolean;
  private closing = false;
  private closePromise: Promise<void> | undefined;

  constructor(options: ProcessSupervisorOptions = {}) {
    this.maxConcurrent = options.maxConcurrent ?? 4;
    this.maxConcurrentPerExecutable = options.maxConcurrentPerExecutable ?? DEFAULT_MAX_CONCURRENT_PER_EXECUTABLE;
    this.pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    this.terminationGraceMs = options.terminationGraceMs ?? DEFAULT_TERMINATION_GRACE_MS;
    this.allowedEnvironmentKeys = new Set(options.allowedEnvironmentKeys ?? []);
    this.requireRootOwnedExecutable = options.requireRootOwnedExecutable ?? false;
    if (!Number.isSafeInteger(this.maxConcurrent) || this.maxConcurrent < 1 || this.maxConcurrent > 64 ||
        !Number.isSafeInteger(this.maxConcurrentPerExecutable) || this.maxConcurrentPerExecutable < 1 || this.maxConcurrentPerExecutable > 64 ||
        !Number.isSafeInteger(this.pollIntervalMs) || this.pollIntervalMs < 5 || this.pollIntervalMs > 1_000 ||
        !Number.isSafeInteger(this.terminationGraceMs) || this.terminationGraceMs < 25 || this.terminationGraceMs > 10_000 ||
        typeof this.requireRootOwnedExecutable !== "boolean") {
      throw new Error("Process supervisor limits are outside the supported range");
    }
    for (const key of this.allowedEnvironmentKeys) validateEnvironmentKey(key);
  }

  async run(request: ProcessExecutionRequest): Promise<ProcessExecutionResult> {
    // Snapshot the caller-owned request before any asynchronous identity
    // checks. Otherwise a caller could mutate a target, argument, or
    // environment while validation is in flight and change what gets spawned.
    const safeRequest = snapshotProcessRequest(request);
    const validatedPaths = await validateRequest(safeRequest, this.allowedEnvironmentKeys, this.requireRootOwnedExecutable);
    if (this.closing) {
      throw new BrokerError("CANCELLED", "Process authority is closed");
    }
    if (this.cancelled(safeRequest.shouldCancel)) {
      throw new BrokerError("CANCELLED", "Process authority was revoked before execution");
    }
    const executableKey = safeRequest.executable;
    const activeForExecutable = this.activeProcessesByExecutable.get(executableKey) ?? 0;
    const pendingForExecutable = this.pendingStartsByExecutable.get(executableKey) ?? 0;
    if (this.activeProcesses + this.pendingStarts.size >= this.maxConcurrent ||
        activeForExecutable + pendingForExecutable >= this.maxConcurrentPerExecutable) {
      throw new BrokerError("CONFLICT", "Process capacity is exhausted", true);
    }

    const environment = Object.fromEntries(Object.entries(safeRequest.environment ?? {}));
    const startedAtMs = Date.now();
    let resolvePendingStart!: () => void;
    const pendingStart = new Promise<void>((resolve) => { resolvePendingStart = resolve; });
    this.pendingStarts.add(pendingStart);
    this.pendingStartsByExecutable.set(executableKey, pendingForExecutable + 1);
    let pendingStartReleased = false;
    const releasePendingStart = (): void => {
      if (pendingStartReleased) return;
      pendingStartReleased = true;
      this.pendingStarts.delete(pendingStart);
      const current = this.pendingStartsByExecutable.get(executableKey) ?? 0;
      if (current <= 1) this.pendingStartsByExecutable.delete(executableKey);
      else this.pendingStartsByExecutable.set(executableKey, current - 1);
      resolvePendingStart();
    };
    let child: ChildProcess;
    try {
      try {
        child = spawn(safeRequest.executable, [...safeRequest.args], {
          cwd: safeRequest.cwd,
          env: environment,
          shell: false,
          detached: true,
          stdio: [safeRequest.stdin === undefined ? "ignore" : "pipe", "pipe", "pipe"]
        });
      } catch {
        throw new BrokerError("EXECUTION_FAILED", "Child process could not be started");
      }
      const capture = attachChildProcessCapture(child, safeRequest.outputCapBytes);
      if (safeRequest.stdin !== undefined && child.stdin !== null) {
        try {
          child.stdin.end(safeRequest.stdin, "utf8");
        } catch {
          child.kill("SIGKILL");
          throw new BrokerError("EXECUTION_FAILED", "Process stdin could not be delivered");
        }
      }
      const childPid = child.pid;
      if (typeof childPid !== "number" || !Number.isSafeInteger(childPid) || childPid <= 0) {
        child.kill("SIGKILL");
        throw new BrokerError("EXECUTION_FAILED", "Child process did not expose a valid process identity");
      }
      const processId = childPid;
      const processTree = createProcessTreeTracker(processId);
      try {
        await assertProcessPathStable(safeRequest.executable, validatedPaths.executable, "Executable");
        await assertProcessPathStable(safeRequest.cwd, validatedPaths.cwd, "Process cwd");
      } catch (error) {
        const drained = await this.abortUnownedProcess(child, processId, processTree);
        if (!drained) throw new BrokerError("UNKNOWN_OUTCOME", "Process path target-swap cleanup could not be verified", true);
        if (error instanceof BrokerError) throw error;
        throw new BrokerError("POLICY_DENIED", "Process path changed after authorization");
      }
      if (process.platform === "darwin" && processTree === undefined) {
        const drained = await this.abortUnownedProcess(child, processId, processTree);
        if (!drained) throw new BrokerError("UNKNOWN_OUTCOME", "Process startup cleanup could not be verified", true);
        throw new BrokerError("POLICY_DENIED", "Process tree observer is unavailable");
      }
      if (safeRequest.onStarted !== undefined || safeRequest.requireCleanExitProof === true) {
        const startTimeMicros = processTree === undefined
          ? undefined
          : await waitForRootProcessIdentity(processTree, child, safeRequest.requireCleanExitProof === true ? 500 : 100);
        if (processTree === undefined || startTimeMicros === undefined || processTree.rootProcessGroupId !== processId) {
          const drained = await this.abortUnownedProcess(child, processId, processTree);
          if (!drained) throw new BrokerError("UNKNOWN_OUTCOME", "Process startup cleanup could not be verified", true);
          throw new BrokerError("POLICY_DENIED", "Process identity or process-group identity could not be captured");
        }
        try {
          processTree.sample();
          if (processTree.observationFailed) {
            throw new BrokerError("POLICY_DENIED", "Process descendants could not be captured");
          }
          if (safeRequest.onStarted !== undefined) {
            await safeRequest.onStarted({
              identity: { pid: processId, processGroupId: processId, startTimeMicros },
              descendants: processTree.snapshotDescendants()
            });
          }
          await assertProcessPathStable(safeRequest.executable, validatedPaths.executable, "Executable");
          await assertProcessPathStable(safeRequest.cwd, validatedPaths.cwd, "Process cwd");
        } catch (error) {
          const drained = await this.abortUnownedProcess(child, processId, processTree);
          if (!drained) throw new BrokerError("UNKNOWN_OUTCOME", "Process startup cleanup could not be verified", true);
          if (error instanceof BrokerError) throw error;
          throw new BrokerError("AUDIT_UNAVAILABLE", "Process identity could not be persisted");
        }
      }
      if (this.closing || this.cancelled(safeRequest.shouldCancel)) {
        const drained = await this.abortUnownedProcess(child, processId, processTree);
        if (!drained) throw new BrokerError("UNKNOWN_OUTCOME", "Process startup cleanup could not be verified", true);
        throw new BrokerError("CANCELLED", "Process authority was revoked before execution");
      }
      this.activeProcesses += 1;
      const currentActiveForExecutable = this.activeProcessesByExecutable.get(executableKey) ?? 0;
      this.activeProcessesByExecutable.set(executableKey, currentActiveForExecutable + 1);
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
      releasePendingStart();
      return this.observe(
        child,
        safeRequest,
        processId,
        startedAtMs,
        processTree,
        capture,
        (stop) => { stopRun = stop; },
        () => {
          if (drained) return;
          drained = true;
          const current = this.activeProcessesByExecutable.get(executableKey) ?? 0;
          if (current <= 1) this.activeProcessesByExecutable.delete(executableKey);
          else this.activeProcessesByExecutable.set(executableKey, current - 1);
          resolveDrained();
          this.activeRuns.delete(activeRun);
        }
      );
    } catch (error) {
      releasePendingStart();
      throw error;
    }
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
      // Without a native tree observer, group disappearance cannot prove that
      // a detached descendant did not escape. Keep the outcome unresolved.
      const deadline = Date.now() + Math.max(this.terminationGraceMs * 3, 1_000);
      while (Date.now() < deadline && processGroupAlive(processId)) {
        await new Promise((resolve) => setTimeout(resolve, this.pollIntervalMs));
      }
      return false;
    } else {
      processTree.sample();
      const rootState = processTree.rootState();
      if (rootState === "alive") signalProcessGroup(child, processId, "SIGKILL");
      else if (rootState === "unknown") {
        try { child.kill("SIGKILL"); } catch { /* Keep the cleanup outcome unresolved. */ }
      }
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
    const snapshot: ProcessOwnershipSnapshot = isPlainDataRecord(persistedValue) && Object.prototype.hasOwnProperty.call(persistedValue, "identity")
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
          typeof native.listProcessGroupMembers !== "function" ||
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
      if (snapshot.ownershipProof === "sandbox-exec-no-fork-v1" && snapshot.descendants.length === 0) {
        // The proof is bound to a Broker-validated single-process sandbox.
        // With no fork-capable descendant and no surviving detached group,
        // the dead root is the complete task boundary and absence is proven.
        if (!processGroupAlive(identity.processGroupId)) {
          return {
            outcome: "absent",
            processId: identity.pid,
            processGroupId: identity.processGroupId,
            terminationObserved: true
          };
        }
      }
      return {
        // A dead root and an empty current group still cannot prove that no
        // descendant was created after the last persisted observation and
        // escaped to another process group. The prior snapshot is evidence of
        // ownership, not a complete post-exit process census, so recovery must
        // remain unresolved instead of publishing absence.
        outcome: "unknown",
        processId: identity.pid,
        processGroupId: identity.processGroupId,
        terminationObserved: false
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
    const pendingStarts = [...this.pendingStarts];
    for (const run of activeRuns) run.stop();
    this.closePromise = Promise.all([
      ...activeRuns.map((run) => run.drained),
      ...pendingStarts
    ]).then(() => undefined);
    return this.closePromise;
  }

  private observe(
    child: ChildProcess,
    request: ProcessExecutionRequest,
    processId: number,
    startedAtMs: number,
    processTree: ProcessTreeTracker | undefined,
    capture: ChildProcessCapture,
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
      let childExitCode: number | null = capture.exited ? capture.exitCode : null;
      let childExitSignal: NodeJS.Signals | null = capture.exited ? capture.exitSignal : null;
      let strictExitProof: Promise<boolean> | undefined;
      let released = false;
      let stdout = capture.stdout;
      let stderr = capture.stderr;
      let spawnError = capture.spawnError;
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

      const handleExit = (): void => {
        childExitCode = capture.exitCode;
        childExitSignal = capture.exitSignal;
        if (request.requireCleanExitProof !== true || strictExitProof !== undefined) return;
        if (processTree === undefined) {
          strictExitProof = Promise.resolve(false);
          return;
        }
        // `close` waits for inherited stdout/stderr descriptors. A detached
        // child can keep those pipes open after the root exits, so anchor the
        // ownership proof at `exit` and use a bounded group-drain window.
        processTree.sample();
        notifyOwnership();
        // The detached group can remain visible for a short interval after
        // the root emits `exit`; let the bounded proof window distinguish
        // that teardown lag from a surviving descendant.
        strictExitProof = processTree.confirmNoDescendantsAfterExit(this.pollIntervalMs);
      };
      const handleClose = (): void => {
        childExitCode = capture.exitCode;
        childExitSignal = capture.exitSignal;
        void (async () => {
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
          } else if (request.requireCleanExitProof === true) {
            const clean = processTree === undefined
              ? false
              : await (strictExitProof ?? processTree.confirmNoDescendantsAfterExit(this.pollIntervalMs));
            if (settled) return;
            if (!clean) finishUnknown();
            else finish(childExitCode, childExitSignal);
          } else {
            finish(childExitCode, childExitSignal);
          }
        })();
      };

      capture.onOutput = () => {
        stdout = capture.stdout;
        stderr = capture.stderr;
        if (!settled && capture.outputOverflow) terminate("output_limit");
      };
      capture.onError = () => { spawnError = true; };
      capture.onExit = handleExit;
      capture.onClose = handleClose;
      capture.onOutput();
      if (capture.exited) handleExit();
      if (capture.closed) handleClose();

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

function attachChildProcessCapture(child: ChildProcess, outputCapBytes: number): ChildProcessCapture {
  const capture: ChildProcessCapture = {
    stdout: Buffer.alloc(0),
    stderr: Buffer.alloc(0),
    stdoutBytes: 0,
    stderrBytes: 0,
    outputOverflow: false,
    spawnError: false,
    exited: false,
    exitCode: null,
    exitSignal: null,
    closed: false
  };
  const append = (stream: "stdout" | "stderr", chunk: Buffer | string): void => {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const remaining = outputCapBytes - capture.stdoutBytes - capture.stderrBytes;
    const accepted = bytes.subarray(0, Math.max(0, Math.min(remaining, bytes.byteLength)));
    if (stream === "stdout") {
      if (accepted.byteLength > 0) capture.stdout = Buffer.concat([capture.stdout, accepted]);
      capture.stdoutBytes += accepted.byteLength;
    } else {
      if (accepted.byteLength > 0) capture.stderr = Buffer.concat([capture.stderr, accepted]);
      capture.stderrBytes += accepted.byteLength;
    }
    if (accepted.byteLength < bytes.byteLength) capture.outputOverflow = true;
    capture.onOutput?.();
  };
  child.stdout?.on("data", (chunk: Buffer | string) => append("stdout", chunk));
  child.stderr?.on("data", (chunk: Buffer | string) => append("stderr", chunk));
  child.once("error", () => {
    capture.spawnError = true;
    capture.onError?.();
  });
  child.once("exit", (code, signal) => {
    capture.exited = true;
    capture.exitCode = code;
    capture.exitSignal = signal;
    capture.onExit?.();
  });
  child.once("close", (code, signal) => {
    capture.closed = true;
    if (!capture.exited) {
      capture.exited = true;
      capture.exitCode = code;
      capture.exitSignal = signal;
      capture.onExit?.();
    }
    capture.onClose?.();
  });
  return capture;
}

async function validateRequest(
  request: ProcessExecutionRequest,
  allowedEnvironmentKeys: ReadonlySet<string>,
  requireRootOwnedExecutable: boolean
): Promise<ValidatedProcessPaths> {
  if (!isPlainDataRecord(request) ||
      !hasAllowedKeys(request, ["executable", "args", "cwd", "environment", "stdin", "timeoutMs", "outputCapBytes", "requireCleanExitProof", "shouldCancel", "onStarted", "onOwnershipChanged"]) ||
      !isCanonicalAbsolutePath(request.executable) || !isCanonicalAbsolutePath(request.cwd) ||
      !isDenseStringArray(request.args, MAX_ARGUMENTS) ||
      !Number.isSafeInteger(request.timeoutMs) || request.timeoutMs < 1 || request.timeoutMs > MAX_TIMEOUT_MS ||
      !Number.isSafeInteger(request.outputCapBytes) || request.outputCapBytes < 1 || request.outputCapBytes > MAX_OUTPUT_BYTES) {
    throw new BrokerError("PRECONDITION_FAILED", "Process request limits or paths are invalid");
  }
  if (request.stdin !== undefined && (typeof request.stdin !== "string" || request.stdin.includes("\0") || Buffer.byteLength(request.stdin, "utf8") > MAX_ARGUMENT_BYTES)) {
    throw new BrokerError("PRECONDITION_FAILED", "Process stdin exceeds the supported size");
  }
  if (request.environment !== undefined && !isPlainDataRecord(request.environment)) {
    throw new BrokerError("PRECONDITION_FAILED", "Process environment is malformed");
  }
  if (request.requireCleanExitProof !== undefined && typeof request.requireCleanExitProof !== "boolean") {
    throw new BrokerError("PRECONDITION_FAILED", "Process exit-proof policy is malformed");
  }
  if ((request.shouldCancel !== undefined && typeof request.shouldCancel !== "function") ||
      (request.onStarted !== undefined && typeof request.onStarted !== "function") ||
      (request.onOwnershipChanged !== undefined && typeof request.onOwnershipChanged !== "function")) {
    throw new BrokerError("PRECONDITION_FAILED", "Process control callbacks are malformed");
  }
  if (request.requireCleanExitProof === true && process.platform !== "darwin") {
    throw new BrokerError("POLICY_DENIED", "Clean process-tree exit proof is unavailable");
  }
  const argumentBytes = request.args.reduce((total, argument) => {
    if (typeof argument !== "string" || argument.includes("\0") || argument.length > 4_096) {
      throw new BrokerError("PRECONDITION_FAILED", "Process argument is invalid");
    }
    return total + Buffer.byteLength(argument, "utf8");
  }, 0);
  if (argumentBytes > MAX_ARGUMENT_BYTES) throw new BrokerError("PRECONDITION_FAILED", "Process arguments exceed the supported size");
  assertArgumentsDoNotContainSecrets(request.args);
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
  assertEnvironmentValuesDoNotContainSecrets(request.environment ?? {});
  let executable: ProcessPathIdentity;
  try {
    executable = await validateExecutable(request.executable);
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("TARGET_NOT_FOUND", "Broker-resolved executable was not found");
  }
  if (requireRootOwnedExecutable && executable.ownerUid !== 0) {
    throw new BrokerError("POLICY_DENIED", "Executable is not root-owned");
  }
  let cwd: ProcessPathIdentity;
  try {
    cwd = await validateDirectory(request.cwd);
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("TARGET_NOT_FOUND", "Broker-resolved process cwd was not found");
  }
  return { executable, cwd };
}

function isCanonicalAbsolutePath(value: string): boolean {
  return typeof value === "string" && value.length >= 1 && value.length <= 4_096 &&
    isAbsolute(value) && resolve(value) === value && !value.includes("\0") && !value.includes("\n");
}

function snapshotProcessRequest(value: unknown): ProcessExecutionRequest {
  if (!isPlainDataRecord(value) ||
      !hasAllowedKeys(value, ["executable", "args", "cwd", "environment", "stdin", "timeoutMs", "outputCapBytes", "requireCleanExitProof", "shouldCancel", "onStarted", "onOwnershipChanged"])) {
    throw new BrokerError("PRECONDITION_FAILED", "Process request limits or paths are invalid");
  }
  if (!isDenseStringArray(value.args, MAX_ARGUMENTS)) {
    throw new BrokerError("PRECONDITION_FAILED", "Process request limits or paths are invalid");
  }
  const environment = value.environment;
  if (environment !== undefined && !isPlainDataRecord(environment)) {
    throw new BrokerError("PRECONDITION_FAILED", "Process environment is malformed");
  }
  if (environment !== undefined && Object.keys(environment).length > MAX_ENVIRONMENT_KEYS) {
    throw new BrokerError("PRECONDITION_FAILED", "Process environment exceeds the supported size");
  }
  if (value.stdin !== undefined && (typeof value.stdin !== "string" || value.stdin.includes("\0") || Buffer.byteLength(value.stdin, "utf8") > MAX_ARGUMENT_BYTES)) {
    throw new BrokerError("PRECONDITION_FAILED", "Process stdin exceeds the supported size");
  }
  if (value.requireCleanExitProof !== undefined && typeof value.requireCleanExitProof !== "boolean") {
    throw new BrokerError("PRECONDITION_FAILED", "Process exit-proof policy is malformed");
  }
  if ((value.shouldCancel !== undefined && typeof value.shouldCancel !== "function") ||
      (value.onStarted !== undefined && typeof value.onStarted !== "function") ||
      (value.onOwnershipChanged !== undefined && typeof value.onOwnershipChanged !== "function")) {
    throw new BrokerError("PRECONDITION_FAILED", "Process control callbacks are malformed");
  }
  const snapshot: ProcessExecutionRequest = {
    executable: value.executable as string,
    args: [...value.args],
    cwd: value.cwd as string,
    timeoutMs: value.timeoutMs as number,
    outputCapBytes: value.outputCapBytes as number
  };
  if (environment !== undefined) snapshot.environment = Object.fromEntries(Object.entries(environment)) as Record<string, string>;
  if (value.stdin !== undefined) snapshot.stdin = value.stdin as string;
  if (value.requireCleanExitProof !== undefined) snapshot.requireCleanExitProof = value.requireCleanExitProof as boolean;
  if (value.shouldCancel !== undefined) snapshot.shouldCancel = value.shouldCancel as () => boolean;
  if (value.onStarted !== undefined) {
    snapshot.onStarted = value.onStarted as (snapshot: ProcessOwnershipSnapshot) => void | Promise<void>;
  }
  if (value.onOwnershipChanged !== undefined) {
    snapshot.onOwnershipChanged = value.onOwnershipChanged as (snapshot: ProcessOwnershipSnapshot) => void;
  }
  return snapshot;
}

function hasAllowedKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const allowedSet = new Set(allowed);
  return Object.keys(value).every((key) => allowedSet.has(key));
}

function isDenseStringArray(value: unknown, maxLength: number): value is readonly string[] {
  if (!Array.isArray(value) || value.length > maxLength || Object.getOwnPropertySymbols(value).length > 0 ||
      Object.keys(value).length !== value.length || Object.getOwnPropertyNames(value).length !== value.length + 1) {
    return false;
  }
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor) || typeof descriptor.value !== "string") return false;
  }
  return true;
}

export async function captureProcessPathIdentity(path: string, kind: ProcessPathKind): Promise<ProcessPathIdentity> {
  return kind === "executable" ? validateExecutable(path) : validateDirectory(path);
}

export async function assertProcessPathIdentityStable(
  path: string,
  expected: ProcessPathIdentity,
  kind: ProcessPathKind
): Promise<void> {
  const label = kind === "executable" ? "Executable" : "Process cwd";
  let current: ProcessPathIdentity;
  try {
    current = await captureProcessPathIdentity(path, kind);
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("POLICY_DENIED", `${label} changed after authorization`);
  }
  if (current.device !== expected.device || current.inode !== expected.inode || current.mode !== expected.mode ||
      (kind === "executable" && (current.size !== expected.size || current.mtimeMs !== expected.mtimeMs || current.ctimeMs !== expected.ctimeMs))) {
    throw new BrokerError("POLICY_DENIED", `${label} changed after authorization`);
  }
  if (kind === "executable" && current.contentSha256 !== expected.contentSha256) {
    throw new BrokerError("POLICY_DENIED", `${label} changed after authorization`);
  }
}

async function validateExecutable(path: string): Promise<ProcessPathIdentity> {
  const stat = await lstat(path);
  if (stat.isSymbolicLink()) throw new BrokerError("POLICY_DENIED", "Executable symlinks are not allowed");
  if (!stat.isFile() || (stat.mode & 0o111) === 0) throw new BrokerError("POLICY_DENIED", "Executable must be a regular executable file");
  if ((stat.mode & 0o022) !== 0) throw new BrokerError("POLICY_DENIED", "Executable permissions are not owner-only");
  if ((await realpath(path)) !== path) throw new BrokerError("POLICY_DENIED", "Executable symlinks are not allowed");
  const identity: ProcessPathIdentity = {
    device: stat.dev,
    inode: stat.ino,
    ownerUid: stat.uid,
    ownerGid: stat.gid,
    mode: stat.mode & 0o7777,
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    ctimeMs: stat.ctimeMs
  };
  if (stat.size > MAX_EXECUTABLE_DIGEST_BYTES) {
    throw new BrokerError("OUTPUT_LIMIT", "Executable exceeds the supported content-identity size");
  }
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (!sameProcessPathMetadata(opened, identity)) {
      throw new BrokerError("POLICY_DENIED", "Executable changed while opening");
    }
    const contentSha256 = await digestOpenedExecutable(handle, stat.size);
    const after = await handle.stat();
    if (!sameProcessPathMetadata(after, identity)) {
      throw new BrokerError("POLICY_DENIED", "Executable changed while reading");
    }
    return { ...identity, contentSha256 };
  } finally {
    await handle.close();
  }
}

async function validateDirectory(path: string): Promise<ProcessPathIdentity> {
  const stat = await lstat(path);
  if (!stat.isDirectory() || (await realpath(path)) !== path) throw new BrokerError("POLICY_DENIED", "Process cwd must be a canonical directory");
  return {
    device: stat.dev,
    inode: stat.ino,
    ownerUid: stat.uid,
    ownerGid: stat.gid,
    mode: stat.mode & 0o7777,
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    ctimeMs: stat.ctimeMs
  };
}

function sameProcessPathMetadata(
  stat: { dev: number; ino: number; uid: number; gid: number; mode: number; size: number; mtimeMs: number; ctimeMs: number },
  identity: ProcessPathIdentity
): boolean {
  return stat.dev === identity.device && stat.ino === identity.inode &&
    stat.uid === identity.ownerUid && stat.gid === identity.ownerGid &&
    (stat.mode & 0o7777) === identity.mode && stat.size === identity.size &&
    stat.mtimeMs === identity.mtimeMs && stat.ctimeMs === identity.ctimeMs;
}

async function digestOpenedExecutable(handle: Awaited<ReturnType<typeof open>>, expectedSize: number): Promise<string> {
  const digest = createHash("sha256");
  const buffer = Buffer.allocUnsafe(EXECUTABLE_DIGEST_READ_CHUNK_BYTES);
  let remaining = expectedSize;
  while (remaining > 0) {
    const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.byteLength, remaining), null);
    if (bytesRead < 1) throw new BrokerError("POLICY_DENIED", "Executable changed while reading");
    digest.update(buffer.subarray(0, bytesRead));
    remaining -= bytesRead;
  }
  const { bytesRead } = await handle.read(buffer, 0, 1, null);
  if (bytesRead !== 0) throw new BrokerError("POLICY_DENIED", "Executable changed while reading");
  return digest.digest("hex");
}

async function assertProcessPathStable(path: string, expected: ProcessPathIdentity, label: "Executable" | "Process cwd"): Promise<void> {
  await assertProcessPathIdentityStable(path, expected, label === "Executable" ? "executable" : "directory");
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
  if (!isPlainDataRecord(identity) || !hasExactFields(identity, ["pid", "processGroupId", "startTimeMicros"]) ||
      !Number.isSafeInteger(identity.pid) || identity.pid < 1 || identity.pid > 99_999_999 ||
      !Number.isSafeInteger(identity.processGroupId) || identity.processGroupId !== identity.pid ||
      !Number.isSafeInteger(identity.startTimeMicros) || identity.startTimeMicros < 1) {
    throw new BrokerError("PRECONDITION_FAILED", "Process ownership identity is malformed");
  }
}

function validateProcessOwnershipSnapshot(snapshot: ProcessOwnershipSnapshot): void {
  if (!isPlainDataRecord(snapshot) || !hasExactFields(snapshot, ["identity", "descendants"], ["ownershipProof"]) ||
      !isDenseArray(snapshot.descendants, 256)) {
    throw new BrokerError("PRECONDITION_FAILED", "Process ownership snapshot is malformed");
  }
  validateProcessOwnershipIdentity(snapshot.identity);
  if (snapshot.ownershipProof !== undefined && snapshot.ownershipProof !== "sandbox-exec-no-fork-v1") {
    throw new BrokerError("PRECONDITION_FAILED", "Process ownership proof is malformed");
  }
  if (snapshot.ownershipProof === "sandbox-exec-no-fork-v1" && snapshot.descendants.length > 0) {
    throw new BrokerError("PRECONDITION_FAILED", "No-fork process ownership proof has descendants");
  }
  if (snapshot.descendants.length > 256) {
    throw new BrokerError("PRECONDITION_FAILED", "Process ownership snapshot is too large");
  }
  let previousPid = 0;
  for (const descendant of snapshot.descendants) {
    if (!isPlainDataRecord(descendant) || !hasExactFields(descendant, ["pid", "startTimeMicros"]) ||
        !Number.isSafeInteger(descendant.pid) || descendant.pid < 1 || descendant.pid > 99_999_999 ||
        descendant.pid === snapshot.identity.pid || descendant.pid <= previousPid ||
        !Number.isSafeInteger(descendant.startTimeMicros) || descendant.startTimeMicros < 1) {
      throw new BrokerError("PRECONDITION_FAILED", "Process ownership snapshot is malformed");
    }
    previousPid = descendant.pid;
  }
}

function hasExactFields(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) && keys.every((key) => allowed.has(key));
}

function isDenseArray(value: unknown, maxLength: number): value is readonly unknown[] {
  if (!Array.isArray(value) || value.length > maxLength || Object.getOwnPropertySymbols(value).length > 0) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.prototype.hasOwnProperty.call(value, index)) return false;
  }
  return true;
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
    if (typeof native.listDescendantProcesses !== "function" || typeof native.listProcessGroupMembers !== "function" ||
        typeof native.isProcessIdentityAlive !== "function" ||
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
        startTimeMicros: expectedRootIdentity.startTimeMicros,
        processGroupId: expectedRootIdentity.processGroupId
      };
      return;
    }
    try {
      const identity = parseProcessIdentity(native.getProcessIdentity(processId), true);
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
      const identity = parseProcessIdentity(this.native.getProcessIdentity(this.processId), true);
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

  get rootProcessGroupId(): number | undefined {
    return this.rootIdentity?.processGroupId;
  }

  rootState(): "alive" | "dead" | "unknown" {
    if (this.failed) return "unknown";
    if (this.rootIdentity === undefined) return "dead";
    try {
      const alive = this.native.isProcessIdentityAlive(this.rootIdentity.pid, this.rootIdentity.startTimeMicros);
      if (alive === true) {
        const current = parseProcessIdentity(this.native.getProcessIdentity(this.rootIdentity.pid), true);
        if (current.pid !== this.rootIdentity.pid || current.startTimeMicros !== this.rootIdentity.startTimeMicros ||
            current.processGroupId !== this.rootIdentity.processGroupId) return "unknown";
        return "alive";
      }
      if (alive === false) return "dead";
      return "unknown";
    } catch {
      return "unknown";
    }
  }

  sample(): void {
    if (this.failed) return;
    try {
      const snapshots = [parseProcessTreeSnapshot(this.native.listDescendantProcesses(this.processId))];
      const processGroupId = this.rootIdentity?.processGroupId;
      if (processGroupId !== undefined) {
        snapshots.push(parseProcessTreeSnapshot(this.native.listProcessGroupMembers(processGroupId)));
      }
      const observedByPid = new Map<number, ProcessTreeIdentity>();
      for (const snapshot of snapshots) {
        if (snapshot.truncated) {
          this.failed = true;
          return;
        }
        for (const identity of snapshot.processes) {
          if (identity.pid === this.processId) continue;
          const existing = observedByPid.get(identity.pid);
          if (existing !== undefined && existing.startTimeMicros !== identity.startTimeMicros) {
            this.failed = true;
            return;
          }
          observedByPid.set(identity.pid, identity);
        }
      }
      const observed = [...observedByPid.values()];
      if (detectProcessIdentityReplacement(this.snapshotDescendants(), observed)) {
        this.failed = true;
        return;
      }
      for (const identity of observed) this.descendants.set(identity.pid, identity);
    } catch {
      this.failed = true;
    }
  }

  /**
   * Take one final native snapshot after the root process has closed. This is
   * intentionally stricter than the ordinary adapter path: any observer
   * uncertainty, truncation, or PID replacement keeps the task unresolved.
   */
  async confirmNoDescendantsAfterExit(settleDelayMs: number): Promise<boolean> {
    if (this.failed || this.rootIdentity === undefined) return false;
    this.sample();
    if (this.failed || this.aliveState() !== "none") return false;
    const deadline = Date.now() + Math.max(settleDelayMs, 25);
    while (processGroupAlive(this.processId) && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, settleDelayMs));
      if (this.failed || this.rootState() === "unknown") return false;
    }
    if (this.failed || this.rootState() === "unknown" || processGroupAlive(this.processId)) return false;
    this.sample();
    return !this.failed && this.aliveState() === "none" && !processGroupAlive(this.processId);
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

function parseProcessIdentity(value: unknown, requireProcessGroupId = false): ProcessTreeIdentity {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Malformed process identity");
  const identity = value as Record<string, unknown>;
  const pid = identity.pid;
  const parentPid = identity.parentPid;
  const processGroupId = identity.processGroupId;
  const startTimeMicros = identity.startTimeMicros;
  if (typeof pid !== "number" || !Number.isSafeInteger(pid) || pid < 1 || pid > 99_999_999 ||
      typeof parentPid !== "number" || !Number.isSafeInteger(parentPid) || parentPid < 1 || parentPid > 99_999_999 ||
      typeof startTimeMicros !== "number" || !Number.isSafeInteger(startTimeMicros) || startTimeMicros < 1) {
    throw new Error("Malformed process identity");
  }
  if (processGroupId !== undefined &&
      (typeof processGroupId !== "number" || !Number.isSafeInteger(processGroupId) || processGroupId < 1 || processGroupId > 99_999_999)) {
    throw new Error("Malformed process-group identity");
  }
  if (requireProcessGroupId && processGroupId === undefined) throw new Error("Process-group identity is unavailable");
  return { pid, startTimeMicros, ...(processGroupId === undefined ? {} : { processGroupId }) };
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
