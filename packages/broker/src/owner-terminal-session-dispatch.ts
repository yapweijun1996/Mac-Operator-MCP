import { setTimeout as delay } from "node:timers/promises";
import { BrokerError, canonicalJson, sha256, type BrokerRequest } from "@mac-operator/contracts";
import type { BrokerJob, BrokerStore, JobLease } from "./persistence.js";
import type { ProcessExecutionResult, ProcessOwnershipSnapshot } from "./process-supervisor.js";
import type { OwnerTerminalControl } from "./owner-terminal.js";
import type { OwnerTerminalSessionManager } from "./owner-terminal-session.js";
import type { OwnerTerminalSessionRequest } from "./owner-terminal-session-request.js";

export interface OwnerTerminalSessionDispatchResult {
  data: Record<string, unknown>;
  verification: Record<string, unknown>;
  warnings: string[];
  truncated: boolean;
  auditTarget: string;
  auditEvidence: Record<string, unknown>;
}

export interface StartedOwnerTerminalSession {
  result: OwnerTerminalSessionDispatchResult;
  /** Settles once the Job is persisted terminal; rejects for cancelled, timed-out or unresolved sessions. */
  finished: Promise<void>;
}

const MODE = "personal_owner_terminal_session";
const AUDIT_TARGET = "host:owner-terminal";
const WARNING = "Uses the macOS owner's permissions; session side effects are not isolated or automatically rolled back";

function wrap(data: Record<string, unknown>, status: "accepted" | "verified", summary: string, evidence: Record<string, unknown>,
    truncated = false): OwnerTerminalSessionDispatchResult {
  return { data: { ...data, execution_mode: MODE }, truncated,
    verification: { required: true, status, strategy: "exit_status_and_declared_task_verification", evidence: { summary } },
    warnings: [WARNING], auditTarget: AUDIT_TARGET, auditEvidence: { ...evidence, mode: MODE } };
}

/**
 * Starts a PTY session under an already admitted, leased Job. The Job stays running
 * for the life of the session; ownership is persisted before any input is accepted
 * and the terminal outcome is persisted when the process tree is drained.
 */
export async function startOwnerTerminalSession(options: {
  store: BrokerStore; manager: OwnerTerminalSessionManager; request: BrokerRequest;
  session: Extract<OwnerTerminalSessionRequest, { action: "start" }>; job: BrokerJob; lease?: JobLease;
  control: OwnerTerminalControl; assertAuthority: () => void; now: () => number;
}): Promise<StartedOwnerTerminalSession> {
  const { store, manager, request, session, now } = options;
  const principalId = request.principal.principalId;
  let job = options.job;
  if (job.state !== "running" || options.lease === undefined) {
    throw new BrokerError("CONFLICT", `Terminal session Job already exists in state ${job.state}; inspect ${job.jobId}`);
  }
  const lease = options.lease;
  const persist = (snapshot: ProcessOwnershipSnapshot, initial: boolean): void => {
    const metadata = { pid: snapshot.identity.pid, processGroupId: snapshot.identity.processGroupId,
      startTimeMicros: snapshot.identity.startTimeMicros, recordedAtMs: now(),
      taskDescriptorDigest: sha256(canonicalJson(request.arguments)), descendants: [...snapshot.descendants] };
    const current = store.ownedJob(job.jobId, principalId);
    if (!current) throw new BrokerError("AUDIT_UNAVAILABLE", "Terminal session Job disappeared during process observation");
    job = initial
      ? store.recordJobProcessOwnership(job.jobId, principalId, current.revision, metadata, lease, now())
      : store.updateJobProcessOwnership(job.jobId, principalId, current.revision, metadata, lease, now());
  };
  let settle!: (error?: BrokerError) => void;
  const finished = new Promise<void>((resolve, reject) => { settle = error => error ? reject(error) : resolve(); });
  finished.catch(() => undefined);
  const onFinished = (result: ProcessExecutionResult): ProcessExecutionResult => {
    try {
      let current = store.ownedJob(job.jobId, principalId);
      if (!current) throw new BrokerError("AUDIT_UNAVAILABLE", "Terminal session Job disappeared before exit readback");
      if (result.state === "cancelled" || current.cancelRequested && result.terminationObserved) {
        if (!result.terminationObserved) throw new BrokerError("UNKNOWN_OUTCOME", "Terminal session cancellation could not be observed");
        if (!current.cancelRequested) {
          if (!options.control.shouldCancel()) throw new BrokerError("UNKNOWN_OUTCOME", "Terminal session cancellation authority could not be confirmed");
          current = store.requestJobCancellation(job.jobId, principalId, "OWNER_TERMINAL_AUTHORITY_CANCELLED", now()).job;
        }
      }
      const cancelled = current.cancelRequested && result.terminationObserved;
      job = store.finishJob(job.jobId, principalId, current.revision, {
        state: result.state === "unknown" ? "unknown" : cancelled ? "cancelled" : result.state === "completed" ? "completed" : "failed",
        resultClass: result.state === "unknown" ? "unknown" : cancelled ? "denied" : result.state === "completed" ? "success" : "failed",
        finishedAtMs: now(), exitCode: result.exitCode, truncated: false,
        // UNKNOWN is reserved for missing process-tree proof, with an explicit
        // diagnostic and preserved ownership for recovery; never infer success.
        stderr: result.state === "unknown" ? "PTY_TERMINATION_UNOBSERVED: process-tree cleanup could not be verified" : ""
      }, lease, now());
      if (result.state === "unknown") settle(new BrokerError("UNKNOWN_OUTCOME", `Terminal session termination is uncertain; inspect ${job.jobId}`));
      else if (cancelled) settle(new BrokerError("CANCELLED", `Terminal session was cancelled; inspect ${job.jobId}`));
      else if (result.state === "timed_out") settle(new BrokerError("TIMEOUT", `Terminal session reached its lifetime limit; inspect ${job.jobId}`));
      else settle();
      return cancelled ? { ...result, state: "cancelled", resultClass: "CANCELLED" } : result;
    } catch (error) {
      const failure = error instanceof BrokerError ? error : new BrokerError("AUDIT_UNAVAILABLE", `Terminal session outcome could not be recorded; inspect ${job.jobId}`, true);
      settle(failure);
      // The manager must retain the session and refuse to publish finished
      // until the authoritative ledger commit succeeds.
      throw failure;
    }
  };
  try {
    options.assertAuthority();
    const { sessionId } = await manager.start(principalId, { cwd: session.cwd, rows: session.rows, cols: session.cols,
      lifetimeMs: session.lifetimeMs, idleTimeoutMs: session.idleTimeoutMs, tag: job.jobId,
      shouldCancel: options.control.shouldCancel,
      onIdleTimeout: () => { store.requestJobCancellation(job.jobId, principalId, "OWNER_TERMINAL_IDLE_TIMEOUT", now()); },
      onProcessStarted: snapshot => persist(snapshot, true), onProcessOwnershipChanged: snapshot => persist(snapshot, false), onFinished });
    return { finished, result: wrap({ action: "start", session_id: sessionId, job_id: job.jobId, state: "running", reused: false },
      "accepted", "The PTY shell started and its process identity was persisted; use read, write and stop with the session id",
      { jobId: job.jobId, action: "start" }) };
  } catch (error) {
    const current = store.ownedJob(job.jobId, principalId);
    if (current?.state === "running") {
      const uncertain = error instanceof BrokerError && (error.errorClass === "UNKNOWN_OUTCOME" || error.errorClass === "AUDIT_UNAVAILABLE" && current.processMetadata !== undefined);
      store.finishJob(job.jobId, principalId, current.revision, { state: uncertain ? "unknown" : current.cancelRequested ? "cancelled" : "failed",
        resultClass: uncertain ? "unknown" : current.cancelRequested ? "denied" : "failed", finishedAtMs: now(),
        stderr: uncertain ? "PTY_START_UNRESOLVED: startup or final-state persistence could not be verified" : "PTY_START_FAILED: terminal session was not admitted" }, lease, now());
    }
    settle(error instanceof BrokerError ? error : new BrokerError("EXECUTION_FAILED", `Terminal session could not be started; inspect ${job.jobId}`));
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("EXECUTION_FAILED", `Terminal session could not be started; inspect ${job.jobId}`);
  }
}

/** write, read and stop act on an in-memory session owned by the same principal. */
export async function dispatchOwnerTerminalSessionIo(options: {
  store: BrokerStore; now: () => number; manager: OwnerTerminalSessionManager; request: BrokerRequest;
  session: Exclude<OwnerTerminalSessionRequest, { action: "start" }>; assertAuthority: () => void;
}): Promise<OwnerTerminalSessionDispatchResult> {
  const { manager, session } = options;
  const principalId = options.request.principal.principalId;
  const info = manager.describe(principalId, session.sessionId);
  const base = { session_id: session.sessionId, job_id: info.tag };
  const evidence = { jobId: info.tag, action: session.action };
  if (session.action === "write") {
    manager.write(principalId, session.sessionId, session.data);
    return wrap({ ...base, action: "write", state: "running" }, "accepted", "Input was delivered to the PTY; read the session for its effect", evidence);
  }
  if (session.action === "read") {
    let read = manager.read(principalId, session.sessionId, session.cursor, session.maxBytes);
    for (let waited = 0; read.data.length === 0 && !read.finished && waited < session.waitMs; waited += 50) {
      await delay(50);
      options.assertAuthority();
      read = manager.read(principalId, session.sessionId, session.cursor, session.maxBytes);
    }
    return wrap({ ...base, action: "read", state: read.finished ? read.state! : "running",
      output: read.data, next_cursor: read.nextCursor, dropped_bytes: read.droppedBytes, truncated: read.truncated, finished: read.finished,
      ...(read.finished ? { exit_code: read.exitCode ?? null } : {}) }, "verified", "Redacted PTY output was read from the cursor", evidence, read.truncated);
  }
  manager.stop(principalId, session.sessionId);
  const waitForEnd = async (limitMs: number): Promise<void> => {
    for (let waited = 0; waited < limitMs && !manager.describe(principalId, session.sessionId).finished; waited += 50) await delay(50);
  };
  await waitForEnd(3_000);
  if (!manager.describe(principalId, session.sessionId).finished) {
    // The shell ignored the hangup: escalate through the Job so the supervisor drains the tree.
    options.store.requestJobCancellation(info.tag, principalId, "OWNER_TERMINAL_STOP_ESCALATED", options.now());
    await waitForEnd(5_000);
  }
  const read = manager.read(principalId, session.sessionId, 0, 1);
  return wrap({ ...base, action: "stop", state: read.finished ? read.state! : "running", finished: read.finished,
    ...(read.finished ? { exit_code: read.exitCode ?? null } : {}) },
  read.finished ? "verified" : "accepted", read.finished ? "The session ended and its process tree was drained" : "Stop was requested; the session is still draining", evidence);
}
