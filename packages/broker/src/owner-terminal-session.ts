import { randomBytes } from "node:crypto";
import { lstat, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import { assertContentDoesNotContainSecrets, redactBoundedText } from "./secret-policy.js";
import { ProcessSupervisor, type ProcessExecutionResult, type ProcessOwnershipSnapshot, type ProcessStdinSink } from "./process-supervisor.js";

const MAX_WRITE_BYTES = 4_096;
// Terminal escape bytes JSON-encode up to 6x, so keep a read within the 256 KiB result cap.
const MAX_READ_BYTES = 32_768;
const RING_BYTES = 262_144;
const MAX_LIFETIME_MS = 600_000;
const FINISHED_RETENTION_MS = 60_000;

/**
 * Allocates a pseudo-terminal with the system Python and relays bytes between the
 * Broker pipes and the PTY master. Python is a root-owned system executable, so no
 * native Node dependency is needed. Window size arrives as argv.
 */
const PTY_SHIM = `
import errno, fcntl, os, select, signal, struct, sys, termios, time, pty
rows, cols, cwd = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
pid, fd = pty.fork()
if pid == 0:
    os.chdir(cwd)
    os.environ['PATH'] = '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:' + os.environ['HOME'] + '/.local/bin'
    os.environ['TMPDIR'] = '/tmp'
    os.execv('/bin/zsh', ['zsh', '-f'])
stop_signal = 0
def requested_stop(sig, frame):
    global stop_signal
    stop_signal = sig
signal.signal(signal.SIGTERM, requested_stop)
signal.signal(signal.SIGHUP, requested_stop)
pending = bytearray()
stopped = False
failed = False
status = None
foreground = pid
try:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
    os.set_blocking(fd, False)
    while not stop_signal:
        # Bound queued input, handle short writes, and keep reading a raw-mode TUI
        # even when its input is backpressured. Terminal bytes stay opaque.
        readers = [fd] + ([0] if len(pending) < 65536 else [])
        ready, writable, _ = select.select(readers, [fd] if pending else [], [], 0.1)
        if fd in ready:
            try:
                data = os.read(fd, 4096)
            except OSError as error:
                if error.errno in (errno.EAGAIN, errno.EINTR):
                    continue
                if error.errno == errno.EIO:
                    break
                raise
            if not data:
                break
            view = memoryview(data)
            while view:
                try:
                    count = os.write(1, view)
                    view = view[count:]
                except InterruptedError:
                    continue
        if 0 in ready:
            data = os.read(0, 4096)
            if not data:
                stopped = True
                break
            pending.extend(data)
        if fd in writable:
            try:
                count = os.write(fd, pending)
                del pending[:count]
            except OSError as error:
                if error.errno not in (errno.EAGAIN, errno.EINTR):
                    raise
except (OSError, ValueError) as error:
    failed = True
    try:
        os.write(2, ('PTY_RELAY_FAILED errno=%s\\n' % getattr(error, 'errno', None)).encode())
    except OSError:
        pass
finally:
    # Capture the terminal-owned foreground group before closing the master.
    # Closing it first loses the only handle to a foreground TUI's job group.
    try:
        foreground = os.tcgetpgrp(fd)
    except OSError:
        pass
    if stopped or failed or stop_signal:
        for group in set((pid, foreground)):
            if group > 0:
                try:
                    if os.getsid(group) == pid:
                        os.killpg(group, signal.SIGHUP)
                except ProcessLookupError:
                    pass
    try:
        os.close(fd)
    except OSError:
        pass
    for sig, wait in ((None, 0.3), (signal.SIGTERM, 0.3), (signal.SIGKILL, 0.3)):
        # An unreaped direct child cannot have its PID reused. Foreground groups
        # receive HUP only while the terminal is attached; any survivors are
        # drained by the supervisor using PID/start-time identities.
        if status is None and sig is not None:
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + wait
        while status is None and time.monotonic() < deadline:
            try:
                done, value = os.waitpid(pid, os.WNOHANG)
                if done:
                    status = value
            except ChildProcessError:
                failed = True
                break
            if status is None:
                time.sleep(0.01)
        if status is not None:
            break
    if status is None:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            status = os.waitpid(pid, 0)[1]
        except ChildProcessError:
            failed = True
if failed or status is None:
    sys.exit(1)
if stop_signal:
    sys.exit(128 + stop_signal)
if stopped:
    sys.exit(0)
sys.exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status))
`.replace(/^[ \t]*#.*\n/gmu, ""); // Keep the documented shim within the supervisor's 4096-byte argument bound.

export interface OwnerTerminalSessionStart {
  cwd: string;
  rows?: number;
  cols?: number;
  /** Absolute session lifetime, at most 600000 ms (the supervisor timeout ceiling). */
  lifetimeMs: number;
  /** Ends the session when the client neither reads nor writes for this long. */
  idleTimeoutMs: number;
  /** Opaque caller label (the Broker stores its Job id) returned by describe(). */
  tag?: string;
  shouldCancel: () => boolean;
  /** Called once, before the cancellation it causes, when the idle limit is reached. */
  onIdleTimeout?: () => void;
  onProcessStarted?: (snapshot: ProcessOwnershipSnapshot) => void | Promise<void>;
  onProcessOwnershipChanged?: (snapshot: ProcessOwnershipSnapshot) => void;
  /** Must commit the final Job state before resolving. Failed commits retain the session. */
  onFinished?: (result: ProcessExecutionResult) => void | ProcessExecutionResult | Promise<void | ProcessExecutionResult>;
}

export interface OwnerTerminalSessionRead {
  data: string;
  nextCursor: number;
  /** Bytes that left the ring buffer before the caller read them. */
  droppedBytes: number;
  truncated: boolean;
  finished: boolean;
  state?: ProcessExecutionResult["state"];
  exitCode?: number | null;
}

interface Session {
  id: string;
  ownerId: string;
  tag: string;
  sink?: ProcessStdinSink | undefined;
  chunks: Buffer[];
  baseOffset: number;
  endOffset: number;
  lastActivityMs: number;
  idleTimeoutMs: number;
  stopRequested: boolean;
  inputEnded: boolean;
  failureRequested?: boolean;
  idleNotified?: boolean;
  result?: ProcessExecutionResult;
  finalizationError?: BrokerError;
  retainTimer?: NodeJS.Timeout;
}

/**
 * Interactive owner-terminal sessions. Like the one-shot owner terminal this is
 * personal owner authority without isolation. The caller (Broker) is responsible for
 * per-call authorization; this class bounds, screens and redacts the byte streams.
 */
export class OwnerTerminalSessionManager {
  readonly available: boolean;
  private readonly supervisor: Pick<ProcessSupervisor, "run" | "close">;
  private readonly sessions = new Map<string, Session>();
  private readonly maxSessions: number;
  private readonly now: () => number;
  private readonly finishedRetentionMs: number;
  private readonly completions = new Set<Promise<void>>();
  private closing = false;

  constructor(options: { enabled?: boolean; maxSessions?: number; now?: () => number; finishedRetentionMs?: number;
    supervisor?: Pick<ProcessSupervisor, "run" | "close"> } = {}) {
    this.available = options.enabled === true && process.platform === "darwin" && process.getuid?.() !== 0;
    this.maxSessions = options.maxSessions ?? 2;
    this.now = options.now ?? Date.now;
    this.finishedRetentionMs = options.finishedRetentionMs ?? FINISHED_RETENTION_MS;
    if (!Number.isSafeInteger(this.finishedRetentionMs) || this.finishedRetentionMs < 1 || this.finishedRetentionMs > FINISHED_RETENTION_MS) {
      throw new Error("Terminal session retention is outside the supported range");
    }
    this.supervisor = options.supervisor ?? new ProcessSupervisor({ requireRootOwnedExecutable: true,
      requireSystemPublishedExecutable: true, maxConcurrent: this.maxSessions, maxConcurrentPerExecutable: this.maxSessions,
      allowedEnvironmentKeys: ["HOME", "LANG", "LC_ALL", "TERM"] });
  }

  async start(ownerId: string, request: OwnerTerminalSessionStart): Promise<{ sessionId: string }> {
    if (!this.available) throw new BrokerError("POLICY_DENIED", "Personal owner terminal mode is not enabled");
    if (this.closing) throw new BrokerError("CANCELLED", "Terminal session manager is closed");
    const rows = request.rows ?? 24;
    const cols = request.cols ?? 80;
    if (typeof ownerId !== "string" || ownerId.length === 0 || !isAbsolute(request.cwd) || request.cwd.includes("\0") ||
        !Number.isSafeInteger(rows) || rows < 1 || rows > 200 || !Number.isSafeInteger(cols) || cols < 1 || cols > 500 ||
        !Number.isSafeInteger(request.lifetimeMs) || request.lifetimeMs < 1_000 || request.lifetimeMs > MAX_LIFETIME_MS ||
        !Number.isSafeInteger(request.idleTimeoutMs) || request.idleTimeoutMs < 1_000 || request.idleTimeoutMs > request.lifetimeMs) {
      throw new BrokerError("PRECONDITION_FAILED", "Terminal session cwd, size or time limits are invalid");
    }
    const cwd = await realpath(request.cwd).catch(() => { throw new BrokerError("TARGET_NOT_FOUND", "Terminal cwd does not exist"); });
    if (!(await lstat(cwd)).isDirectory()) throw new BrokerError("PRECONDITION_FAILED", "Terminal cwd must be a directory");
    if (request.shouldCancel()) throw new BrokerError("CANCELLED", "Terminal authority was revoked before execution");
    if ([...this.sessions.values()].filter(session => session.result === undefined).length >= this.maxSessions) {
      throw new BrokerError("CONFLICT", "Terminal session capacity is exhausted", true);
    }
    const home = await realpath(homedir());
    // Recheck after path resolution so concurrent starts/shutdown cannot outrun admission.
    if (this.closing) throw new BrokerError("CANCELLED", "Terminal session manager is closed");
    if ([...this.sessions.values()].filter(session => session.result === undefined).length >= this.maxSessions) {
      throw new BrokerError("CONFLICT", "Terminal session capacity is exhausted", true);
    }
    const session: Session = { id: `tsess_${randomBytes(12).toString("hex")}`, ownerId, tag: request.tag ?? "", chunks: [], baseOffset: 0, endOffset: 0,
      lastActivityMs: this.now(), idleTimeoutMs: request.idleTimeoutMs, stopRequested: false, inputEnded: false };
    this.sessions.set(session.id, session);
    let markReady!: () => void;
    let markFailed!: (error: unknown) => void;
    const ready = new Promise<void>((resolve, reject) => { markReady = resolve; markFailed = reject; });
    let inputReady = false;
    let ownership: ProcessOwnershipSnapshot | undefined;
    const startedAt = this.now();
    const running = this.supervisor.run({
      executable: "/usr/bin/python3", args: ["-c", PTY_SHIM, String(rows), String(cols), cwd], cwd: home,
      environment: { HOME: home, LANG: "en_US.UTF-8", LC_ALL: "en_US.UTF-8", TERM: "xterm-256color" },
      timeoutMs: request.lifetimeMs, outputCapBytes: 1,
      keepStdinOpen: true, streamOutput: true,
      onOutputChunk: chunk => this.append(session, chunk),
      onStdinReady: sink => { session.sink = sink; inputReady = true; markReady(); },
      shouldCancel: () => {
        if (request.shouldCancel() || session.stopRequested) return true;
        if (this.now() - session.lastActivityMs <= session.idleTimeoutMs) return false;
        if (!session.idleNotified) {
          session.idleNotified = true;
          request.onIdleTimeout?.();
        }
        return true;
      },
      onStarted: async snapshot => { ownership = snapshot; await request.onProcessStarted?.(snapshot); },
      ...(request.onProcessOwnershipChanged ? { onOwnershipChanged: request.onProcessOwnershipChanged } : {})
    });
    const completion = running.then(async result => {
      // Orphan cleanup is a failed PTY when the supervisor proved the tree drained.
      // Unobserved termination remains explicitly uncertain, never fabricated success.
      const terminal = (result.state === "unknown" || result.state === "cancelled" && session.failureRequested) && result.terminationObserved
        ? { ...result, state: "failed" as const, resultClass: "EXECUTION_FAILED" as const } : result;
      await this.finish(session, terminal, request);
      if (!inputReady) markFailed(new BrokerError("EXECUTION_FAILED", "Terminal session ended before input became ready"));
    }, async error => {
      const brokerError = error instanceof BrokerError ? error : new BrokerError("UNKNOWN_OUTCOME", "Terminal session supervision failed", true);
      const uncertain = brokerError.errorClass === "UNKNOWN_OUTCOME";
      await this.finish(session, { state: uncertain ? "unknown" : "failed", resultClass: uncertain ? "UNKNOWN_OUTCOME" : "EXECUTION_FAILED",
        exitCode: null, signal: null, stdout: "", stderr: "", truncated: false, durationMs: Math.max(0, this.now() - startedAt),
        processId: ownership?.identity.pid ?? 0, processGroupId: ownership?.identity.processGroupId ?? 0, terminationObserved: !uncertain }, request);
      markFailed(brokerError);
    }).catch(error => {
      session.finalizationError = error instanceof BrokerError ? error : new BrokerError("AUDIT_UNAVAILABLE", "Terminal session final state could not be persisted", true);
      markFailed(session.finalizationError);
    });
    this.completions.add(completion);
    void completion.then(() => { this.completions.delete(completion); });
    await ready;
    return { sessionId: session.id };
  }

  /** Sends bytes to the PTY. Control characters are allowed; known secrets are not. */
  write(ownerId: string, sessionId: string, data: string): void {
    const session = this.owned(ownerId, sessionId);
    if (session.result !== undefined || session.inputEnded || session.sink === undefined) throw new BrokerError("CONFLICT", "Terminal session has ended or is stopping");
    if (typeof data !== "string" || data.length === 0 || data.includes("\0") || Buffer.byteLength(data, "utf8") > MAX_WRITE_BYTES) {
      throw new BrokerError("PRECONDITION_FAILED", "Terminal input is empty, contains NUL or exceeds 4096 bytes");
    }
    assertContentDoesNotContainSecrets(Buffer.from(data, "utf8"));
    session.lastActivityMs = this.now();
    try {
      if (!session.sink.write(data)) throw new BrokerError("EXECUTION_FAILED", "Terminal session input is not writable");
    } catch {
      session.failureRequested = true;
      session.stopRequested = true;
      throw new BrokerError("EXECUTION_FAILED", "Terminal session input is not writable");
    }
  }

  read(ownerId: string, sessionId: string, cursor: number, maxBytes = MAX_READ_BYTES): OwnerTerminalSessionRead {
    const session = this.owned(ownerId, sessionId);
    if (!Number.isSafeInteger(cursor) || cursor < 0 || cursor > session.endOffset ||
        !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_READ_BYTES) {
      throw new BrokerError("PRECONDITION_FAILED", "Terminal read cursor or size is invalid");
    }
    session.lastActivityMs = this.now();
    const from = Math.max(cursor, session.baseOffset);
    const dropped = from - cursor;
    const all = Buffer.concat(session.chunks);
    let slice = all.subarray(from - session.baseOffset);
    let truncated = false;
    if (slice.byteLength > maxBytes) {
      let end = maxBytes;
      // Do not split a UTF-8 sequence.
      while (end > 0 && (slice[end]! & 0xc0) === 0x80) end -= 1;
      slice = slice.subarray(0, end);
      truncated = true;
    }
    const redacted = redactBoundedText(slice.toString("utf8"), MAX_READ_BYTES * 2);
    const base = { data: redacted.text, nextCursor: from + slice.byteLength, droppedBytes: dropped,
      truncated: truncated || redacted.truncated, finished: session.result !== undefined };
    return session.result === undefined ? base : { ...base, state: session.result.state, exitCode: session.result.exitCode };
  }

  describe(ownerId: string, sessionId: string): { tag: string; finished: boolean } {
    const session = this.owned(ownerId, sessionId);
    return { tag: session.tag, finished: session.result !== undefined };
  }

  /**
   * Graceful stop: closing the PTY hangs up the shell and the session ends as completed.
   * A session that ignores the hangup must be cancelled by its owner (Job cancellation).
   */
  stop(ownerId: string, sessionId: string): void {
    const session = this.owned(ownerId, sessionId);
    if (session.result !== undefined || session.inputEnded) return;
    session.inputEnded = true;
    try { session.sink?.end(); }
    catch {
      session.failureRequested = true;
      session.stopRequested = true;
      throw new BrokerError("EXECUTION_FAILED", "Terminal session input could not be closed");
    }
  }

  async close(): Promise<void> {
    this.closing = true;
    for (const session of this.sessions.values()) {
      session.stopRequested = true;
      try { this.stop(session.ownerId, session.id); } catch { /* Supervision still drains the tree. */ }
    }
    await this.supervisor.close();
    await Promise.all(this.completions);
    const failure = [...this.sessions.values()].find(session => session.finalizationError)?.finalizationError;
    if (failure) throw failure;
    for (const session of this.sessions.values()) if (session.retainTimer) clearTimeout(session.retainTimer);
    this.sessions.clear();
  }

  private owned(ownerId: string, sessionId: string): Session {
    const session = this.sessions.get(sessionId);
    // Same error for missing and foreign sessions so ids cannot be probed.
    if (session === undefined || session.ownerId !== ownerId) throw new BrokerError("TARGET_NOT_FOUND", "Terminal session was not found");
    if (session.finalizationError) throw session.finalizationError;
    return session;
  }

  private append(session: Session, chunk: Buffer): void {
    session.chunks.push(chunk);
    session.endOffset += chunk.byteLength;
    let retained = session.endOffset - session.baseOffset;
    while (retained > RING_BYTES && session.chunks.length > 1) {
      const dropped = session.chunks.shift()!;
      session.baseOffset += dropped.byteLength;
      retained -= dropped.byteLength;
    }
  }

  private async finish(session: Session, result: ProcessExecutionResult, request: OwnerTerminalSessionStart): Promise<void> {
    session.sink = undefined;
    session.inputEnded = true;
    // The caller owns the authoritative ledger commit. Do not publish finished
    // or arm eviction when that commit fails.
    const committed = await request.onFinished?.(result);
    session.result = committed ?? result;
    session.retainTimer = setTimeout(() => this.sessions.delete(session.id), this.finishedRetentionMs);
    session.retainTimer.unref();
  }
}
