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
import fcntl, os, select, struct, sys, termios, pty
rows, cols, cwd = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
pid, fd = pty.fork()
if pid == 0:
    os.chdir(cwd)
    os.environ['PATH'] = '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'
    os.environ['TMPDIR'] = '/tmp'
    os.execv('/bin/zsh', ['zsh', '-f'])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
stdin_open = True
hung_up = False
while True:
    fds = [fd] + ([0] if stdin_open else [])
    ready, _, _ = select.select(fds, [], [])
    if fd in ready:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        os.write(1, data)
    if stdin_open and 0 in ready:
        data = os.read(0, 4096)
        if not data:
            stdin_open = False
            hung_up = True
            os.close(fd)
            break
        os.write(fd, data)
try:
    status = os.waitpid(pid, 0)[1]
except ChildProcessError:
    status = 0
if hung_up:
    sys.exit(0)
sys.exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status))
`;

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
  onProcessStarted?: (snapshot: ProcessOwnershipSnapshot) => void | Promise<void>;
  onProcessOwnershipChanged?: (snapshot: ProcessOwnershipSnapshot) => void;
  onFinished?: (result: ProcessExecutionResult) => void;
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
  result?: ProcessExecutionResult;
  retainTimer?: NodeJS.Timeout;
}

/**
 * Interactive owner-terminal sessions. Like the one-shot owner terminal this is
 * personal owner authority without isolation. The caller (Broker) is responsible for
 * per-call authorization; this class bounds, screens and redacts the byte streams.
 */
export class OwnerTerminalSessionManager {
  readonly available: boolean;
  private readonly supervisor: ProcessSupervisor;
  private readonly sessions = new Map<string, Session>();
  private readonly maxSessions: number;
  private readonly now: () => number;

  constructor(options: { enabled?: boolean; maxSessions?: number; now?: () => number } = {}) {
    this.available = options.enabled === true && process.platform === "darwin" && process.getuid?.() !== 0;
    this.maxSessions = options.maxSessions ?? 2;
    this.now = options.now ?? Date.now;
    this.supervisor = new ProcessSupervisor({ requireRootOwnedExecutable: true,
      requireSystemPublishedExecutable: true, maxConcurrent: this.maxSessions, maxConcurrentPerExecutable: this.maxSessions,
      allowedEnvironmentKeys: ["HOME", "LANG", "LC_ALL", "TERM"] });
  }

  async start(ownerId: string, request: OwnerTerminalSessionStart): Promise<{ sessionId: string }> {
    if (!this.available) throw new BrokerError("POLICY_DENIED", "Personal owner terminal mode is not enabled");
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
    const session: Session = { id: `tsess_${randomBytes(12).toString("hex")}`, ownerId, tag: request.tag ?? "", chunks: [], baseOffset: 0, endOffset: 0,
      lastActivityMs: this.now(), idleTimeoutMs: request.idleTimeoutMs, stopRequested: false };
    this.sessions.set(session.id, session);
    const home = await realpath(homedir());
    let markReady!: () => void;
    let markFailed!: (error: unknown) => void;
    const ready = new Promise<void>((resolve, reject) => { markReady = resolve; markFailed = reject; });
    const running = this.supervisor.run({
      executable: "/usr/bin/python3", args: ["-c", PTY_SHIM, String(rows), String(cols), cwd], cwd: home,
      environment: { HOME: home, LANG: "en_US.UTF-8", LC_ALL: "en_US.UTF-8", TERM: "xterm-256color" },
      timeoutMs: request.lifetimeMs, outputCapBytes: 1,
      keepStdinOpen: true, streamOutput: true,
      onOutputChunk: chunk => this.append(session, chunk),
      onStdinReady: sink => { session.sink = sink; markReady(); },
      shouldCancel: () => request.shouldCancel() || session.stopRequested ||
        this.now() - session.lastActivityMs > session.idleTimeoutMs,
      ...(request.onProcessStarted ? { onStarted: request.onProcessStarted } : {}),
      ...(request.onProcessOwnershipChanged ? { onOwnershipChanged: request.onProcessOwnershipChanged } : {})
    });
    void running.then(result => this.finish(session, result, request), error => {
      this.sessions.delete(session.id);
      markFailed(error);
    });
    await ready;
    return { sessionId: session.id };
  }

  /** Sends bytes to the PTY. Control characters are allowed; known secrets are not. */
  write(ownerId: string, sessionId: string, data: string): void {
    const session = this.owned(ownerId, sessionId);
    if (session.result !== undefined || session.sink === undefined) throw new BrokerError("CONFLICT", "Terminal session has ended");
    if (typeof data !== "string" || data.length === 0 || data.includes("\0") || Buffer.byteLength(data, "utf8") > MAX_WRITE_BYTES) {
      throw new BrokerError("PRECONDITION_FAILED", "Terminal input is empty, contains NUL or exceeds 4096 bytes");
    }
    assertContentDoesNotContainSecrets(Buffer.from(data, "utf8"));
    session.lastActivityMs = this.now();
    if (!session.sink.write(data)) throw new BrokerError("EXECUTION_FAILED", "Terminal session input is not writable");
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
    if (session.result !== undefined) return;
    session.sink?.end();
  }

  async close(): Promise<void> {
    for (const session of this.sessions.values()) { session.stopRequested = true; session.sink?.end(); }
    await this.supervisor.close();
    for (const session of this.sessions.values()) if (session.retainTimer) clearTimeout(session.retainTimer);
    this.sessions.clear();
  }

  private owned(ownerId: string, sessionId: string): Session {
    const session = this.sessions.get(sessionId);
    // Same error for missing and foreign sessions so ids cannot be probed.
    if (session === undefined || session.ownerId !== ownerId) throw new BrokerError("TARGET_NOT_FOUND", "Terminal session was not found");
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

  private finish(session: Session, result: ProcessExecutionResult, request: OwnerTerminalSessionStart): void {
    session.result = result;
    session.sink = undefined;
    try { request.onFinished?.(result); } catch { /* Persistence failures are the Broker's to surface. */ }
    session.retainTimer = setTimeout(() => this.sessions.delete(session.id), FINISHED_RETENTION_MS);
    session.retainTimer.unref();
  }
}
