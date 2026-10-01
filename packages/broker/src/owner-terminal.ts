import { lstat, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import { isPlainDataRecord } from "./plain-record.js";
import { assertContentDoesNotContainSecrets } from "./secret-policy.js";
import { ProcessSupervisor, type ProcessExecutionResult, type ProcessOwnershipSnapshot } from "./process-supervisor.js";

export interface OwnerTerminalRequest {
  command: string;
  cwd: string;
  idempotencyKey: string;
  timeoutMs: number;
}

export interface OwnerTerminalControl {
  timeoutMs: number;
  shouldCancel: () => boolean;
  onProcessStarted?: (snapshot: ProcessOwnershipSnapshot) => void;
  onProcessOwnershipChanged?: (snapshot: ProcessOwnershipSnapshot) => void;
}

export interface OwnerTerminalExecutor {
  readonly available: boolean;
  run(request: OwnerTerminalRequest, control: OwnerTerminalControl): Promise<ProcessExecutionResult>;
  close(): Promise<void>;
}

export function parseOwnerTerminalRequest(value: unknown): OwnerTerminalRequest {
  if (!isPlainDataRecord(value) || Object.keys(value).some(key => !["command", "cwd", "idempotency_key", "timeout_ms"].includes(key)) ||
      typeof value.command !== "string" || value.command.trim().length === 0 || value.command.includes("\0") ||
      Buffer.byteLength(value.command, "utf8") > 32_768 || typeof value.cwd !== "string" ||
      value.cwd.length > 4096 || !isAbsolute(value.cwd) || value.cwd.includes("\0") ||
      typeof value.idempotency_key !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(value.idempotency_key) ||
      (value.timeout_ms !== undefined && (!Number.isSafeInteger(value.timeout_ms) ||
        (value.timeout_ms as number) < 100 || (value.timeout_ms as number) > 120_000))) {
    throw new BrokerError("PRECONDITION_FAILED", "Terminal command, absolute cwd, idempotency key or timeout is invalid");
  }
  assertContentDoesNotContainSecrets(Buffer.from(value.command, "utf8"));
  return { command: value.command, cwd: value.cwd, idempotencyKey: value.idempotency_key,
    timeoutMs: (value.timeout_ms as number | undefined) ?? 30_000 };
}

/** Explicit personal owner authority, not an isolation implementation. */
export class PersonalOwnerTerminalExecutor implements OwnerTerminalExecutor {
  readonly available: boolean;
  private readonly supervisor: ProcessSupervisor;

  constructor(options: { enabled?: boolean } = {}) {
    this.available = options.enabled === true && process.platform === "darwin" && process.getuid?.() !== 0;
    this.supervisor = new ProcessSupervisor({ requireRootOwnedExecutable: true,
      requireSystemPublishedExecutable: true, maxConcurrent: 2, maxConcurrentPerExecutable: 2,
      allowedEnvironmentKeys: ["HOME", "LANG", "LC_ALL", "TERM"] });
  }

  close(): Promise<void> { return this.supervisor.close(); }

  async run(request: OwnerTerminalRequest, control: OwnerTerminalControl): Promise<ProcessExecutionResult> {
    if (!this.available) throw new BrokerError("POLICY_DENIED", "Personal owner terminal mode is not enabled");
    const cwd = await realpath(request.cwd).catch(() => { throw new BrokerError("TARGET_NOT_FOUND", "Terminal cwd does not exist"); });
    if (!(await lstat(cwd)).isDirectory()) throw new BrokerError("PRECONDITION_FAILED", "Terminal cwd must be a directory");
    if (control.shouldCancel()) throw new BrokerError("CANCELLED", "Terminal authority was revoked before execution");
    return this.supervisor.run({ executable: "/bin/zsh", args: ["-f", "-s"], cwd: await realpath(homedir()),
      stdin: `export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin TMPDIR=/tmp\ncd -- ${shellQuote(cwd)} || exit 125\n${request.command}\n`, timeoutMs: Math.min(request.timeoutMs, control.timeoutMs), outputCapBytes: 131_072,
      environment: { HOME: homedir(), LANG: "en_US.UTF-8", LC_ALL: "en_US.UTF-8", TERM: "dumb" },
      shouldCancel: control.shouldCancel,
      ...(control.onProcessStarted ? { onStarted: control.onProcessStarted } : {}),
      ...(control.onProcessOwnershipChanged ? { onOwnershipChanged: control.onProcessOwnershipChanged } : {}) });
  }
}

function shellQuote(value: string): string { return "'" + value.replaceAll("'", "'\"'\"'") + "'"; }
