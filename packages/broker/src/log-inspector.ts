import { BrokerError } from "@mac-operator/contracts";
import { ProcessSupervisor, type ProcessExecutionResult } from "./process-supervisor.js";
import { redactLogText } from "./secret-policy.js";

const LOG_EXECUTABLE = "/usr/bin/log";
const LOG_CWD = "/";
const MAX_LINES = 2_000;
const MAX_SINCE_SECONDS = 31_536_000;
const MAX_EFFECTIVE_SINCE_SECONDS = 86_400;
const MAX_OUTPUT_BYTES = 512 * 1024;
const SOURCE_PATTERN = /^system$|^process\/[A-Za-z0-9._+-]{1,120}$/u;

export interface SafeLogEntry {
  timestamp: string | null;
  level?: string;
  message: string;
}

export interface SafeLogTail {
  source: string;
  entries: readonly SafeLogEntry[];
  truncated: boolean;
  warnings: readonly string[];
}

export interface LogExecutionControl {
  timeoutMs: number;
  shouldCancel: () => boolean;
}

export interface LogInspector {
  tail(source: string, lines: number, sinceSeconds: number, control: LogExecutionControl): Promise<SafeLogTail>;
}

export class MacLogInspector implements LogInspector {
  private readonly supervisor: ProcessSupervisor;

  constructor(supervisor = new ProcessSupervisor({ maxConcurrent: 2, allowedEnvironmentKeys: [] })) {
    this.supervisor = supervisor;
  }

  async tail(source: string, lines: number, sinceSeconds: number, control: LogExecutionControl): Promise<SafeLogTail> {
    validateLogRequest(source, lines, sinceSeconds);
    const effectiveSince = Math.max(1, Math.min(sinceSeconds, MAX_EFFECTIVE_SINCE_SECONDS));
    const args = ["show", "--last", `${effectiveSince}s`, "--style", "ndjson", "--no-pager"];
    if (source.startsWith("process/")) args.push("--process", source.slice("process/".length));
    const result = await this.supervisor.run({
      executable: LOG_EXECUTABLE,
      args,
      cwd: LOG_CWD,
      environment: {},
      timeoutMs: Math.min(control.timeoutMs, 10_000),
      outputCapBytes: MAX_OUTPUT_BYTES,
      shouldCancel: control.shouldCancel
    });
    return parseLogResult(source, lines, sinceSeconds, effectiveSince, result);
  }
}

export function validateLogRequest(source: string, lines: number, sinceSeconds: number): void {
  if (typeof source !== "string" || source.length < 1 || source.length > 128 || !SOURCE_PATTERN.test(source) ||
      source.includes("..") || source.includes("\\") ||
      !Number.isSafeInteger(lines) || lines < 1 || lines > MAX_LINES ||
      !Number.isSafeInteger(sinceSeconds) || sinceSeconds < 0 || sinceSeconds > MAX_SINCE_SECONDS) {
    throw new BrokerError("PRECONDITION_FAILED", "Log tail arguments are outside the supported range");
  }
}

function parseLogResult(
  source: string,
  lines: number,
  requestedSinceSeconds: number,
  effectiveSinceSeconds: number,
  result: ProcessExecutionResult
): SafeLogTail {
  if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", "Log inspection was cancelled");
  if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", "Log inspection timed out");
  if (result.resultClass === "OUTPUT_LIMIT") throw new BrokerError("OUTPUT_LIMIT", "Log inspection exceeded its output limit");
  if (result.resultClass !== "SUCCEEDED") throw new BrokerError("EXECUTION_FAILED", "Log inspection failed");

  const entries: SafeLogEntry[] = [];
  const warnings: string[] = [];
  let malformedLines = 0;
  for (const line of result.stdout.split("\n")) {
    if (line.trim().length === 0) continue;
    let parsed: unknown;
    try { parsed = JSON.parse(line) as unknown; } catch {
      malformedLines += 1;
      continue;
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      malformedLines += 1;
      continue;
    }
    const record = parsed as Record<string, unknown>;
    const rawMessage = typeof record.eventMessage === "string"
      ? record.eventMessage
      : typeof record.message === "string" ? record.message : "";
    if (rawMessage.length === 0) continue;
    const redacted = redactLogText(rawMessage);
    const timestamp = parseTimestamp(record.timestamp);
    const level = typeof record.messageType === "string" && record.messageType.length <= 64
      ? record.messageType
      : undefined;
    entries.push({ timestamp, ...(level ? { level } : {}), message: redacted.text });
  }
  const selected = entries.slice(Math.max(0, entries.length - lines));
  if (malformedLines > 0) warnings.push("Some log records were malformed and were omitted");
  if (result.truncated) warnings.push("Log output was truncated by a fixed adapter budget");
  if (entries.length > lines) warnings.push("Log entries were limited to the requested line budget");
  if (requestedSinceSeconds > effectiveSinceSeconds) warnings.push("The requested log window was capped at 24 hours");
  if (entries.some((entry) => entry.message.includes("[REDACTED]"))) warnings.push("Sensitive log content was redacted");
  return {
    source,
    entries: selected,
    truncated: result.truncated || malformedLines > 0 || entries.length > lines,
    warnings: warnings.slice(0, 32)
  };
}

function parseTimestamp(value: unknown): string | null {
  if (typeof value !== "string" || value.length < 1 || value.length > 64) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : new Date(parsed).toISOString();
}
