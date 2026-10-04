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
  private readonly supervisor: Pick<ProcessSupervisor, "run">;

  constructor(supervisor: Pick<ProcessSupervisor, "run"> = new ProcessSupervisor({ maxConcurrent: 2, allowedEnvironmentKeys: [] })) {
    this.supervisor = supervisor;
  }

  async tail(source: string, lines: number, sinceSeconds: number, control: LogExecutionControl): Promise<SafeLogTail> {
    validateLogRequest(source, lines, sinceSeconds);
    const effectiveSince = Math.max(1, Math.min(sinceSeconds, MAX_EFFECTIVE_SINCE_SECONDS));
    const args = ["show", "--last", `${effectiveSince}s`, "--style", "compact", "--no-pager"];
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

const MAX_MESSAGE_LENGTH = 8192;

export function validateLogRequest(source: string, lines: number, sinceSeconds: number): void {
  if (typeof source !== "string" || source.length < 1 || source.length > 128 || !SOURCE_PATTERN.test(source) ||
      source.includes("..") || source.includes("\\")) {
    throw new BrokerError("PRECONDITION_FAILED",
      'source must be "system" or "process/<name>" (name: 1-120 characters from A-Z a-z 0-9 . _ + -); mac_capabilities lists authorized_log_sources. A launchd id such as system/<label> is a service id for mac_service_status, not a log source');
  }
  if (!Number.isSafeInteger(lines) || lines < 1 || lines > MAX_LINES) {
    throw new BrokerError("PRECONDITION_FAILED", `lines must be an integer between 1 and ${MAX_LINES}`);
  }
  if (!Number.isSafeInteger(sinceSeconds) || sinceSeconds < 0 || sinceSeconds > MAX_SINCE_SECONDS) {
    throw new BrokerError("PRECONDITION_FAILED", `since_seconds must be an integer between 0 and ${MAX_SINCE_SECONDS}`);
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
  // An output-limited log process has already been terminated by the
  // supervisor and its captured bytes are bounded. Parse that prefix and
  // expose the loss explicitly instead of discarding otherwise safe records.
  if (result.resultClass === "OUTPUT_LIMIT" && !result.terminationObserved) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Log inspection termination could not be verified", true);
  }
  if (result.resultClass === "UNKNOWN_OUTCOME") throw new BrokerError("UNKNOWN_OUTCOME", "Log inspection outcome could not be verified", true);
  if (result.resultClass !== "SUCCEEDED" && result.resultClass !== "OUTPUT_LIMIT") {
    throw new BrokerError("EXECUTION_FAILED", "Log inspection failed");
  }

  const entries: SafeLogEntry[] = [];
  const warnings: string[] = [];
  let malformedLines = 0;
  let partialTailDropped = false;
  const outputLimited = result.resultClass === "OUTPUT_LIMIT";
  const rawLines = result.stdout.split("\n");
  // A budget cut usually ends mid-record; drop that unfinished final line rather than report half a sentence.
  if ((result.truncated || outputLimited) && !result.stdout.endsWith("\n") && rawLines.length > 0) {
    rawLines.pop();
    partialTailDropped = true;
  }
  // `log show` wraps multi-line messages: lines without a timestamp continue the previous record.
  const drafts: Array<{ timestamp: string; level: string; text: string }> = [];
  for (const line of rawLines) {
    if (line.trim().length === 0 || /^Timestamp\s+Ty\s+Process/u.test(line)) continue;
    const match = /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)\s+(\S+)\s+\S+\s+(.*)$/u.exec(line);
    if (match) {
      drafts.push({ timestamp: match[1]!, level: match[2]!, text: match[3]!.replace(/^\[[^\]]{0,256}\]\s+/u, "").trim() });
    } else if (/^\d{4}-\d{2}-\d{2} /u.test(line)) {
      malformedLines += 1;
    } else if (drafts.length > 0) {
      const draft = drafts[drafts.length - 1]!;
      if (draft.text.length < MAX_MESSAGE_LENGTH) draft.text = `${draft.text}\n${line.trim()}`;
    }
  }
  for (const draft of drafts) {
    if (draft.text.length === 0) continue;
    const redacted = redactLogText(draft.text);
    const parsedTimestamp = Date.parse(draft.timestamp);
    entries.push({
      timestamp: Number.isNaN(parsedTimestamp) ? null : new Date(parsedTimestamp).toISOString(),
      level: draft.level.slice(0, 64),
      message: redacted.text.slice(0, MAX_MESSAGE_LENGTH)
    });
  }
  const selected = entries.slice(Math.max(0, entries.length - lines));
  if (malformedLines > 0) warnings.push(`${malformedLines} malformed log record${malformedLines === 1 ? " was" : "s were"} omitted`);
  if (result.truncated || outputLimited) warnings.push("Log output was truncated by a fixed adapter budget");
  if (partialTailDropped) warnings.push("The final partial log record was dropped");
  if (entries.length > lines) warnings.push("Log entries were limited to the requested line budget");
  if (requestedSinceSeconds > effectiveSinceSeconds) warnings.push("The requested log window was capped at 24 hours");
  if (entries.some((entry) => entry.message.includes("[REDACTED]"))) warnings.push("Sensitive log content was redacted");
  return {
    source,
    entries: selected,
    truncated: result.truncated || outputLimited || malformedLines > 0 || entries.length > lines,
    warnings: warnings.slice(0, 32)
  };
}
