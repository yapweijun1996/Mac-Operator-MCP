import { isAbsolute, resolve } from "node:path";
import { ProcessSupervisor, type ProcessExecutionRequest, type ProcessExecutionResult } from "./process-supervisor.js";

const LAUNCHCTL_PATH = "/bin/launchctl";
const LAUNCHCTL_CWD = "/";
const LAUNCHCTL_TIMEOUT_MS = 5_000;
const LAUNCHCTL_OUTPUT_CAP_BYTES = 131_072;
const SERVICE_ID_PATTERN = /^(?:system|gui\/[1-9][0-9]{0,9})\/[A-Za-z0-9._:@+-]{1,128}$/u;

export type LaunchdReadbackErrorCode =
  | "INVALID_SERVICE"
  | "UNAVAILABLE"
  | "EXECUTION_FAILED"
  | "MALFORMED_READBACK";

export class LaunchdReadbackError extends Error {
  readonly code: LaunchdReadbackErrorCode;

  constructor(code: LaunchdReadbackErrorCode, message: string) {
    super(message);
    this.name = "LaunchdReadbackError";
    this.code = code;
  }
}

export interface LaunchdReadbackExecutor {
  run(command: ProcessExecutionRequest): Promise<ProcessExecutionResult>;
}

export interface LaunchdJobReadback {
  serviceId: string;
  domain: "system" | `gui/${number}`;
  label: string;
  state: "running" | "stopped" | "waiting" | "launching" | "loaded" | "failed" | "unknown";
  pid: number | null;
  program: string | null;
  plistPath: string | null;
  type: "LaunchAgent" | "LaunchDaemon" | null;
  lastExitCode: number | null;
  truncated: false;
}

/**
 * Performs a read-only, bounded launchd print and returns only stable service
 * metadata. No shell, environment, plist mutation, or service transition is
 * available through this adapter.
 */
export async function readLaunchdJobReadback(
  serviceId: string,
  options: { executor?: LaunchdReadbackExecutor } = {}
): Promise<LaunchdJobReadback> {
  const parsedId = parseServiceId(serviceId);
  const executor = options.executor ?? new ProcessSupervisor({ allowedEnvironmentKeys: [] });
  let result: ProcessExecutionResult;
  try {
    result = await executor.run({
      executable: LAUNCHCTL_PATH,
      args: ["print", serviceId],
      cwd: LAUNCHCTL_CWD,
      environment: {},
      timeoutMs: LAUNCHCTL_TIMEOUT_MS,
      outputCapBytes: LAUNCHCTL_OUTPUT_CAP_BYTES
    });
  } catch {
    throw new LaunchdReadbackError("EXECUTION_FAILED", "launchd readback execution failed");
  }
  if (result.resultClass === "OUTPUT_LIMIT") {
    throw new LaunchdReadbackError("EXECUTION_FAILED", "launchd readback exceeded its output budget");
  }
  if (result.resultClass !== "SUCCEEDED") {
    if (/Could not find service|No such process|Bad request|service .* not found/iu.test(result.stderr)) {
      throw new LaunchdReadbackError("UNAVAILABLE", "launchd service is unavailable");
    }
    throw new LaunchdReadbackError("EXECUTION_FAILED", "launchd readback failed");
  }
  return parseLaunchdJobReadback(serviceId, result.stdout, parsedId);
}

export function validateLaunchdReadbackServiceId(serviceId: string): void {
  parseServiceId(serviceId);
}

export function parseLaunchdJobReadback(
  serviceId: string,
  output: string,
  expected = parseServiceId(serviceId)
): LaunchdJobReadback {
  if (typeof output !== "string" || Buffer.byteLength(output, "utf8") > LAUNCHCTL_OUTPUT_CAP_BYTES) {
    throw new LaunchdReadbackError("MALFORMED_READBACK", "launchd readback output is outside its bounded format");
  }
  const header = new RegExp(`^${escapeRegExp(serviceId)}\\s*=\\s*\\{`, "mu");
  if (!header.test(output)) {
    throw new LaunchdReadbackError("MALFORMED_READBACK", "launchd readback service identity does not match the request");
  }
  const stateValue = field(output, "state");
  const state = parseState(stateValue);
  const pid = parsePid(field(output, "pid"));
  const program = parseOptionalPath(field(output, "program"), "program");
  const plistPath = parseOptionalPath(field(output, "path"), "path");
  const type = parseType(field(output, "type"));
  const lastExitCode = parseExitCode(field(output, "last exit code"));
  return {
    serviceId,
    domain: expected.domain,
    label: expected.label,
    state,
    pid,
    program,
    plistPath,
    type,
    lastExitCode,
    truncated: false
  };
}

function parseServiceId(serviceId: string): { domain: "system" | `gui/${number}`; label: string } {
  if (typeof serviceId !== "string" || serviceId.length > 256 || !SERVICE_ID_PATTERN.test(serviceId) ||
      serviceId.includes("..") || serviceId.includes("//") || serviceId.includes("\\")) {
    throw new LaunchdReadbackError("INVALID_SERVICE", "launchd service identifier is invalid");
  }
  const separator = serviceId.lastIndexOf("/");
  const domain = serviceId.slice(0, separator);
  const label = serviceId.slice(separator + 1);
  return {
    domain: domain === "system" ? "system" : domain as `gui/${number}`,
    label
  };
}

function field(output: string, name: string): string | undefined {
  return new RegExp(`(?:^|\\n)\\s*${escapeRegExp(name)}\\s*=\\s*([^\\r\\n]+)`, "mu").exec(output)?.[1]?.trim();
}

function parseState(value: string | undefined): LaunchdJobReadback["state"] {
  switch (value) {
    case "running":
    case "stopped":
    case "waiting":
    case "launching":
    case "loaded":
    case "failed": return value;
    case undefined:
    case "": return "unknown";
    default: throw new LaunchdReadbackError("MALFORMED_READBACK", "launchd returned an unsupported service state");
  }
}

function parsePid(value: string | undefined): number | null {
  if (value === undefined) return null;
  const pid = Number(value);
  if (!Number.isSafeInteger(pid) || pid < 1 || pid > 99_999_999) {
    throw new LaunchdReadbackError("MALFORMED_READBACK", "launchd returned a malformed process identity");
  }
  return pid;
}

function parseOptionalPath(value: string | undefined, fieldName: string): string | null {
  if (value === undefined) return null;
  if (!isAbsolute(value) || resolve(value) !== value || value.includes("\0") || value.includes("\n") || value.includes("\r") || value !== value.trim()) {
    throw new LaunchdReadbackError("MALFORMED_READBACK", `launchd returned a malformed ${fieldName} path`);
  }
  return value;
}

function parseType(value: string | undefined): LaunchdJobReadback["type"] {
  if (value === undefined) return null;
  if (value === "LaunchAgent" || value === "LaunchDaemon") return value;
  throw new LaunchdReadbackError("MALFORMED_READBACK", "launchd returned an unsupported service type");
}

function parseExitCode(value: string | undefined): number | null {
  if (value === undefined || value === "(never exited)") return null;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < -2_147_483_648 || parsed > 2_147_483_647) {
    throw new LaunchdReadbackError("MALFORMED_READBACK", "launchd returned a malformed exit code");
  }
  return parsed;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}
