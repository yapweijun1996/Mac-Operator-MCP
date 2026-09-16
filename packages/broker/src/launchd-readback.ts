import { isAbsolute, resolve } from "node:path";
import { ProcessSupervisor, type ProcessExecutionRequest, type ProcessExecutionResult } from "./process-supervisor.js";

const LAUNCHCTL_PATH = "/bin/launchctl";
const LAUNCHCTL_CWD = "/";
const LAUNCHCTL_TIMEOUT_MS = 5_000;
const LAUNCHCTL_OUTPUT_CAP_BYTES = 131_072;
const MAX_ARGUMENT_COUNT = 64;
const MAX_ARGUMENT_BYTES = 4_096;
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
  arguments: readonly string[] | null;
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
  const header = new RegExp(`^${escapeRegExp(serviceId)}\\s*=\\s*\\{`, "gmu");
  const headers = [...output.matchAll(header)];
  if (headers.length !== 1) {
    throw new LaunchdReadbackError("MALFORMED_READBACK", "launchd readback service identity does not match the request");
  }
  const stateValue = field(output, "state");
  const state = parseState(stateValue);
  const pid = parsePid(field(output, "pid"));
  const program = parseOptionalPath(field(output, "program"), "program");
  const argumentsValue = parseArguments(output);
  const plistPath = parseOptionalPath(field(output, "path"), "path");
  const type = parseType(field(output, "type"));
  if (type !== null) {
    const expectedType = expected.domain === "system" ? "LaunchDaemon" : "LaunchAgent";
    if (type !== expectedType) {
      throw new LaunchdReadbackError("MALFORMED_READBACK", "launchd service type does not match the requested domain");
    }
  }
  if (program !== null && argumentsValue !== null && argumentsValue[0] !== program) {
    throw new LaunchdReadbackError("MALFORMED_READBACK", "launchd program and first argument do not match");
  }
  const lastExitCode = parseExitCode(field(output, "last exit code"));
  return {
    serviceId,
    domain: expected.domain,
    label: expected.label,
    state,
    pid,
    program,
    arguments: argumentsValue,
    plistPath,
    type,
    lastExitCode,
    truncated: false
  };
}

function parseArguments(output: string): readonly string[] | null {
  const lines = output.split(/\r?\n/u);
  const starts = lines.reduce<number[]>((indices, line, index) => {
    if (/^\targuments\s*=\s*\{\s*$/u.test(line)) indices.push(index);
    return indices;
  }, []);
  if (starts.length > 1) {
    throw new LaunchdReadbackError("MALFORMED_READBACK", "launchd returned duplicate program argument lists");
  }
  const start = starts[0] ?? -1;
  if (start < 0) return null;
  const values: string[] = [];
  let closed = false;
  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index]!;
    if (/^\s*\}\s*$/u.test(line)) {
      closed = true;
      break;
    }
    const value = line.trim();
    if (value.length === 0 || value.includes("\0") || value.includes("{") || value.includes("}") ||
        /[\u0000-\u001F\u007F]/u.test(value) || Buffer.byteLength(value, "utf8") > MAX_ARGUMENT_BYTES) {
      throw new LaunchdReadbackError("MALFORMED_READBACK", "launchd returned a malformed program argument");
    }
    values.push(value);
    if (values.length > MAX_ARGUMENT_COUNT) {
      throw new LaunchdReadbackError("MALFORMED_READBACK", "launchd returned too many program arguments");
    }
  }
  if (!closed || values.length === 0) {
    throw new LaunchdReadbackError("MALFORMED_READBACK", "launchd returned an incomplete program argument list");
  }
  return values;
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
  // launchctl nests additional state dictionaries below the one-tab service
  // fields. Restrict singleton extraction to that exact top-level indent so a
  // nested `state = active` cannot shadow the service's `state = running`.
  const pattern = new RegExp(`(?:^|\\n)\\t${escapeRegExp(name)}\\s*=\\s*([^\\r\\n]+)`, "gmu");
  const matches = [...output.matchAll(pattern)];
  if (matches.length > 1) {
    throw new LaunchdReadbackError("MALFORMED_READBACK", `launchd returned duplicate ${name} fields`);
  }
  return matches[0]?.[1]?.trim();
}

function parseState(value: string | undefined): LaunchdJobReadback["state"] {
  switch (value) {
    case "running":
    case "stopped":
    case "waiting":
    case "launching":
    case "loaded":
    case "failed": return value;
    // macOS reports this transient proxy state immediately after a
    // LaunchAgent bootstrap. It is not proof that the requested program is
    // running, so preserve the strict running check at higher boundaries.
    case "xpcproxy": return "launching";
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
