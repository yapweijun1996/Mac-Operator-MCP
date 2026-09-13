import { BrokerError } from "@mac-operator/contracts";
import { ProcessSupervisor, type ProcessExecutionResult } from "./process-supervisor.js";

const LAUNCHCTL = "/bin/launchctl";
const LAUNCHCTL_CWD = "/";
const SERVICE_ID_PATTERN = /^system\/[A-Za-z0-9._:@+-]{1,240}$/u;
const MAX_OUTPUT_BYTES = 128 * 1024;

export interface SafeServiceStatus {
  serviceId: string;
  loaded: boolean;
  running: boolean;
  state: "loaded" | "running" | "stopped" | "failed" | "unknown";
  lastExitCode: number | null;
  pid: number | null;
  warnings: readonly string[];
  truncated: boolean;
}

export interface ServiceExecutionControl {
  timeoutMs: number;
  shouldCancel: () => boolean;
}

export interface ServiceInspector {
  inspect(serviceId: string, control: ServiceExecutionControl): Promise<SafeServiceStatus>;
}

export class LaunchdServiceInspector implements ServiceInspector {
  private readonly supervisor: ProcessSupervisor;

  constructor(supervisor = new ProcessSupervisor({ maxConcurrent: 2, allowedEnvironmentKeys: [] })) {
    this.supervisor = supervisor;
  }

  async inspect(serviceId: string, control: ServiceExecutionControl): Promise<SafeServiceStatus> {
    validateServiceId(serviceId);
    const result = await this.supervisor.run({
      executable: LAUNCHCTL,
      args: ["print", serviceId],
      cwd: LAUNCHCTL_CWD,
      environment: {},
      timeoutMs: Math.min(control.timeoutMs, 5_000),
      outputCapBytes: MAX_OUTPUT_BYTES,
      shouldCancel: control.shouldCancel
    });
    return parseLaunchctlResult(serviceId, result);
  }
}

export function validateServiceId(serviceId: string): void {
  if (typeof serviceId !== "string" || serviceId.length > 256 || !SERVICE_ID_PATTERN.test(serviceId) ||
      serviceId.includes("..") || serviceId.includes("//") || serviceId.includes("\\")) {
    throw new BrokerError("PRECONDITION_FAILED", "service_id must be a system launchd identifier");
  }
}

function parseLaunchctlResult(serviceId: string, result: ProcessExecutionResult): SafeServiceStatus {
  if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", "Service inspection was cancelled");
  if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", "Service inspection timed out");
  if (result.resultClass === "OUTPUT_LIMIT") throw new BrokerError("OUTPUT_LIMIT", "Service inspection exceeded its output limit");
  if (result.resultClass !== "SUCCEEDED") {
    if (/Could not find service|Bad request/u.test(result.stderr)) {
      throw new BrokerError("TARGET_NOT_FOUND", "The requested launchd service was not found");
    }
    throw new BrokerError("EXECUTION_FAILED", "Launchd service inspection failed");
  }
  const stateValue = /(?:^|\n)\s*state\s*=\s*([^\r\n]+)/u.exec(result.stdout)?.[1]?.trim() ?? "";
  const state = normalizeState(stateValue);
  const pidValue = /(?:^|\n)\s*pid\s*=\s*([0-9]+)/u.exec(result.stdout)?.[1];
  const pid = pidValue === undefined ? null : Number(pidValue);
  if (pid !== null && (!Number.isSafeInteger(pid) || pid < 1 || pid > 99_999_999)) {
    throw new BrokerError("EXECUTION_FAILED", "Launchd returned a malformed process identity");
  }
  const lastExitMatch = /(?:^|\n)\s*last exit code\s*=\s*([^\r\n]+)/u.exec(result.stdout)?.[1]?.trim();
  const lastExitCode = parseExitCode(lastExitMatch);
  if (state === "unknown" && stateValue.length > 0) {
    throw new BrokerError("EXECUTION_FAILED", "Launchd returned an unsupported service state");
  }
  const warnings = result.truncated
    ? ["Launchd output was truncated by a fixed adapter budget"]
    : [];
  return {
    serviceId,
    loaded: true,
    running: state === "running",
    state,
    lastExitCode,
    pid,
    warnings,
    truncated: result.truncated
  };
}

function normalizeState(value: string): SafeServiceStatus["state"] {
  switch (value) {
    case "running": return "running";
    case "stopped": return "stopped";
    case "failed": return "failed";
    case "waiting":
    case "launching":
    case "loaded":
    // A freshly bootstrapped macOS job can expose its XPC proxy before the
    // target program is running. Keep the public status conservative.
    case "xpcproxy": return "loaded";
    case "": return "unknown";
    default: return "unknown";
  }
}

function parseExitCode(value: string | undefined): number | null {
  if (value === undefined || value === "(never exited)") return null;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < -2_147_483_648 || parsed > 2_147_483_647) {
    throw new BrokerError("EXECUTION_FAILED", "Launchd returned a malformed exit code");
  }
  return parsed;
}
