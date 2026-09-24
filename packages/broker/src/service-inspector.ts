import { BrokerError } from "@mac-operator/contracts";
import { ProcessSupervisor, type ProcessExecutionResult } from "./process-supervisor.js";
import { LaunchdReadbackError, parseLaunchdJobReadback } from "./launchd-readback.js";

const LAUNCHCTL = "/bin/launchctl";
const LAUNCHCTL_CWD = "/";
// Keep the adapter input bound identical to the strict launchd readback
// parser. A target that the parser cannot represent must be rejected before
// launchctl is invoked, rather than discovered only after execution.
const SERVICE_ID_PATTERN = /^system\/[A-Za-z0-9._:@+-]{1,128}$/u;
const MAX_SERVICE_ID_LENGTH = 135;
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
  inspectEnablement?(serviceId: string, control: ServiceExecutionControl): Promise<"enabled" | "disabled">;
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

  async inspectEnablement(serviceId: string, control: ServiceExecutionControl): Promise<"enabled" | "disabled"> {
    validateServiceId(serviceId);
    const result = await this.supervisor.run({
      executable: LAUNCHCTL,
      args: ["print-disabled", "system"],
      cwd: LAUNCHCTL_CWD,
      environment: {},
      timeoutMs: Math.min(control.timeoutMs, 5_000),
      outputCapBytes: MAX_OUTPUT_BYTES,
      shouldCancel: control.shouldCancel
    });
    if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", "Launchd enablement readback was cancelled");
    if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", "Launchd enablement readback timed out");
    if (result.resultClass === "OUTPUT_LIMIT" || result.truncated) {
      throw new BrokerError("OUTPUT_LIMIT", "Launchd enablement readback exceeded its output limit");
    }
    if (result.resultClass !== "SUCCEEDED") {
      throw new BrokerError("EXECUTION_FAILED", "Launchd enablement readback failed");
    }
    return parseLaunchdEnablementStatus(serviceId, result.stdout);
  }
}

/**
 * Parses only the bounded `launchctl print-disabled system` dictionary shape.
 * An absent override means enabled by default; unknown output fails closed.
 */
export function parseLaunchdEnablementStatus(serviceId: string, output: string): "enabled" | "disabled" {
  validateServiceId(serviceId);
  if (typeof output !== "string" || output.length > MAX_OUTPUT_BYTES) {
    throw new BrokerError("OUTPUT_LIMIT", "Launchd enablement readback is outside its output limit");
  }
  const lines = output.trim().split(/\r?\n/u);
  if (lines.length < 2 || lines[0]?.trim() !== "disabled services = {" || lines.at(-1)?.trim() !== "}") {
    throw new BrokerError("EXECUTION_FAILED", "Launchd enablement readback is malformed");
  }
  const states = new Map<string, "enabled" | "disabled">();
  for (const line of lines.slice(1, -1)) {
    if (line.trim().length === 0) continue;
    const match = /^\s*"([A-Za-z0-9._:@+-]{1,128})"\s*=>\s*(enabled|disabled)\s*$/u.exec(line);
    if (!match) throw new BrokerError("EXECUTION_FAILED", "Launchd enablement readback contains an unsupported entry");
    const label = match[1]!;
    const state = match[2] as "enabled" | "disabled";
    if (states.has(label)) throw new BrokerError("EXECUTION_FAILED", "Launchd enablement readback contains a duplicate service");
    states.set(label, state);
  }
  return states.get(serviceId.slice("system/".length)) ?? "enabled";
}

export function validateServiceId(serviceId: string): void {
  if (typeof serviceId !== "string" || serviceId.length > MAX_SERVICE_ID_LENGTH || !SERVICE_ID_PATTERN.test(serviceId) ||
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
  let readback;
  try {
    readback = parseLaunchdJobReadback(serviceId, result.stdout);
  } catch (error) {
    if (error instanceof LaunchdReadbackError) {
      throw new BrokerError("EXECUTION_FAILED", "Launchd returned a malformed service readback");
    }
    throw error;
  }
  if (readback.type !== "LaunchDaemon") {
    throw new BrokerError("EXECUTION_FAILED", "Launchd service type is not LaunchDaemon");
  }
  const state = normalizeState(readback.state);
  const pid = readback.pid;
  const lastExitCode = readback.lastExitCode;
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

function normalizeState(value: ReturnType<typeof parseLaunchdJobReadback>["state"]): SafeServiceStatus["state"] {
  switch (value) {
    case "running": return "running";
    case "stopped": return "stopped";
    case "failed": return "failed";
    case "waiting":
    case "launching":
    case "loaded":
    // A freshly bootstrapped macOS job can expose its XPC proxy before the
    // target program is running. Keep the public status conservative.
      return "loaded";
    case "unknown": return "unknown";
    default: return "unknown";
  }
}
