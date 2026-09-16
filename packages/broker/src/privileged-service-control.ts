import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import {
  AllowlistedPrivilegedHelper,
  type PrivilegedHelperExecutionControl,
  type PrivilegedHelperExecutionResult,
  type PrivilegedHelperAdapter,
  type UnsignedPrivilegedHelperCommand
} from "./privileged-helper.js";
import { inspectProcessDescriptorExecutionCapability } from "./process-launch-capability.js";
import { ProcessSupervisor, type ProcessExecutionRequest, type ProcessExecutionResult } from "./process-supervisor.js";
import { LaunchdServiceInspector, validateServiceId, type SafeServiceStatus, type ServiceInspector } from "./service-inspector.js";
import type { PrivilegedHelperPayload } from "./persistence.js";

const LAUNCHCTL_PATH = "/bin/launchctl";
const LAUNCHCTL_CWD = "/";
const COMMAND_TIMEOUT_MS = 5_000;
const COMMAND_OUTPUT_CAP_BYTES = 128 * 1024;
const MAX_OPERATION_TIMEOUT_MS = 30_000;
const SUPPORTED_ACTIONS = new Set(["start", "stop", "restart"]);

export interface PrivilegedServiceControlCommandRunner {
  run(request: ProcessExecutionRequest): Promise<ProcessExecutionResult>;
}

export interface PrivilegedServiceControlAdapterOptions {
  /** Explicit host enablement. Omitted means disabled. */
  enabled?: boolean;
  /** Host-only command runner seam; production uses the descriptor-gated supervisor. */
  commandRunner?: PrivilegedServiceControlCommandRunner;
  /** Host-only status seam; production uses bounded launchd readback. */
  inspector?: ServiceInspector;
  now?: () => number;
}

/**
 * Fixed-argv service control for the separately authenticated root helper.
 * The adapter accepts only the already-bound service-control payload and never
 * exposes a shell, executable path, environment, or arbitrary argument list.
 * It is disabled unless the host has descriptor execution evidence (or a
 * deliberate test command runner is supplied).
 */
export class PrivilegedServiceControlAdapter implements PrivilegedHelperAdapter {
  readonly available: boolean;
  readonly enabledCapabilities: readonly string[];
  private readonly commandRunner: PrivilegedServiceControlCommandRunner;
  private readonly inspector: ServiceInspector;
  private readonly now: () => number;

  constructor(options: PrivilegedServiceControlAdapterOptions = {}) {
    const enabled = options.enabled ?? false;
    if (typeof enabled !== "boolean") throw new Error("Privileged service-control enablement is invalid");
    if (options.commandRunner !== undefined && typeof options.commandRunner.run !== "function") {
      throw new Error("Privileged service-control command runner is invalid");
    }
    if (options.inspector !== undefined && typeof options.inspector.inspect !== "function") {
      throw new Error("Privileged service-control inspector is invalid");
    }
    if (options.commandRunner !== undefined && options.inspector === undefined) {
      throw new Error("Privileged service-control test runner requires an injected inspector");
    }
    this.now = options.now ?? Date.now;
    if (typeof this.now !== "function") throw new Error("Privileged service-control clock is invalid");
    const supervisor = options.commandRunner === undefined
      ? new ProcessSupervisor({
        maxConcurrent: 1,
        maxConcurrentPerExecutable: 1,
        allowedEnvironmentKeys: [],
        requireRootOwnedExecutable: true,
        requireDescriptorExecution: true
      })
      : undefined;
    this.commandRunner = options.commandRunner ?? supervisor!;
    this.inspector = options.inspector ?? new LaunchdServiceInspector(supervisor);
    const hostReady = options.commandRunner !== undefined ||
      (isRootProcess() && inspectProcessDescriptorExecutionCapability().available);
    this.available = enabled && hostReady;
    this.enabledCapabilities = this.available ? ["mac_priv_service_control"] : [];
  }

  async execute(command: UnsignedPrivilegedHelperCommand, control: PrivilegedHelperExecutionControl): Promise<PrivilegedHelperExecutionResult> {
    const payload = servicePayload(command);
    const timeoutMs = boundedTimeout(control);
    const startedAtMs = this.now();
    if (!Number.isSafeInteger(startedAtMs) || startedAtMs < 0) {
      throw new BrokerError("PRECONDITION_FAILED", "Privileged service-control clock is invalid");
    }
    const deadlineMs = startedAtMs + timeoutMs;
    const boundedControl: PrivilegedHelperExecutionControl = {
      timeoutMs,
      shouldCancel: () => control.shouldCancel() || this.now() >= deadlineMs
    };
    checkControl(control, deadlineMs, this.now);

    const action = supportedAction(payload.action);
    const expectedState = expectedServiceState(action, payload.expected_state);
    const preState = await this.inspect(payload.service_id, boundedControl, deadlineMs);
    checkControl(control, deadlineMs, this.now);

    const alreadyInState = action !== "restart" && preState.state === expectedState;
    if (!alreadyInState) {
      let result: ProcessExecutionResult;
      try {
        result = await this.commandRunner.run({
          executable: LAUNCHCTL_PATH,
          args: fixedActionArgs(action, payload.service_id),
          cwd: LAUNCHCTL_CWD,
          environment: {},
          timeoutMs: Math.min(remaining(deadlineMs, this.now), COMMAND_TIMEOUT_MS),
          outputCapBytes: COMMAND_OUTPUT_CAP_BYTES,
          shouldCancel: boundedControl.shouldCancel
        });
      } catch (error) {
        if (error instanceof BrokerError) throw error;
        throw new BrokerError("EXECUTION_FAILED", "Privileged service-control command could not be started");
      }
      mapCommandResult(result);
      checkControl(control, deadlineMs, this.now);
    }

    let postState: SafeServiceStatus;
    try {
      postState = await this.inspect(payload.service_id, boundedControl, deadlineMs);
    } catch {
      return unknownOutcome(payload, preState, "Post-action launchd readback was unavailable");
    }
    const readbackHash = sha256(canonicalJson({
      serviceId: postState.serviceId,
      state: postState.state,
      loaded: postState.loaded,
      running: postState.running,
      pid: postState.pid,
      lastExitCode: postState.lastExitCode
    }));
    const warnings = [...preState.warnings, ...postState.warnings];
    if (postState.state !== expectedState) {
      return {
        operation: "service_control",
        targetRef: command.targetRef,
        state: "failed",
        resultClass: "VERIFICATION_FAILED",
        evidence: { pre_state: preState.state, post_state: postState.state, idempotent: alreadyInState },
        warnings,
        truncated: preState.truncated || postState.truncated,
        verification: {
          status: "failed",
          strategy: "allowlisted_postcondition",
          summary: "Launchd service state did not match the requested postcondition",
          readbackHash
        }
      };
    }
    return {
      operation: "service_control",
      targetRef: command.targetRef,
      state: "completed",
      resultClass: "SUCCEEDED",
      evidence: { pre_state: preState.state, post_state: postState.state, idempotent: alreadyInState },
      warnings,
      truncated: preState.truncated || postState.truncated,
      verification: {
        status: "verified",
        strategy: "allowlisted_postcondition",
        summary: alreadyInState ? "Requested service state was already satisfied" : "Launchd service state readback matched",
        readbackHash
      }
    };
  }

  private async inspect(serviceId: string, control: PrivilegedHelperExecutionControl, deadlineMs: number): Promise<SafeServiceStatus> {
    const remainingMs = remaining(deadlineMs, this.now);
    try {
      return await this.inspector.inspect(serviceId, {
        timeoutMs: Math.min(control.timeoutMs, remainingMs),
        shouldCancel: control.shouldCancel
      });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("EXECUTION_FAILED", "Privileged service-control readback failed");
    }
  }
}

/** Convenience factory that makes the handler map explicit and capability-bound. */
export function createPrivilegedServiceControlHelper(options: PrivilegedServiceControlAdapterOptions = {}): PrivilegedHelperAdapter {
  const adapter = new PrivilegedServiceControlAdapter(options);
  return new AllowlistedPrivilegedHelper({
    ...(adapter.available ? { service_control: (command, control) => adapter.execute(command, control) } : {})
  });
}

function servicePayload(command: UnsignedPrivilegedHelperCommand): Extract<PrivilegedHelperPayload, { operation: "service_control" }> {
  if (command.operation !== "service_control" || command.payload.operation !== "service_control") {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged service-control command payload is invalid");
  }
  validateServiceId(command.payload.service_id);
  supportedAction(command.payload.action);
  return command.payload;
}

function supportedAction(action: Extract<PrivilegedHelperPayload, { operation: "service_control" }>["action"]): "start" | "stop" | "restart" {
  if (!SUPPORTED_ACTIONS.has(action)) {
    throw new BrokerError("UNSUPPORTED_CAPABILITY", "Privileged service action is not enabled by this helper");
  }
  return action as "start" | "stop" | "restart";
}

function expectedServiceState(action: Extract<PrivilegedHelperPayload, { operation: "service_control" }>["action"], expected?: string): "running" | "stopped" {
  const derived = action === "stop" ? "stopped" : "running";
  if (expected !== undefined && expected !== derived) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged service expected_state does not match the action");
  }
  return derived;
}

function fixedActionArgs(action: "start" | "stop" | "restart", serviceId: string): readonly string[] {
  if (action === "start") return ["kickstart", serviceId];
  if (action === "stop") return ["kill", "SIGTERM", serviceId];
  return ["kickstart", "-k", serviceId];
}

function boundedTimeout(control: PrivilegedHelperExecutionControl): number {
  if (!control || typeof control.shouldCancel !== "function" || !Number.isSafeInteger(control.timeoutMs) || control.timeoutMs < 1) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged service-control execution budget is invalid");
  }
  return Math.min(control.timeoutMs, MAX_OPERATION_TIMEOUT_MS);
}

function isRootProcess(): boolean {
  try {
    return typeof process.getuid === "function" && process.getuid() === 0;
  } catch {
    return false;
  }
}

function checkControl(control: PrivilegedHelperExecutionControl, deadlineMs: number, now: () => number): void {
  if (control.shouldCancel()) throw new BrokerError("CANCELLED", "Privileged service-control operation was cancelled");
  if (now() >= deadlineMs) throw new BrokerError("TIMEOUT", "Privileged service-control operation timed out");
}

function remaining(deadlineMs: number, now: () => number): number {
  const value = deadlineMs - now();
  if (value <= 0) throw new BrokerError("TIMEOUT", "Privileged service-control operation timed out");
  return value;
}

function mapCommandResult(result: ProcessExecutionResult): void {
  if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", "Privileged service-control command was cancelled");
  if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", "Privileged service-control command timed out");
  if (result.resultClass === "OUTPUT_LIMIT") throw new BrokerError("OUTPUT_LIMIT", "Privileged service-control command exceeded its output limit");
  if (result.resultClass === "UNKNOWN_OUTCOME") throw new BrokerError("UNKNOWN_OUTCOME", "Privileged service-control command outcome is unresolved", true);
  if (result.resultClass !== "SUCCEEDED") {
    if (/Could not find service|No such process|Bad request|service .* not found/iu.test(result.stderr)) {
      throw new BrokerError("TARGET_NOT_FOUND", "The requested launchd service was not found");
    }
    throw new BrokerError("EXECUTION_FAILED", "Privileged service-control command failed");
  }
}

function unknownOutcome(
  payload: Extract<PrivilegedHelperPayload, { operation: "service_control" }>,
  preState: SafeServiceStatus,
  warning: string
): PrivilegedHelperExecutionResult {
  return {
    operation: "service_control",
    targetRef: `service:${payload.service_id}`,
    state: "unknown",
    resultClass: "UNKNOWN_OUTCOME",
    evidence: { pre_state: preState.state, post_state: "unknown", idempotent: false },
    warnings: [warning],
    truncated: preState.truncated,
    verification: { status: "unknown", strategy: "allowlisted_postcondition", summary: "Post-action state could not be established" }
  };
}
