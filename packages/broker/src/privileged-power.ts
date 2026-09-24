import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import {
  AllowlistedPrivilegedHelper,
  type PrivilegedHelperAdapter,
  type PrivilegedHelperExecutionControl,
  type PrivilegedHelperExecutionResult,
  type PrivilegedHelperJobReadback,
  type UnsignedPrivilegedHelperJobReadbackRequest,
  type UnsignedPrivilegedHelperCommand
} from "./privileged-helper.js";
import { inspectSystemPublishedExecutablePath } from "./system-published-executable.js";
import { ProcessSupervisor, type ProcessExecutionRequest, type ProcessExecutionResult } from "./process-supervisor.js";
import { validatePrivilegedHelperPayload, type PrivilegedHelperPayload } from "./persistence.js";

const SHUTDOWN_PATH = "/sbin/shutdown";
const COMMAND_CWD = "/";
const COMMAND_TIMEOUT_MS = 30_000;
const COMMAND_OUTPUT_CAP_BYTES = 256 * 1024;
const MAX_OPERATION_TIMEOUT_MS = 30_000;
const MAX_SCHEDULE_AHEAD_MS = 7 * 24 * 60 * 60 * 1_000;

export interface PrivilegedPowerCommandRunner {
  run(request: ProcessExecutionRequest): Promise<ProcessExecutionResult>;
}

export interface PrivilegedPowerAdapterOptions {
  /** Explicit host enablement. Omitted means disabled. */
  enabled?: boolean;
  /** Test-only command seam; production uses the fixed system-published tool. */
  commandRunner?: PrivilegedPowerCommandRunner;
  /** Explicit operator acceptance of the fixed root-owned shutdown boundary. */
  systemPublishedExecutablePathAccepted?: boolean;
  now?: () => number;
}

/**
 * Fixed-argv reboot/shutdown handoff. The reason is retained in the
 * Broker-bound payload for audit intent but is deliberately never forwarded as
 * a shutdown warning string. A successful command means only that the host
 * accepted the handoff; it does not claim that the machine already rebooted.
 */
export class PrivilegedPowerAdapter implements PrivilegedHelperAdapter {
  readonly available: boolean;
  readonly enabledCapabilities: readonly string[];
  private readonly commandRunner: PrivilegedPowerCommandRunner;
  private readonly now: () => number;

  constructor(options: PrivilegedPowerAdapterOptions = {}) {
    const enabled = options.enabled ?? false;
    if (typeof enabled !== "boolean") throw new Error("Privileged power enablement is invalid");
    if (options.commandRunner !== undefined && typeof options.commandRunner.run !== "function") {
      throw new Error("Privileged power command runner is invalid");
    }
    if (options.systemPublishedExecutablePathAccepted !== undefined && typeof options.systemPublishedExecutablePathAccepted !== "boolean") {
      throw new Error("Privileged power system-published executable acceptance is invalid");
    }
    this.now = options.now ?? Date.now;
    if (typeof this.now !== "function") throw new Error("Privileged power clock is invalid");
    const supervisor = options.commandRunner === undefined
      ? new ProcessSupervisor({
        maxConcurrent: 1,
        maxConcurrentPerExecutable: 1,
        allowedEnvironmentKeys: [],
        requireRootOwnedExecutable: true,
        requireSystemPublishedExecutable: true
      })
      : undefined;
    this.commandRunner = options.commandRunner ?? supervisor!;
    const hostReady = options.commandRunner !== undefined ||
      (isRootProcess() && options.systemPublishedExecutablePathAccepted === true && inspectSystemPublishedExecutablePath(SHUTDOWN_PATH));
    this.available = enabled && hostReady;
    this.enabledCapabilities = this.available ? ["mac_priv_power"] : [];
  }

  async execute(command: UnsignedPrivilegedHelperCommand, control: PrivilegedHelperExecutionControl): Promise<PrivilegedHelperExecutionResult> {
    const payload = powerPayload(command);
    const timeoutMs = boundedTimeout(control);
    const startedAtMs = this.now();
    if (!Number.isSafeInteger(startedAtMs) || startedAtMs < 0) {
      throw new BrokerError("PRECONDITION_FAILED", "Privileged power clock is invalid");
    }
    const deadlineMs = startedAtMs + timeoutMs;
    const boundedControl: PrivilegedHelperExecutionControl = {
      timeoutMs,
      shouldCancel: () => control.shouldCancel() || this.now() >= deadlineMs
    };
    checkControl(control, deadlineMs, this.now);

    const schedule = resolveSchedule(payload.not_before, startedAtMs);
    const args = fixedPowerArgs(payload.action, schedule, startedAtMs);
    let result: ProcessExecutionResult;
    try {
      result = await this.commandRunner.run({
        executable: SHUTDOWN_PATH,
        args,
        cwd: COMMAND_CWD,
        environment: {},
        timeoutMs: Math.min(remaining(deadlineMs, this.now), COMMAND_TIMEOUT_MS),
        outputCapBytes: COMMAND_OUTPUT_CAP_BYTES,
        shouldCancel: boundedControl.shouldCancel
      });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("EXECUTION_FAILED", "Privileged power handoff could not be started");
    }
    if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", "Privileged power handoff was cancelled");
    if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", "Privileged power handoff timed out");
    if (result.resultClass === "OUTPUT_LIMIT") throw new BrokerError("OUTPUT_LIMIT", "Privileged power handoff exceeded its output limit");
    if (result.resultClass === "UNKNOWN_OUTCOME") {
      return unresolvedPower(command, schedule, "Privileged power handoff outcome is unresolved");
    }
    if (result.resultClass !== "SUCCEEDED") throw new BrokerError("EXECUTION_FAILED", "Privileged power handoff failed");
    checkControl(control, deadlineMs, this.now);

    const state = schedule === undefined ? "accepted" : "scheduled";
    const handoffId = `power:${sha256(canonicalJson({ commandId: command.commandId, action: payload.action, schedule: schedule ?? null })).slice(0, 48)}`;
    const readbackHash = sha256(canonicalJson({ action: payload.action, state, scheduledFor: schedule ?? null, handoffId }));
    return {
      operation: "power",
      targetRef: command.targetRef,
      state: "completed",
      resultClass: "SUCCEEDED",
      evidence: {
        state,
        scheduled_for: schedule ?? null,
        handoff_id: handoffId,
        connection_loss_expected: true
      },
      warnings: [],
      truncated: result.truncated,
      verification: {
        status: "verified",
        strategy: "allowlisted_postcondition",
        summary: schedule === undefined ? "Fixed shutdown command accepted the power handoff" : "Fixed shutdown command accepted the scheduled power handoff",
        readbackHash
      }
    };
  }

  async readback(request: UnsignedPrivilegedHelperJobReadbackRequest, control: PrivilegedHelperExecutionControl): Promise<PrivilegedHelperJobReadback> {
    const payload = powerPayload(request);
    if (control.shouldCancel()) throw new BrokerError("CANCELLED", "Privileged power readback was cancelled");
    return {
      operation: "power",
      targetRef: request.targetRef,
      postcondition: "unavailable",
      evidence: { state: "unavailable", action: payload.action, connection_loss_expected: true },
      warnings: ["Power handoff postcondition cannot be established after an unresolved outcome"],
      summary: "Power handoff postcondition cannot be established after an unresolved outcome"
    };
  }
}

/** Convenience factory that exposes only the power operation when available. */
export function createPrivilegedPowerHelper(options: PrivilegedPowerAdapterOptions = {}): PrivilegedHelperAdapter {
  const adapter = new PrivilegedPowerAdapter(options);
  return new AllowlistedPrivilegedHelper({
    ...(adapter.available ? {
      power: (command, control) => adapter.execute(command, control),
      power_readback: (request, control) => adapter.readback(request, control)
    } : {})
  });
}

function powerPayload(command: Pick<UnsignedPrivilegedHelperCommand | UnsignedPrivilegedHelperJobReadbackRequest, "operation" | "payload" | "targetRef">): Extract<PrivilegedHelperPayload, { operation: "power" }> {
  if (command.operation !== "power" || command.payload.operation !== "power") {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged power command payload is invalid");
  }
  try { validatePrivilegedHelperPayload(command.payload); }
  catch { throw new BrokerError("PRECONDITION_FAILED", "Privileged power command payload is invalid"); }
  if (command.targetRef !== "host:local") {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged power command target is invalid");
  }
  return command.payload;
}

function resolveSchedule(notBefore: string | undefined, nowMs: number): string | undefined {
  if (notBefore === undefined) return undefined;
  const requestedMs = Date.parse(notBefore);
  if (!Number.isFinite(requestedMs) || requestedMs <= nowMs) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged power not_before must be in the future");
  }
  const deltaMs = requestedMs - nowMs;
  if (deltaMs > MAX_SCHEDULE_AHEAD_MS) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged power schedule exceeds its bounded horizon");
  }
  const minutes = Math.max(1, Math.ceil(deltaMs / 60_000));
  return new Date(nowMs + minutes * 60_000).toISOString();
}

function fixedPowerArgs(action: "reboot" | "shutdown", scheduledFor: string | undefined, nowMs: number): readonly string[] {
  const mode = action === "reboot" ? "-r" : "-h";
  if (scheduledFor === undefined) return [mode, "now"];
  const scheduledMs = Date.parse(scheduledFor);
  const minutes = Math.max(1, Math.round((scheduledMs - nowMs) / 60_000));
  return [mode, `+${minutes}`];
}

function unresolvedPower(
  command: UnsignedPrivilegedHelperCommand,
  scheduledFor: string | undefined,
  summary: string
): PrivilegedHelperExecutionResult {
  return {
    operation: "power",
    targetRef: command.targetRef,
    state: "unknown",
    resultClass: "UNKNOWN_OUTCOME",
    evidence: {
      state: "unknown",
      scheduled_for: scheduledFor ?? null,
      handoff_id: `power:${sha256(command.commandId).slice(0, 48)}`,
      connection_loss_expected: true
    },
    warnings: [summary],
    truncated: false,
    verification: { status: "unknown", strategy: "allowlisted_postcondition", summary }
  };
}

function boundedTimeout(control: PrivilegedHelperExecutionControl): number {
  if (!control || typeof control.shouldCancel !== "function" || !Number.isSafeInteger(control.timeoutMs) || control.timeoutMs < 1) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged power execution budget is invalid");
  }
  return Math.min(control.timeoutMs, MAX_OPERATION_TIMEOUT_MS);
}

function checkControl(control: PrivilegedHelperExecutionControl, deadlineMs: number, now: () => number): void {
  if (control.shouldCancel()) throw new BrokerError("CANCELLED", "Privileged power operation was cancelled");
  if (now() >= deadlineMs) throw new BrokerError("TIMEOUT", "Privileged power operation timed out");
}

function remaining(deadlineMs: number, now: () => number): number {
  const value = deadlineMs - now();
  if (value <= 0) throw new BrokerError("TIMEOUT", "Privileged power operation timed out");
  return value;
}

function isRootProcess(): boolean {
  try { return typeof process.getuid === "function" && process.getuid() === 0; }
  catch { return false; }
}
