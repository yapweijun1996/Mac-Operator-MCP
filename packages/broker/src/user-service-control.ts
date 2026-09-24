import { BrokerError } from "@mac-operator/contracts";
import { isAbsolute, resolve } from "node:path";
import { inspectProcessDescriptorExecutionCapability } from "./process-launch-capability.js";
import { inspectSystemPublishedExecutablePath } from "./system-published-executable.js";
import { parseLaunchdJobReadback, readLaunchdJobReadback, type LaunchdJobReadback } from "./launchd-readback.js";
import {
  ProcessSupervisor,
  type DescriptorProcessSpawnAdapter,
  type ProcessExecutionRequest,
  type ProcessExecutionResult
} from "./process-supervisor.js";

const LAUNCHCTL_PATH = "/bin/launchctl";
const LAUNCHCTL_CWD = "/";
const COMMAND_TIMEOUT_MS = 5_000;
const COMMAND_OUTPUT_CAP_BYTES = 128 * 1024;
const MAX_OPERATION_TIMEOUT_MS = 30_000;
const POSTCONDITION_SETTLE_ATTEMPTS = 8;
const POSTCONDITION_SETTLE_DELAY_MS = 50;
const USER_SERVICE_ID_PATTERN = /^gui\/[1-9][0-9]{0,9}\/com\.mac-operator\.[A-Za-z0-9_:@+-]{1,96}$/u;
const SOURCE_REVISION_PATTERN = /^[0-9a-f]{7,64}$/u;

export type UserServiceControlAction = "start" | "stop" | "restart";
export type UserServiceControlState = "running" | "stopped";
export type UserServiceRollbackStatus = "not_needed" | "verified" | "failed" | "unknown";

export interface UserServiceBinding {
  serviceId: string;
  sourceRevision: string;
  plistPath: string;
  program: string;
  arguments: readonly string[];
}

export interface UserServiceControlRequest {
  serviceId: string;
  action: UserServiceControlAction;
  expectedState?: UserServiceControlState;
}

export interface UserServiceExecutionControl {
  timeoutMs: number;
  shouldCancel: () => boolean;
}

export interface UserServiceReadback {
  launchd: LaunchdJobReadback;
  sourceRevision: string;
}

export interface UserServiceControlPrecondition {
  state: UserServiceControlState;
  sourceRevision: string;
}

export interface UserServiceReadbackObserver {
  inspect(serviceId: string, control: UserServiceExecutionControl): Promise<UserServiceReadback>;
}

export interface UserServiceSourceRevisionReader {
  read(serviceId: string, control: UserServiceExecutionControl): Promise<string>;
}

export interface UserServiceControlCommandRunner {
  run(request: ProcessExecutionRequest): Promise<ProcessExecutionResult>;
}

export interface UserServiceControlAdapterOptions {
  /** Explicit host enablement. Omitted means disabled. */
  enabled?: boolean;
  /** The owner uid that the policy-bound service identities must use. */
  uid?: number;
  /** Policy-owned user-domain LaunchAgent bindings. */
  bindings?: readonly UserServiceBinding[];
  /** Host-only seams. Production wiring must provide real readback and evidence. */
  commandRunner?: UserServiceControlCommandRunner;
  /** Optional native descriptor launcher; the fixed path boundary is the default native route. */
  descriptorSpawnAdapter?: DescriptorProcessSpawnAdapter;
  /** Explicit operator acceptance of the fixed system-published launchctl boundary. */
  systemPublishedExecutablePathAccepted?: boolean;
  inspector?: UserServiceReadbackObserver;
  sourceRevisionReader?: UserServiceSourceRevisionReader;
  now?: () => number;
}

export interface UserServiceControlResult {
  operation: "service_control";
  serviceId: string;
  action: UserServiceControlAction;
  state: "completed" | "failed" | "unknown";
  resultClass: "SUCCEEDED" | "VERIFICATION_FAILED" | "UNKNOWN_OUTCOME";
  preState: UserServiceControlState;
  postState: UserServiceControlState | "unknown";
  sourceRevision: string;
  idempotent: boolean;
  rollback: {
    status: UserServiceRollbackStatus;
    state: UserServiceControlState | "unknown";
  };
  verification: {
    status: "verified" | "failed" | "unknown";
    summary: string;
  };
}

export function validateUserServiceControlResult(value: unknown): asserts value is UserServiceControlResult {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("EXECUTION_FAILED", "User service-control result is malformed");
  }
  const result = value as Record<string, unknown>;
  if (result.operation !== "service_control" || typeof result.serviceId !== "string" ||
      !/^gui\/[1-9][0-9]{0,9}\/com\.mac-operator\.[A-Za-z0-9_:@+-]{1,96}$/u.test(result.serviceId) ||
      !["start", "stop", "restart"].includes(result.action as string) ||
      !["completed", "failed", "unknown"].includes(result.state as string) ||
      !["SUCCEEDED", "VERIFICATION_FAILED", "UNKNOWN_OUTCOME"].includes(result.resultClass as string) ||
      !["running", "stopped"].includes(result.preState as string) ||
      !["running", "stopped", "unknown"].includes(result.postState as string) ||
      typeof result.sourceRevision !== "string" || !/^[0-9a-f]{7,64}$/u.test(result.sourceRevision) ||
      typeof result.idempotent !== "boolean" || result.rollback === null || typeof result.rollback !== "object" ||
      result.verification === null || typeof result.verification !== "object") {
    throw new BrokerError("EXECUTION_FAILED", "User service-control result is malformed");
  }
  const rollback = result.rollback as Record<string, unknown>;
  const verification = result.verification as Record<string, unknown>;
  if (!["not_needed", "verified", "failed", "unknown"].includes(rollback.status as string) ||
      !["running", "stopped", "unknown"].includes(rollback.state as string) ||
      !["verified", "failed", "unknown"].includes(verification.status as string) ||
      typeof verification.summary !== "string" || verification.summary.length > 2048) {
    throw new BrokerError("EXECUTION_FAILED", "User service-control result is malformed");
  }
}

/**
 * Production host observer seam. Launchd identity is parsed by the shared
 * bounded readback parser; source revision is supplied by a separate
 * Broker-owned metadata channel and is never inferred from launchctl output.
 */
export class LaunchdUserServiceReadbackObserver implements UserServiceReadbackObserver {
  constructor(
    private readonly commandRunner: UserServiceControlCommandRunner,
    private readonly sourceRevisionReader: UserServiceSourceRevisionReader
  ) {}

  async inspect(serviceId: string, control: UserServiceExecutionControl): Promise<UserServiceReadback> {
    const launchd = await readLaunchdJobReadback(serviceId, {
      executor: this.commandRunner,
      control
    });
    const sourceRevision = await this.sourceRevisionReader.read(serviceId, control);
    return { launchd, sourceRevision };
  }
}

/**
 * Bounded owner-only LaunchAgent lifecycle adapter for MOP-104.
 *
 * The standard Broker path may use this adapter only when its runtime,
 * policy, approval, and host-evidence gates are explicitly supplied. The
 * default policy and public OAuth profile keep the capability disabled. The
 * request selects only a previously bound service identity and action;
 * launchctl, environment, working directory, and arguments remain
 * adapter-owned.
 */
export class UserServiceControlAdapter {
  readonly available: boolean;
  readonly enabledCapabilities: readonly string[];

  private readonly uid: number;
  private readonly bindings: ReadonlyMap<string, UserServiceBinding>;
  private readonly commandRunner: UserServiceControlCommandRunner;
  private readonly inspector: UserServiceReadbackObserver;
  private readonly now: () => number;

  constructor(options: UserServiceControlAdapterOptions = {}) {
    const enabled = options.enabled ?? false;
    if (typeof enabled !== "boolean") throw new Error("User service-control enablement is invalid");
    this.uid = options.uid ?? readCurrentUid();
    if (!Number.isSafeInteger(this.uid) || this.uid < 1 || this.uid > 2_147_483_647) {
      throw new Error("User service-control uid is invalid");
    }
    const bindings = options.bindings ?? [];
    if (!Array.isArray(bindings) || bindings.length > 32) throw new Error("User service-control bindings are invalid");
    const map = new Map<string, UserServiceBinding>();
    for (const binding of bindings) {
      validateBinding(binding, this.uid);
      if (map.has(binding.serviceId)) throw new Error("User service-control bindings contain a duplicate service");
      map.set(binding.serviceId, freezeBinding(binding));
    }
    this.bindings = map;
    if (options.commandRunner !== undefined && typeof options.commandRunner.run !== "function") {
      throw new Error("User service-control command runner is invalid");
    }
    if (options.commandRunner !== undefined && options.descriptorSpawnAdapter !== undefined) {
      throw new Error("User service-control command runner and descriptor launcher are mutually exclusive");
    }
    if (options.systemPublishedExecutablePathAccepted !== undefined && typeof options.systemPublishedExecutablePathAccepted !== "boolean") {
      throw new Error("User service-control system-published executable acceptance is invalid");
    }
    if (options.inspector !== undefined && typeof options.inspector.inspect !== "function") {
      throw new Error("User service-control inspector is invalid");
    }
    if (options.sourceRevisionReader !== undefined && typeof options.sourceRevisionReader.read !== "function") {
      throw new Error("User service-control source revision reader is invalid");
    }
    if (options.commandRunner !== undefined && options.inspector === undefined && options.sourceRevisionReader === undefined) {
      throw new Error("User service-control test runner requires an injected inspector or source reader");
    }
    this.now = options.now ?? Date.now;
    if (typeof this.now !== "function") throw new Error("User service-control clock is invalid");
    const supervisor = options.commandRunner === undefined
      ? new ProcessSupervisor({
        maxConcurrent: 1,
        maxConcurrentPerExecutable: 1,
        allowedEnvironmentKeys: [],
        requireRootOwnedExecutable: true,
        ...(options.descriptorSpawnAdapter === undefined
          ? { requireSystemPublishedExecutable: true }
          : {
            requireDescriptorExecution: true,
            descriptorSpawnAdapter: options.descriptorSpawnAdapter
          })
      })
      : undefined;
    this.commandRunner = options.commandRunner ?? supervisor!;
    this.inspector = options.inspector ?? (options.sourceRevisionReader === undefined
      ? unavailableReadbackObserver()
      : new LaunchdUserServiceReadbackObserver(this.commandRunner, options.sourceRevisionReader));
    const injectedHostReady = options.commandRunner !== undefined && (options.inspector !== undefined || options.sourceRevisionReader !== undefined);
    const nativeHostReady = options.commandRunner === undefined && options.sourceRevisionReader !== undefined &&
      (options.descriptorSpawnAdapter !== undefined
        ? inspectProcessDescriptorExecutionCapability().available
        : options.systemPublishedExecutablePathAccepted === true && inspectSystemPublishedExecutablePath(LAUNCHCTL_PATH));
    const hostReady = injectedHostReady || nativeHostReady;
    this.available = enabled && hostReady && this.uid === readCurrentUid();
    this.enabledCapabilities = this.available ? ["mac_service_control"] : [];
  }

  async execute(
    request: UserServiceControlRequest,
    control: UserServiceExecutionControl,
    precondition?: UserServiceControlPrecondition
  ): Promise<UserServiceControlResult> {
    if (!this.available) throw new BrokerError("UNSUPPORTED_CAPABILITY", "User service-control adapter is disabled");
    const binding = this.resolveRequest(request);
    const timeoutMs = boundedTimeout(control);
    const startedAtMs = this.now();
    if (!Number.isSafeInteger(startedAtMs) || startedAtMs < 0) {
      throw new BrokerError("PRECONDITION_FAILED", "User service-control clock is invalid");
    }
    const deadlineMs = startedAtMs + timeoutMs;
    checkControl(control, deadlineMs, this.now);

    const boundedControl: UserServiceExecutionControl = {
      timeoutMs,
      shouldCancel: () => control.shouldCancel() || this.now() >= deadlineMs
    };
    const pre = await this.inspect(binding, boundedControl, deadlineMs);
    checkControl(control, deadlineMs, this.now);
    const preState = requireStableState(pre.launchd.state);
    if (precondition !== undefined &&
        (precondition.state !== preState || precondition.sourceRevision !== pre.sourceRevision)) {
      throw new BrokerError("CONFLICT", "User service precondition changed before dispatch");
    }
    const expectedState = expectedStateFor(request.action, request.expectedState);
    const idempotent = request.action !== "restart" && preState === expectedState;

    if (!idempotent) {
      let commandResult: ProcessExecutionResult;
      try {
        commandResult = await this.commandRunner.run({
          executable: LAUNCHCTL_PATH,
          args: fixedActionArgs(request.action, request.serviceId),
          cwd: LAUNCHCTL_CWD,
          environment: {},
          timeoutMs: Math.min(remaining(deadlineMs, this.now), COMMAND_TIMEOUT_MS),
          outputCapBytes: COMMAND_OUTPUT_CAP_BYTES,
          shouldCancel: boundedControl.shouldCancel
        });
      } catch (error) {
        if (error instanceof BrokerError && (error.errorClass === "CANCELLED" || error.errorClass === "TIMEOUT")) {
          throw error;
        }
        return unknownResult(binding, request.action, preState, pre.sourceRevision, "launchctl command could not be started");
      }
      if (commandResult.resultClass !== "SUCCEEDED") {
        return await recoverAfterUncertainCommand(
          binding,
          request.action,
          preState,
          pre.sourceRevision,
          boundedControl,
          deadlineMs,
          this.inspect.bind(this),
          this.commandRunner,
          this.now
        );
      }
      checkControl(control, deadlineMs, this.now);
    }

    let post: UserServiceReadback;
    try {
      post = await this.inspect(binding, boundedControl, deadlineMs);
      post = await this.settlePostcondition(binding, request, boundedControl, deadlineMs, post);
    } catch {
      return unknownResult(binding, request.action, preState, pre.sourceRevision, "post-action launchd readback was unavailable");
    }
    const postState = requireStableStateOrUnknown(post.launchd.state);
    if (postState === expectedState && post.sourceRevision === binding.sourceRevision) {
      return {
        operation: "service_control",
        serviceId: binding.serviceId,
        action: request.action,
        state: "completed",
        resultClass: "SUCCEEDED",
        preState,
        postState,
        sourceRevision: post.sourceRevision,
        idempotent,
        rollback: { status: "not_needed", state: preState },
        verification: {
          status: "verified",
          summary: idempotent ? "requested service state was already satisfied" : "launchd state and source revision matched"
        }
      };
    }

    return recoverFromPostconditionMismatch(
      binding,
      request.action,
      preState,
      postState,
      pre.sourceRevision,
      boundedControl,
      deadlineMs,
      this.inspect.bind(this),
      this.commandRunner,
      this.now
    );
  }

  /** Read the policy-bound service identity before Job admission or dispatch. */
  async readPrecondition(
    request: UserServiceControlRequest,
    control: UserServiceExecutionControl
  ): Promise<UserServiceControlPrecondition> {
    if (!this.available) throw new BrokerError("UNSUPPORTED_CAPABILITY", "User service-control adapter is disabled");
    const binding = this.resolveRequest(request);
    const timeoutMs = boundedTimeout(control);
    const startedAtMs = this.now();
    if (!Number.isSafeInteger(startedAtMs) || startedAtMs < 0) {
      throw new BrokerError("PRECONDITION_FAILED", "User service-control clock is invalid");
    }
    const deadlineMs = startedAtMs + timeoutMs;
    checkControl(control, deadlineMs, this.now);
    const readback = await this.inspect(binding, {
      timeoutMs,
      shouldCancel: () => control.shouldCancel() || this.now() >= deadlineMs
    }, deadlineMs);
    checkControl(control, deadlineMs, this.now);
    return {
      state: requireStableState(readback.launchd.state),
      sourceRevision: readback.sourceRevision
    };
  }

  private resolveRequest(request: UserServiceControlRequest): UserServiceBinding {
    if (request === null || typeof request !== "object" || typeof request.serviceId !== "string") {
      throw new BrokerError("PRECONDITION_FAILED", "User service-control request is malformed");
    }
    validateUserServiceId(request.serviceId, this.uid);
    if (!["start", "stop", "restart"].includes(request.action)) {
      throw new BrokerError("UNSUPPORTED_CAPABILITY", "User service action is not enabled");
    }
    if (request.expectedState !== undefined && request.expectedState !== expectedStateFor(request.action)) {
      throw new BrokerError("PRECONDITION_FAILED", "User service expected_state does not match the action");
    }
    const binding = this.bindings.get(request.serviceId);
    if (binding === undefined) throw new BrokerError("TARGET_NOT_FOUND", "The requested user service is not policy-bound");
    return binding;
  }

  private async inspect(
    binding: UserServiceBinding,
    control: UserServiceExecutionControl,
    deadlineMs: number
  ): Promise<UserServiceReadback> {
    const remainingMs = remaining(deadlineMs, this.now);
    let readback: UserServiceReadback;
    try {
      readback = await this.inspector.inspect(binding.serviceId, {
        timeoutMs: Math.min(control.timeoutMs, remainingMs),
        shouldCancel: control.shouldCancel
      });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("EXECUTION_FAILED", "User service readback failed");
    }
    validateReadback(binding, readback);
    return readback;
  }

  /**
   * launchd can report a short-lived proxy/loading state immediately after a
   * successful kickstart or kill. Wait only for bounded, known transient
   * states; a stable mismatch still follows the strict rollback path.
   */
  private async settlePostcondition(
    binding: UserServiceBinding,
    request: UserServiceControlRequest,
    control: UserServiceExecutionControl,
    deadlineMs: number,
    initial: UserServiceReadback
  ): Promise<UserServiceReadback> {
    const expectedState = expectedStateFor(request.action, request.expectedState);
    let current = initial;
    for (let attempt = 0; attempt < POSTCONDITION_SETTLE_ATTEMPTS; attempt += 1) {
      const state = current.launchd.state;
      if (state === expectedState || !isTransientPostconditionState(state, expectedState) || attempt === POSTCONDITION_SETTLE_ATTEMPTS - 1) {
        return current;
      }
      checkControl(control, deadlineMs, this.now);
      const remainingMs = remaining(deadlineMs, this.now);
      await new Promise((resolve) => setTimeout(resolve, Math.min(POSTCONDITION_SETTLE_DELAY_MS, remainingMs)));
      checkControl(control, deadlineMs, this.now);
      current = await this.inspect(binding, control, deadlineMs);
    }
    return current;
  }
}

export function validateUserServiceId(serviceId: string, uid: number): void {
  if (!Number.isSafeInteger(uid) || uid < 1 || uid > 2_147_483_647 ||
      typeof serviceId !== "string" || serviceId.length > 160 ||
      !USER_SERVICE_ID_PATTERN.test(serviceId) || serviceId !== serviceId.replace(/\.\./gu, "") ||
      serviceId.includes("//") || serviceId.includes("\\") || !serviceId.startsWith(`gui/${String(uid)}/`)) {
    throw new BrokerError("PRECONDITION_FAILED", "service_id must be a policy-bound non-root user launchd identifier");
  }
}

function validateBinding(binding: UserServiceBinding, uid: number): void {
  if (binding === null || typeof binding !== "object") throw new Error("User service binding is malformed");
  validateUserServiceId(binding.serviceId, uid);
  if (!SOURCE_REVISION_PATTERN.test(binding.sourceRevision)) throw new Error("User service source revision is invalid");
  const label = binding.serviceId.slice(binding.serviceId.lastIndexOf("/") + 1);
  if (!isCanonicalAbsolutePath(binding.plistPath) || !binding.plistPath.endsWith(`/Library/LaunchAgents/${label}.plist`)) {
    throw new Error("User service plist path is invalid");
  }
  if (!isCanonicalAbsolutePath(binding.program) || !Array.isArray(binding.arguments) || binding.arguments.length < 1 ||
      binding.arguments.length > 16 || binding.arguments[0] !== binding.program ||
      binding.arguments.some((value) => typeof value !== "string" || value.length === 0 || value.includes("\0") || value.includes("\n") || value.includes("\r"))) {
    throw new Error("User service executable or arguments are invalid");
  }
}

function freezeBinding(binding: UserServiceBinding): UserServiceBinding {
  return Object.freeze({ ...binding, arguments: Object.freeze([...binding.arguments]) });
}

function validateReadback(binding: UserServiceBinding, readback: UserServiceReadback): void {
  if (readback === null || typeof readback !== "object" || readback.launchd === null || typeof readback.launchd !== "object" ||
      readback.launchd.serviceId !== binding.serviceId || readback.launchd.domain !== binding.serviceId.slice(0, binding.serviceId.lastIndexOf("/")) ||
      readback.launchd.label !== binding.serviceId.slice(binding.serviceId.lastIndexOf("/") + 1) || readback.launchd.type !== "LaunchAgent" ||
      readback.launchd.program !== binding.program || !sameStrings(readback.launchd.arguments, binding.arguments) ||
      readback.launchd.plistPath !== binding.plistPath || readback.launchd.truncated !== false ||
      typeof readback.sourceRevision !== "string" || readback.sourceRevision !== binding.sourceRevision) {
    throw new BrokerError("PRECONDITION_FAILED", "User service readback does not match the policy-bound identity");
  }
}

function expectedStateFor(action: UserServiceControlAction, expected?: UserServiceControlState): UserServiceControlState {
  const expectedState = action === "stop" ? "stopped" : "running";
  if (expected !== undefined && expected !== expectedState) {
    throw new BrokerError("PRECONDITION_FAILED", "User service expected_state does not match the action");
  }
  return expectedState;
}

function isTransientPostconditionState(
  state: LaunchdJobReadback["state"],
  expected: UserServiceControlState
): boolean {
  if (expected === "running") return state === "launching" || state === "waiting" || state === "loaded";
  return state === "running" || state === "launching" || state === "waiting" || state === "loaded";
}

function fixedActionArgs(action: UserServiceControlAction, serviceId: string): readonly string[] {
  if (action === "start") return ["kickstart", serviceId];
  if (action === "stop") return ["kill", "SIGTERM", serviceId];
  return ["kickstart", "-k", serviceId];
}

function rollbackArgs(state: UserServiceControlState, serviceId: string): readonly string[] {
  return state === "running" ? ["kickstart", serviceId] : ["kill", "SIGTERM", serviceId];
}

async function recoverAfterUncertainCommand(
  binding: UserServiceBinding,
  action: UserServiceControlAction,
  preState: UserServiceControlState,
  sourceRevision: string,
  control: UserServiceExecutionControl,
  deadlineMs: number,
  inspect: (binding: UserServiceBinding, control: UserServiceExecutionControl, deadlineMs: number) => Promise<UserServiceReadback>,
  commandRunner: UserServiceControlCommandRunner,
  now: () => number
): Promise<UserServiceControlResult> {
  try {
    const observed = await inspect(binding, control, deadlineMs);
    const observedState = requireStableStateOrUnknown(observed.launchd.state);
    if (observedState === preState && observed.sourceRevision === sourceRevision) {
      return unknownResult(binding, action, preState, sourceRevision, "launchctl reported failure; original state was read back", {
        status: "verified",
        state: preState
      });
    }
    if (observedState !== "unknown" && observed.sourceRevision === sourceRevision) {
      try {
        const rollback = await commandRunner.run({
          executable: LAUNCHCTL_PATH,
          args: rollbackArgs(preState, binding.serviceId),
          cwd: LAUNCHCTL_CWD,
          environment: {},
          timeoutMs: Math.min(remaining(deadlineMs, now), COMMAND_TIMEOUT_MS),
          outputCapBytes: COMMAND_OUTPUT_CAP_BYTES,
          shouldCancel: control.shouldCancel
        });
        if (rollback.resultClass !== "SUCCEEDED") {
          return unknownResult(binding, action, preState, sourceRevision, "launchctl outcome and rollback are unresolved");
        }
        const restored = await inspect(binding, control, deadlineMs);
        const restoredState = requireStableStateOrUnknown(restored.launchd.state);
        if (restoredState === preState && restored.sourceRevision === sourceRevision) {
          return unknownResult(binding, action, preState, sourceRevision, "launchctl outcome was unresolved; original state was restored", {
            status: "verified",
            state: restoredState
          });
        }
      } catch {
        return unknownResult(binding, action, preState, sourceRevision, "launchctl outcome and rollback are unresolved");
      }
    }
  } catch {
    return unknownResult(binding, action, preState, sourceRevision, "launchctl outcome and state are unresolved");
  }
  return unknownResult(binding, action, preState, sourceRevision, "launchctl outcome and rollback state are unresolved");
}

async function recoverFromPostconditionMismatch(
  binding: UserServiceBinding,
  action: UserServiceControlAction,
  preState: UserServiceControlState,
  postState: UserServiceControlState | "unknown",
  sourceRevision: string,
  control: UserServiceExecutionControl,
  deadlineMs: number,
  inspect: (binding: UserServiceBinding, control: UserServiceExecutionControl, deadlineMs: number) => Promise<UserServiceReadback>,
  commandRunner: UserServiceControlCommandRunner,
  now: () => number
): Promise<UserServiceControlResult> {
  if (postState === "unknown") return unknownResult(binding, action, preState, sourceRevision, "postcondition state was not stable enough for rollback");
  try {
    const rollback = await commandRunner.run({
      executable: LAUNCHCTL_PATH,
      args: rollbackArgs(preState, binding.serviceId),
      cwd: LAUNCHCTL_CWD,
      environment: {},
      timeoutMs: Math.min(remaining(deadlineMs, now), COMMAND_TIMEOUT_MS),
      outputCapBytes: COMMAND_OUTPUT_CAP_BYTES,
      shouldCancel: control.shouldCancel
    });
    if (rollback.resultClass !== "SUCCEEDED") return unknownResult(binding, action, preState, sourceRevision, "rollback command did not complete");
    const readback = await inspect(binding, control, deadlineMs);
    const rollbackState = requireStableStateOrUnknown(readback.launchd.state);
    if (rollbackState !== preState || readback.sourceRevision !== sourceRevision) {
      return unknownResult(binding, action, preState, sourceRevision, "rollback readback did not restore the original identity");
    }
    return {
      operation: "service_control",
      serviceId: binding.serviceId,
      action,
      state: "failed",
      resultClass: "VERIFICATION_FAILED",
      preState,
      postState,
      sourceRevision,
      idempotent: false,
      rollback: { status: "verified", state: rollbackState },
      verification: { status: "failed", summary: "requested postcondition failed; original state was restored" }
    };
  } catch {
    return unknownResult(binding, action, preState, sourceRevision, "rollback outcome could not be established");
  }
}

function unknownResult(
  binding: UserServiceBinding,
  action: UserServiceControlAction,
  preState: UserServiceControlState,
  sourceRevision: string,
  summary: string,
  rollback: { status: UserServiceRollbackStatus; state: UserServiceControlState | "unknown" } = {
    status: "unknown",
    state: "unknown"
  }
): UserServiceControlResult {
  return {
    operation: "service_control",
    serviceId: binding.serviceId,
    action,
    state: "unknown",
    resultClass: "UNKNOWN_OUTCOME",
    preState,
    postState: "unknown",
    sourceRevision,
    idempotent: false,
    rollback,
    verification: { status: "unknown", summary }
  };
}

function requireStableState(value: LaunchdJobReadback["state"]): UserServiceControlState {
  const state = requireStableStateOrUnknown(value);
  if (state === "unknown") throw new BrokerError("PRECONDITION_FAILED", "User service is not in a stable running or stopped state");
  return state;
}

function requireStableStateOrUnknown(value: LaunchdJobReadback["state"]): UserServiceControlState | "unknown" {
  if (value === "running" || value === "stopped") return value;
  return "unknown";
}

function boundedTimeout(control: UserServiceExecutionControl): number {
  if (control === null || typeof control !== "object" || typeof control.shouldCancel !== "function" ||
      !Number.isSafeInteger(control.timeoutMs) || control.timeoutMs < 1) {
    throw new BrokerError("PRECONDITION_FAILED", "User service-control execution budget is invalid");
  }
  return Math.min(control.timeoutMs, MAX_OPERATION_TIMEOUT_MS);
}

function checkControl(control: UserServiceExecutionControl, deadlineMs: number, now: () => number): void {
  if (control.shouldCancel()) throw new BrokerError("CANCELLED", "User service-control operation was cancelled");
  if (now() >= deadlineMs) throw new BrokerError("TIMEOUT", "User service-control operation timed out");
}

function remaining(deadlineMs: number, now: () => number): number {
  const value = deadlineMs - now();
  if (value <= 0) throw new BrokerError("TIMEOUT", "User service-control operation timed out");
  return value;
}

function sameStrings(left: readonly string[] | null, right: readonly string[]): boolean {
  return left !== null && left.length === right.length && left.every((value, index) => value === right[index]);
}

function isCanonicalAbsolutePath(value: string): boolean {
  return typeof value === "string" && isAbsolute(value) && resolve(value) === value && !value.includes("\0") &&
    !value.includes("\n") && !value.includes("\r") && !value.includes("//");
}

function readCurrentUid(): number {
  try {
    return typeof process.getuid === "function" ? process.getuid() : -1;
  } catch {
    return -1;
  }
}

function unavailableReadbackObserver(): UserServiceReadbackObserver {
  return {
    inspect: async () => {
      throw new BrokerError("UNSUPPORTED_CAPABILITY", "User service readback adapter is not enabled");
    }
  };
}

// Keep the parser import part of this candidate's proof surface. The real
// host observer must parse launchctl output with the shared strict parser.
export function parseUserServiceReadback(serviceId: string, output: string, sourceRevision: string): UserServiceReadback {
  return { launchd: parseLaunchdJobReadback(serviceId, output), sourceRevision };
}
