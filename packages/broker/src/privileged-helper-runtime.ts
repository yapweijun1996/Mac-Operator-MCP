import { isAbsolute, resolve } from "node:path";
import { capturePeerProcessIdentity, type PeerProcessIdentity } from "./peer-credentials.js";
import { ProcessSupervisor, type ProcessExecutionRequest, type ProcessExecutionResult } from "./process-supervisor.js";
import { PrivilegedHelperKeyManager } from "./privileged-helper-keyring.js";
import {
  PrivilegedHelperIpcServer,
  type PrivilegedHelperAdapter,
  type PrivilegedHelperIpcServerOptions,
  type PrivilegedHelperReplayGuard,
  type UnsignedPrivilegedHelperCommand
} from "./privileged-helper.js";
import type { BrokerStore } from "./persistence.js";
import type { NativePeerPolicy } from "./native-peer-ipc-server.js";

export type PrivilegedHelperRuntimeState = "stopped" | "starting" | "running" | "stopping" | "failed";

export type PrivilegedHelperStartupErrorCode =
  | "HELPER_KEY_CONFIG_UNAVAILABLE"
  | "HELPER_SOCKET_INVALID"
  | "HELPER_PEER_POLICY_INVALID"
  | "INVALID_HELPER_SERVICE"
  | "HELPER_SERVICE_UNAVAILABLE"
  | "HELPER_PROCESS_NOT_RUNNING"
  | "HELPER_PROCESS_IDENTITY_UNAVAILABLE";

export class PrivilegedHelperStartupError extends Error {
  readonly code: PrivilegedHelperStartupErrorCode;

  constructor(code: PrivilegedHelperStartupErrorCode, message: string) {
    super(message);
    this.name = "PrivilegedHelperStartupError";
    this.code = code;
  }
}

export interface PrivilegedHelperRuntimeOptions {
  helperKeyConfigPath: string;
  helperKeyStore: BrokerStore;
  socketPath: string;
  /** The helper must never reuse the unprivileged Broker socket. */
  brokerSocketPath: string;
  /** Optional additional local control socket paths that must remain distinct. */
  reservedSocketPaths?: readonly string[];
  /** Production helper startup requires native peer credentials and identity. */
  peerPolicy: NativePeerPolicy;
  replayGuard: PrivilegedHelperReplayGuard;
  adapter: PrivilegedHelperAdapter;
  authorizeCommand: (command: UnsignedPrivilegedHelperCommand) => void;
  serverOptions?: Omit<PrivilegedHelperIpcServerOptions, "authenticationKey" | "socketPath" | "peerPolicy" | "replayGuard" | "adapter" | "authorizeCommand">;
}

export interface LaunchdHelperIdentityCommandExecutor {
  run(command: ProcessExecutionRequest): Promise<ProcessExecutionResult>;
}

export interface LaunchdBrokerIdentityCaptureOptions {
  brokerServiceId: string;
  expectedBrokerUid: number;
  commandExecutor?: LaunchdHelperIdentityCommandExecutor;
}

interface LaunchdBrokerProcessReadback {
  serviceId: string;
  uid: number;
  label: "com.mac-operator.broker";
  pid: number;
  state: "running";
}

const LAUNCHCTL_PATH = "/bin/launchctl";
const LAUNCHCTL_TIMEOUT_MS = 5_000;
const LAUNCHCTL_OUTPUT_CAP_BYTES = 131_072;
const BROKER_SERVICE_PATTERN = /^gui\/([1-9][0-9]{0,9})\/(com\.mac-operator\.broker)$/u;

/**
 * Owns the separately authenticated helper listener lifecycle. It is not a
 * Broker channel and cannot be registered with the MCP Edge.
 */
export class PrivilegedHelperRuntime {
  private stateValue: PrivilegedHelperRuntimeState = "stopped";
  private operation: Promise<void> = Promise.resolve();

  constructor(private readonly server: PrivilegedHelperIpcServer) {}

  get state(): PrivilegedHelperRuntimeState {
    return this.stateValue;
  }

  start(): Promise<void> {
    return this.enqueue(() => this.startInternal());
  }

  close(): Promise<void> {
    return this.enqueue(() => this.closeInternal());
  }

  private async startInternal(): Promise<void> {
    if (this.stateValue !== "stopped") throw new Error(`Privileged helper runtime cannot start from ${this.stateValue}`);
    this.stateValue = "starting";
    try {
      await this.server.listen();
      this.stateValue = "running";
    } catch (error) {
      try {
        await this.server.close();
        this.stateValue = "stopped";
      } catch (cleanupError) {
        this.stateValue = "failed";
        throw new AggregateError([error, cleanupError], "Privileged helper startup failed and cleanup also failed");
      }
      throw error;
    }
  }

  private async closeInternal(): Promise<void> {
    if (this.stateValue === "stopped") return;
    this.stateValue = "stopping";
    try {
      await this.server.close();
      this.stateValue = "stopped";
    } catch (error) {
      this.stateValue = "failed";
      throw error;
    }
  }

  private enqueue(operation: () => Promise<void>): Promise<void> {
    const run = this.operation.catch(() => undefined).then(operation);
    this.operation = run;
    return run;
  }
}

/**
 * Captures the exact per-user Broker identity that the root helper is allowed
 * to call. launchd contributes only the PID; native readback binds PID and
 * start-time before helper construction.
 */
export async function captureLaunchdBrokerProcessIdentity(
  options: LaunchdBrokerIdentityCaptureOptions
): Promise<PeerProcessIdentity> {
  const service = parseLaunchdBrokerServiceId(options.brokerServiceId, options.expectedBrokerUid);
  const executor = options.commandExecutor ?? new ProcessSupervisor({ allowedEnvironmentKeys: [] });
  let result: ProcessExecutionResult;
  try {
    result = await executor.run({
      executable: LAUNCHCTL_PATH,
      args: ["print", service.serviceId],
      cwd: "/",
      environment: {},
      timeoutMs: LAUNCHCTL_TIMEOUT_MS,
      outputCapBytes: LAUNCHCTL_OUTPUT_CAP_BYTES
    });
  } catch {
    throw new PrivilegedHelperStartupError("HELPER_SERVICE_UNAVAILABLE", "Broker launchd readback failed");
  }
  const readback = parseLaunchdBrokerProcessReadback(service.serviceId, result);
  try {
    return capturePeerProcessIdentity(readback.pid);
  } catch {
    throw new PrivilegedHelperStartupError("HELPER_PROCESS_IDENTITY_UNAVAILABLE", "Broker process identity readback failed");
  }
}

/**
 * Production helper startup binding. The caller cannot supply a PID or
 * process identity; it must match the exact per-user Broker LaunchAgent.
 */
export async function createPrivilegedHelperRuntimeForLaunchdBroker(
  options: Omit<PrivilegedHelperRuntimeOptions, "peerPolicy"> & {
    brokerServiceId: string;
    expectedBrokerUid: number;
    expectedBrokerGid?: number;
    commandExecutor?: LaunchdHelperIdentityCommandExecutor;
  }
): Promise<PrivilegedHelperRuntime> {
  const { brokerServiceId, expectedBrokerUid, expectedBrokerGid, commandExecutor, ...runtimeOptions } = options;
  const identity = await captureLaunchdBrokerProcessIdentity({
    brokerServiceId,
    expectedBrokerUid,
    ...(commandExecutor === undefined ? {} : { commandExecutor })
  });
  return createPrivilegedHelperRuntimeFromActiveKeyConfig({
    ...runtimeOptions,
    peerPolicy: {
      expectedUid: expectedBrokerUid,
      ...(expectedBrokerGid === undefined ? {} : { expectedGid: expectedBrokerGid }),
      allowedProcessIdentity: identity
    }
  });
}

/**
 * Restores the exact BrokerStore-approved helper key before constructing the
 * helper server. No request argument can select the key, socket, or peer.
 */
export async function createPrivilegedHelperRuntimeFromActiveKeyConfig(
  options: PrivilegedHelperRuntimeOptions
): Promise<PrivilegedHelperRuntime> {
  validateSocketBoundary(options);
  if (options.peerPolicy.allowedProcessIdentity === undefined) {
    throw new PrivilegedHelperStartupError(
      "HELPER_PEER_POLICY_INVALID",
      "Privileged helper startup requires an explicit native peer process identity"
    );
  }
  const manager = new PrivilegedHelperKeyManager(options.helperKeyConfigPath, options.helperKeyStore);
  try {
    await manager.restore();
    const server = manager.createServer({
      ...(options.serverOptions ?? {}),
      socketPath: options.socketPath,
      peerPolicy: options.peerPolicy,
      replayGuard: options.replayGuard,
      adapter: options.adapter,
      authorizeCommand: options.authorizeCommand
    });
    manager.dispose();
    return new PrivilegedHelperRuntime(server);
  } catch (error) {
    manager.dispose();
    throw new PrivilegedHelperStartupError(
      "HELPER_KEY_CONFIG_UNAVAILABLE",
      error instanceof Error ? error.message : "Privileged helper key configuration could not be restored"
    );
  }
}

function validateSocketBoundary(options: PrivilegedHelperRuntimeOptions): void {
  const paths = [options.socketPath, options.brokerSocketPath, ...(options.reservedSocketPaths ?? [])];
  if (paths.some((path) => !isAbsolute(path) || resolve(path) !== path || path.includes("\0"))) {
    throw new PrivilegedHelperStartupError("HELPER_SOCKET_INVALID", "Privileged helper socket paths must be canonical absolute paths");
  }
  const identities = new Set(paths);
  if (identities.size !== paths.length) {
    throw new PrivilegedHelperStartupError("HELPER_SOCKET_INVALID", "Privileged helper socket must be distinct from Broker and control sockets");
  }
}

function parseLaunchdBrokerServiceId(serviceId: string, expectedUid?: number): { serviceId: string; uid: number; label: "com.mac-operator.broker" } {
  const match = typeof serviceId === "string" ? BROKER_SERVICE_PATTERN.exec(serviceId) : null;
  if (!match) throw new PrivilegedHelperStartupError("INVALID_HELPER_SERVICE", "Broker launchd service ID is invalid");
  const uid = Number(match[1]);
  if (expectedUid !== undefined && (!Number.isSafeInteger(expectedUid) || expectedUid < 1 || uid !== expectedUid)) {
    throw new PrivilegedHelperStartupError("INVALID_HELPER_SERVICE", "Broker launchd service user does not match the expected user");
  }
  return { serviceId, uid, label: "com.mac-operator.broker" };
}

function parseLaunchdBrokerProcessReadback(serviceId: string, result: ProcessExecutionResult): LaunchdBrokerProcessReadback {
  const service = parseLaunchdBrokerServiceId(serviceId);
  if (result.resultClass !== "SUCCEEDED") {
    if (/Could not find service|No such process|service .* not found/iu.test(result.stderr)) {
      throw new PrivilegedHelperStartupError("HELPER_SERVICE_UNAVAILABLE", "Broker launchd service is unavailable");
    }
    throw new PrivilegedHelperStartupError("HELPER_SERVICE_UNAVAILABLE", "Broker launchd readback failed");
  }
  const header = new RegExp(`^${escapeRegExp(service.serviceId)}\\s*=\\s*\\{`, "mu");
  if (!header.test(result.stdout)) throw new PrivilegedHelperStartupError("HELPER_SERVICE_UNAVAILABLE", "Broker launchd readback identity is mismatched");
  const state = /^\s*state\s*=\s*([^\r\n]+)/mu.exec(result.stdout)?.[1]?.trim();
  if (state !== "running") throw new PrivilegedHelperStartupError("HELPER_PROCESS_NOT_RUNNING", "Broker launchd service is not running");
  const pidText = /^\s*pid\s*=\s*([0-9]+)/mu.exec(result.stdout)?.[1];
  const pid = pidText === undefined ? NaN : Number(pidText);
  if (!Number.isSafeInteger(pid) || pid < 1 || pid > 99_999_999) {
    throw new PrivilegedHelperStartupError("HELPER_PROCESS_NOT_RUNNING", "Broker launchd service has no valid process identity");
  }
  return { ...service, pid, state: "running" };
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}
