import { isAbsolute, resolve } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import { capturePeerProcessIdentity, type PeerProcessIdentity } from "./peer-credentials.js";
import { ProcessSupervisor, type ProcessExecutionRequest, type ProcessExecutionResult } from "./process-supervisor.js";
import { loadPrivilegedHelperKeyConfigWithoutBroker, PrivilegedHelperKeyManager } from "./privileged-helper-keyring.js";
import {
  PrivilegedHelperIpcServer,
  type PrivilegedHelperAdapter,
  type PrivilegedHelperIpcServerOptions,
  type PrivilegedHelperReplayGuard,
  type PrivilegedHelperStatusReadback,
  type UnsignedPrivilegedHelperCommand
} from "./privileged-helper.js";
import type { BrokerStore } from "./persistence.js";
import type { NativePeerPolicy } from "./native-peer-ipc-server.js";
import { PrivilegedHelperAuthorityClient, type PrivilegedHelperAuthorityPoller } from "./privileged-helper-authority-ipc.js";

export type PrivilegedHelperRuntimeState = "stopped" | "starting" | "running" | "stopping" | "failed";

export type PrivilegedHelperStartupErrorCode =
  | "HELPER_KEY_CONFIG_UNAVAILABLE"
  | "HELPER_SOCKET_INVALID"
  | "HELPER_PEER_POLICY_INVALID"
  | "INVALID_HELPER_SERVICE"
  | "HELPER_SERVICE_UNAVAILABLE"
  | "HELPER_PROCESS_NOT_RUNNING"
  | "HELPER_PROCESS_IDENTITY_UNAVAILABLE"
  | "HELPER_AUTHORITY_UNAVAILABLE";

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
  /** Broker-owned authority polling socket; required when an adapter is enabled. */
  authoritySocketPath?: string;
  /** Optional additional local control socket paths that must remain distinct. */
  reservedSocketPaths?: readonly string[];
  /** Production helper startup requires native peer credentials and identity. */
  peerPolicy: NativePeerPolicy;
  replayGuard: PrivilegedHelperReplayGuard;
  adapter: PrivilegedHelperAdapter;
  authorizeCommand: (command: UnsignedPrivilegedHelperCommand) => void;
  /** Optional separately authenticated Broker authority poll channel. */
  authorityPoller?: PrivilegedHelperAuthorityPoller;
  authorityPollIntervalMs?: number;
  /** Helper-owned runtime metadata source; never inferred from launchd. */
  readStatus?: () => PrivilegedHelperStatusReadback;
  /** Broker-owned final authority gate for status reads. */
  authorizeStatus?: () => void;
  serverOptions?: Omit<PrivilegedHelperIpcServerOptions, "authenticationKey" | "socketPath" | "peerPolicy" | "replayGuard" | "adapter" | "authorizeCommand" | "readStatus" | "authorizeStatus">;
}

/**
 * Root-helper startup options. This deliberately has no BrokerStore field:
 * the helper loads its protected key material locally and asks the Broker's
 * authenticated authority channel before dispatching enabled operations.
 */
export interface PrivilegedHelperRuntimeKeyMaterialOptions {
  helperKeyConfigPath: string;
  socketPath: string;
  /** The helper must never reuse the unprivileged Broker socket. */
  brokerSocketPath: string;
  /** Broker-owned authority polling socket; required when an adapter is enabled. */
  authoritySocketPath?: string;
  reservedSocketPaths?: readonly string[];
  /** Broker identity for both the helper command and authority poll channels. */
  peerPolicy: NativePeerPolicy;
  replayGuard: PrivilegedHelperReplayGuard;
  adapter: PrivilegedHelperAdapter;
  /** Local command gate. Broker authority remains mandatory through polling. */
  authorizeCommand: (command: UnsignedPrivilegedHelperCommand) => void;
  authorityPoller?: PrivilegedHelperAuthorityPoller;
  authorityPollIntervalMs?: number;
  readStatus?: () => PrivilegedHelperStatusReadback;
  authorizeStatus?: () => void;
  keyAuthorityCheck?: () => void;
  serverOptions?: Omit<PrivilegedHelperIpcServerOptions, "authenticationKey" | "socketPath" | "peerPolicy" | "replayGuard" | "adapter" | "authorizeCommand" | "readStatus" | "authorizeStatus">;
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

  constructor(
    private readonly server: PrivilegedHelperIpcServer,
    private readonly authorityPoller?: PrivilegedHelperAuthorityPoller
  ) {}

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
      try {
        await this.server.close();
      } finally {
        this.authorityPoller?.dispose?.();
      }
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
  validateHelperPeerPolicy(options.peerPolicy);
  const manager = new PrivilegedHelperKeyManager(options.helperKeyConfigPath, options.helperKeyStore);
  let authorityPoller = options.authorityPoller;
  try {
    await manager.restore();
    if (options.adapter.available && authorityPoller === undefined) {
      if (options.authoritySocketPath === undefined) {
        throw new PrivilegedHelperStartupError(
          "HELPER_AUTHORITY_UNAVAILABLE",
          "Privileged helper startup requires an authority socket when an adapter is enabled"
        );
      }
      authorityPoller = manager.createAuthorityPoller({
        socketPath: options.authoritySocketPath,
        peerPolicy: options.peerPolicy
      });
    }
    if (options.adapter.available && authorityPoller === undefined) {
      throw new PrivilegedHelperStartupError(
        "HELPER_AUTHORITY_UNAVAILABLE",
        "Privileged helper startup requires a separately authenticated Broker authority poller when an adapter is enabled"
      );
    }
    const server = manager.createServer({
      ...(options.serverOptions ?? {}),
      socketPath: options.socketPath,
      peerPolicy: options.peerPolicy,
      replayGuard: options.replayGuard,
      adapter: options.adapter,
      authorizeCommand: options.authorizeCommand,
      ...(authorityPoller === undefined ? {} : { authorityPoller }),
      ...(options.authorityPollIntervalMs === undefined ? {} : { authorityPollIntervalMs: options.authorityPollIntervalMs }),
      ...(options.readStatus === undefined ? {} : { readStatus: options.readStatus }),
      ...(options.authorizeStatus === undefined ? {} : { authorizeStatus: options.authorizeStatus })
    });
    manager.dispose();
    return new PrivilegedHelperRuntime(server, authorityPoller);
  } catch (error) {
    authorityPoller?.dispose?.();
    manager.dispose();
    if (error instanceof PrivilegedHelperStartupError) throw error;
    throw new PrivilegedHelperStartupError(
      "HELPER_KEY_CONFIG_UNAVAILABLE",
      error instanceof Error ? error.message : "Privileged helper key configuration could not be restored"
    );
  }
}

/**
 * Root-helper startup that does not open BrokerStore. The helper key config
 * and key are read from a protected root-owned source; revocation, rotation,
 * request binding, and kill-switch decisions are supplied by the authenticated
 * Broker authority poller before and during every enabled operation.
 */
export async function createPrivilegedHelperRuntimeFromKeyMaterial(
  options: PrivilegedHelperRuntimeKeyMaterialOptions
): Promise<PrivilegedHelperRuntime> {
  validateSocketBoundary(options);
  validateHelperPeerPolicy(options.peerPolicy);
  let loaded: Awaited<ReturnType<typeof loadPrivilegedHelperKeyConfigWithoutBroker>> | undefined;
  let authorityPoller = options.authorityPoller;
  let server: PrivilegedHelperIpcServer | undefined;
  try {
    loaded = await loadPrivilegedHelperKeyConfigWithoutBroker(options.helperKeyConfigPath);
    const now = options.serverOptions?.now ?? Date.now;
    const notBeforeMs = loaded.key.notBeforeMs;
    const expiresAtMs = loaded.key.expiresAtMs;
    const assertConfiguredKeyUsable = (): void => {
      const nowMs = now();
      if (!Number.isSafeInteger(nowMs) || nowMs < notBeforeMs || nowMs >= expiresAtMs) {
        throw new BrokerError("AUTH_EXPIRED", "Privileged helper key is outside its validity window");
      }
      options.keyAuthorityCheck?.();
    };
    assertConfiguredKeyUsable();
    if (options.adapter.available && authorityPoller === undefined) {
      if (options.authoritySocketPath === undefined) {
        throw new PrivilegedHelperStartupError(
          "HELPER_AUTHORITY_UNAVAILABLE",
          "Privileged helper startup requires an authority socket when an adapter is enabled"
        );
      }
      authorityPoller = new PrivilegedHelperAuthorityClient({
        socketPath: options.authoritySocketPath,
        authenticationKey: loaded.key.key,
        peerPolicy: options.peerPolicy,
        now,
        keyAuthorityCheck: assertConfiguredKeyUsable
      });
    }
    if (options.adapter.available && authorityPoller === undefined) {
      throw new PrivilegedHelperStartupError(
        "HELPER_AUTHORITY_UNAVAILABLE",
        "Privileged helper startup requires a separately authenticated Broker authority poller when an adapter is enabled"
      );
    }
    server = new PrivilegedHelperIpcServer({
      ...(options.serverOptions ?? {}),
      socketPath: options.socketPath,
      authenticationKey: loaded.key.key,
      peerPolicy: options.peerPolicy,
      replayGuard: options.replayGuard,
      adapter: options.adapter,
      authorizeCommand: options.authorizeCommand,
      keyAuthorityCheck: assertConfiguredKeyUsable,
      ...(authorityPoller === undefined ? {} : { authorityPoller }),
      ...(options.authorityPollIntervalMs === undefined ? {} : { authorityPollIntervalMs: options.authorityPollIntervalMs }),
      ...(options.readStatus === undefined ? {} : { readStatus: options.readStatus }),
      ...(options.authorizeStatus === undefined ? {} : { authorizeStatus: options.authorizeStatus })
    });
    loaded.key.key.fill(0);
    loaded = undefined;
    return new PrivilegedHelperRuntime(server, authorityPoller);
  } catch (error) {
    authorityPoller?.dispose?.();
    loaded?.key.key.fill(0);
    await server?.close().catch(() => undefined);
    if (error instanceof PrivilegedHelperStartupError) throw error;
    throw new PrivilegedHelperStartupError(
      "HELPER_KEY_CONFIG_UNAVAILABLE",
      error instanceof Error ? error.message : "Privileged helper key material could not be loaded"
    );
  }
}

type PrivilegedHelperSocketBoundaryOptions = Pick<PrivilegedHelperRuntimeOptions, "socketPath" | "brokerSocketPath" | "authoritySocketPath" | "reservedSocketPaths">;

function validateSocketBoundary(options: PrivilegedHelperSocketBoundaryOptions): void {
  const paths = [
    options.socketPath,
    options.brokerSocketPath,
    ...(options.authoritySocketPath === undefined ? [] : [options.authoritySocketPath]),
    ...(options.reservedSocketPaths ?? [])
  ];
  if (paths.some((path) => !isAbsolute(path) || resolve(path) !== path || path.includes("\0"))) {
    throw new PrivilegedHelperStartupError("HELPER_SOCKET_INVALID", "Privileged helper socket paths must be canonical absolute paths");
  }
  const identities = new Set(paths);
  if (identities.size !== paths.length) {
    throw new PrivilegedHelperStartupError("HELPER_SOCKET_INVALID", "Privileged helper socket must be distinct from Broker and control sockets");
  }
}

function validateHelperPeerPolicy(peerPolicy: NativePeerPolicy): void {
  if (peerPolicy.allowedProcessIdentity === undefined) {
    throw new PrivilegedHelperStartupError(
      "HELPER_PEER_POLICY_INVALID",
      "Privileged helper startup requires an explicit native peer process identity"
    );
  }
  if (!Number.isSafeInteger(peerPolicy.expectedUid) || peerPolicy.expectedUid < 1) {
    throw new PrivilegedHelperStartupError(
      "HELPER_PEER_POLICY_INVALID",
      "Privileged helper startup requires a non-root Broker peer identity"
    );
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
