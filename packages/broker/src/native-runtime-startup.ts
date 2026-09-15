import { ProcessSupervisor, type ProcessExecutionRequest, type ProcessExecutionResult } from "./process-supervisor.js";
import { capturePeerProcessIdentity, type PeerProcessIdentity } from "./peer-credentials.js";
import { createMacOsNativeBrokerRuntime, type MacOsNativeBrokerRuntimeOptions } from "./runtime.js";
import { EdgeAuthenticationKeyManager } from "./edge-keyring-config.js";
import { AuthorityControlKeyManager } from "./authority-control-keyring.js";
import { AuthorityControlIpcServer } from "./authority-control-ipc.js";
import { KeychainDeliveryServer } from "./keychain-delivery.js";
import { assertPrivilegedHelperCommandAuthority } from "./privileged-helper.js";
import { PrivilegedHelperKeyManager } from "./privileged-helper-keyring.js";
import type { EdgeKeyring } from "./edge-keyring.js";
import type { Broker } from "./broker.js";
import type { BrokerStore } from "./persistence.js";
import type { NativePeerPolicy } from "./native-peer-ipc-server.js";

const LAUNCHCTL_PATH = "/bin/launchctl";
const LAUNCHCTL_TIMEOUT_MS = 5_000;
const LAUNCHCTL_OUTPUT_CAP_BYTES = 131_072;
const LAUNCHD_STARTUP_DEADLINE_MS = 5_000;
const LAUNCHD_XPCPROXY_RETRY_DELAY_MS = 50;
const EDGE_SERVICE_PATTERN = /^gui\/([1-9][0-9]{0,9})\/(com\.mac-operator\.[A-Za-z0-9.-]{1,96})$/u;

export type NativeRuntimeStartupErrorCode =
  | "INVALID_EDGE_SERVICE"
  | "EDGE_SERVICE_UNAVAILABLE"
  | "EDGE_PROCESS_NOT_RUNNING"
  | "EDGE_PROCESS_IDENTITY_UNAVAILABLE"
  | "EDGE_KEY_CONFIG_UNAVAILABLE"
  | "AUTHORITY_KEY_CONFIG_UNAVAILABLE"
  | "HELPER_AUTHORITY_CONFIG_UNAVAILABLE";

export class NativeRuntimeStartupError extends Error {
  readonly code: NativeRuntimeStartupErrorCode;

  constructor(code: NativeRuntimeStartupErrorCode, message: string) {
    super(message);
    this.name = "NativeRuntimeStartupError";
    this.code = code;
  }
}

export interface LaunchdIdentityCommandExecutor {
  run(command: ProcessExecutionRequest): Promise<ProcessExecutionResult>;
}

export interface LaunchdEdgeProcessReadback {
  serviceId: string;
  uid: number;
  label: string;
  pid: number;
  state: "running";
}

export interface LaunchdEdgeIdentityCaptureOptions {
  edgeServiceId: string;
  expectedUid: number;
  commandExecutor?: LaunchdIdentityCommandExecutor;
}

/**
 * Captures the current Edge process identity from its user LaunchAgent.
 * launchd output is only used to obtain a PID; the native process readback is
 * the authority for PID/start-time binding and the Broker rechecks it after
 * the listener starts.
 */
export async function captureLaunchdEdgeProcessIdentity(
  options: LaunchdEdgeIdentityCaptureOptions
): Promise<PeerProcessIdentity> {
  const service = parseEdgeServiceId(options.edgeServiceId, options.expectedUid);
  const executor = options.commandExecutor ?? new ProcessSupervisor({ allowedEnvironmentKeys: [] });
  const deadline = Date.now() + LAUNCHD_STARTUP_DEADLINE_MS;
  for (;;) {
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) {
      throw new NativeRuntimeStartupError("EDGE_PROCESS_NOT_RUNNING", "Edge launchd service did not reach running state");
    }
    let result: ProcessExecutionResult;
    try {
      result = await executor.run({
        executable: LAUNCHCTL_PATH,
        args: ["print", service.serviceId],
        cwd: "/",
        environment: {},
        timeoutMs: Math.min(LAUNCHCTL_TIMEOUT_MS, remainingMs),
        outputCapBytes: LAUNCHCTL_OUTPUT_CAP_BYTES
      });
    } catch {
      throw new NativeRuntimeStartupError("EDGE_SERVICE_UNAVAILABLE", "Edge launchd readback failed");
    }
    try {
      const readback = parseLaunchdEdgeProcessReadback(service.serviceId, result);
      try {
        return capturePeerProcessIdentity(readback.pid);
      } catch {
        throw new NativeRuntimeStartupError("EDGE_PROCESS_IDENTITY_UNAVAILABLE", "Edge process identity readback failed");
      }
    } catch (error) {
      if (error instanceof NativeRuntimeStartupError && error.code === "EDGE_PROCESS_NOT_RUNNING" && isXpcProxyState(result.stdout)) {
        const delayMs = Math.min(LAUNCHD_XPCPROXY_RETRY_DELAY_MS, Math.max(0, deadline - Date.now()));
        if (delayMs > 0) {
          await new Promise<void>((resolve) => setTimeout(resolve, delayMs));
          continue;
        }
      }
      throw error;
    }
  }
}

/**
 * Production startup assembly for a Broker whose Edge is managed by a
 * per-user LaunchAgent. The caller must provide the exact Edge service ID and
 * expected user; no PID, permission, or capability is accepted from MCP
 * request arguments.
 */
export async function createMacOsNativeBrokerRuntimeForLaunchdEdge(
  options: Omit<MacOsNativeBrokerRuntimeOptions, "peerPolicy"> & {
    edgeServiceId: string;
    expectedEdgeUid: number;
    expectedEdgeGid?: number;
    commandExecutor?: LaunchdIdentityCommandExecutor;
  }
): Promise<ReturnType<typeof createMacOsNativeBrokerRuntime>> {
  const { edgeServiceId, expectedEdgeUid, expectedEdgeGid, commandExecutor, ...runtimeOptions } = options;
  const identity = await captureLaunchdEdgeProcessIdentity({
    edgeServiceId,
    expectedUid: expectedEdgeUid,
    ...(commandExecutor === undefined ? {} : { commandExecutor })
  });
  return createMacOsNativeBrokerRuntime({
    ...runtimeOptions,
    peerPolicy: {
      expectedUid: expectedEdgeUid,
      ...(expectedEdgeGid === undefined ? {} : { expectedGid: expectedEdgeGid }),
      allowedProcessIdentity: identity
    }
  });
}

/**
 * Startup assembly that restores the exact BrokerStore-approved Edge key
 * configuration before constructing the Broker and native IPC listener.
 * Callers must provide a Broker factory so the restored keyring is the one
 * owned by the Broker; a pre-built Broker cannot be safely patched in place.
 */
export async function createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfig(
  options: Omit<MacOsNativeBrokerRuntimeOptions, "peerPolicy" | "broker"> & {
    edgeServiceId: string;
    expectedEdgeUid: number;
    expectedEdgeGid?: number;
    commandExecutor?: LaunchdIdentityCommandExecutor;
    edgeKeyConfigPath: string;
    edgeKeyStore: BrokerStore;
    createBroker: (edgeAuthenticationKeys: EdgeKeyring) => Broker;
    keychainDelivery?: {
      socketPath: string;
      keyId: string;
    };
  }
): Promise<ReturnType<typeof createMacOsNativeBrokerRuntime>> {
  const {
    edgeKeyConfigPath,
    edgeKeyStore,
    createBroker,
    keychainDelivery,
    ...runtimeOptions
  } = options;
  const manager = new EdgeAuthenticationKeyManager(edgeKeyConfigPath, edgeKeyStore);
  const loaded = await manager.restore();
  if (loaded.keys.length === 0 || loaded.keys.some((key) => key.edgeId !== runtimeOptions.edgeId)) {
    throw new NativeRuntimeStartupError(
      "EDGE_KEY_CONFIG_UNAVAILABLE",
      "Active Edge key configuration does not match the requested Edge identity"
    );
  }
  const keychainEntries = loaded.document.keys.filter((entry) => entry.keySource === "keychain");
  if (keychainEntries.length > 0 && keychainDelivery === undefined) {
    throw new NativeRuntimeStartupError(
      "EDGE_KEY_CONFIG_UNAVAILABLE",
      "Keychain-backed Edge configuration requires an explicit delivery channel"
    );
  }
  if (keychainDelivery === undefined) {
    const broker = createBroker(loaded.keyring);
    return createMacOsNativeBrokerRuntimeForLaunchdEdge({ ...runtimeOptions, broker });
  }
  if (keychainDelivery.socketPath === runtimeOptions.socketPath) {
    throw new NativeRuntimeStartupError(
      "EDGE_KEY_CONFIG_UNAVAILABLE",
      "Keychain delivery socket must be separate from the Broker IPC socket"
    );
  }
  const selected = keychainEntries.find((entry) => entry.keyId === keychainDelivery.keyId);
  if (selected === undefined || selected.service === undefined || selected.account === undefined) {
    throw new NativeRuntimeStartupError(
      "EDGE_KEY_CONFIG_UNAVAILABLE",
      "Requested Keychain delivery key is not active for the Edge"
    );
  }
  const broker = createBroker(loaded.keyring);
  const identity = await captureLaunchdEdgeProcessIdentity({
    edgeServiceId: runtimeOptions.edgeServiceId,
    expectedUid: runtimeOptions.expectedEdgeUid,
    ...(runtimeOptions.commandExecutor === undefined ? {} : { commandExecutor: runtimeOptions.commandExecutor })
  });
  const peerPolicy = {
    expectedUid: runtimeOptions.expectedEdgeUid,
    ...(runtimeOptions.expectedEdgeGid === undefined ? {} : { expectedGid: runtimeOptions.expectedEdgeGid }),
    allowedProcessIdentity: identity
  };
  const delivery = new KeychainDeliveryServer({
    socketPath: keychainDelivery.socketPath,
    peerPolicy,
    service: selected.service,
    account: selected.account,
    keyId: selected.keyId,
    keyDigest: selected.keyDigest,
    onPeerIdentityLost: (lostIdentity) => {
      broker.revokeEdge(runtimeOptions.edgeId);
      runtimeOptions.onPeerIdentityLost?.(lostIdentity);
    }
  });
  return createMacOsNativeBrokerRuntime({
    ...runtimeOptions,
    broker,
    peerPolicy,
    operatorChannels: [...(runtimeOptions.operatorChannels ?? []), delivery]
  });
}

/**
 * Production startup assembly for the Edge, Broker, and separate owner-only
 * Authority Control channel. Both key configurations must already have an
 * exact persisted activation; no MCP request can select either key or socket.
 */
export async function createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfigAndAuthority(
  options: Omit<MacOsNativeBrokerRuntimeOptions, "peerPolicy" | "broker"> & {
    edgeServiceId: string;
    expectedEdgeUid: number;
    expectedEdgeGid?: number;
    commandExecutor?: LaunchdIdentityCommandExecutor;
    edgeKeyConfigPath: string;
    edgeKeyStore: BrokerStore;
    createBroker: (edgeAuthenticationKeys: EdgeKeyring) => Broker;
    keychainDelivery?: {
      socketPath: string;
      keyId: string;
    };
    authorityKeyConfigPath: string;
    authoritySocketPath: string;
    authorityPeerPolicy: NativePeerPolicy;
  }
): Promise<ReturnType<typeof createMacOsNativeBrokerRuntime>> {
  const {
    authorityKeyConfigPath,
    authoritySocketPath,
    authorityPeerPolicy,
    edgeKeyStore,
    socketPath,
    ...baseOptions
  } = options;
  if (authoritySocketPath === socketPath) {
    throw new NativeRuntimeStartupError(
      "AUTHORITY_KEY_CONFIG_UNAVAILABLE",
      "Authority Control socket must be separate from the Broker IPC socket"
    );
  }
  if (authorityPeerPolicy.allowedProcessIdentity === undefined) {
    throw new NativeRuntimeStartupError(
      "AUTHORITY_KEY_CONFIG_UNAVAILABLE",
      "Authority Control startup requires an explicit native peer process identity"
    );
  }
  const manager = new AuthorityControlKeyManager(authorityKeyConfigPath, edgeKeyStore);
  let loaded: Awaited<ReturnType<AuthorityControlKeyManager["restore"]>>;
  try {
    loaded = await manager.restore();
  } catch (error) {
    manager.dispose();
    if (error instanceof NativeRuntimeStartupError) throw error;
    throw new NativeRuntimeStartupError(
      "AUTHORITY_KEY_CONFIG_UNAVAILABLE",
      "Active Authority Control key configuration could not be restored"
    );
  }
  let authorityChannel: AuthorityControlIpcServer;
  try {
    authorityChannel = new AuthorityControlIpcServer({
      socketPath: authoritySocketPath,
      store: edgeKeyStore,
      authenticationKey: loaded.key.key,
      peerPolicy: authorityPeerPolicy
    });
  } catch {
    manager.dispose();
    throw new NativeRuntimeStartupError(
      "AUTHORITY_KEY_CONFIG_UNAVAILABLE",
      "Authority Control channel could not be constructed"
    );
  }
  // The server owns a defensive key copy and wipes it on close. The manager
  // must not retain a second live copy after startup assembly succeeds.
  manager.dispose();
  try {
    return await createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfig({
      ...baseOptions,
      socketPath,
      edgeKeyStore,
      operatorChannels: [...(baseOptions.operatorChannels ?? []), authorityChannel]
    });
  } catch (error) {
    await authorityChannel.close().catch(() => undefined);
    throw error;
  }
}

/**
 * Production startup assembly for the helper-to-Broker authority poll
 * channel. The Broker owns this listener and the final persisted authority
 * callback; the root helper receives only a separately authenticated client
 * endpoint and never reads BrokerStore directly.
 */
export async function createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfigAndPrivilegedHelperAuthority(
  options: Omit<MacOsNativeBrokerRuntimeOptions, "peerPolicy" | "broker"> & {
    edgeServiceId: string;
    expectedEdgeUid: number;
    expectedEdgeGid?: number;
    commandExecutor?: LaunchdIdentityCommandExecutor;
    edgeKeyConfigPath: string;
    edgeKeyStore: BrokerStore;
    createBroker: (edgeAuthenticationKeys: EdgeKeyring) => Broker;
    keychainDelivery?: {
      socketPath: string;
      keyId: string;
    };
    helperKeyConfigPath: string;
    helperAuthoritySocketPath: string;
    helperAuthorityPeerPolicy: NativePeerPolicy;
  }
): Promise<ReturnType<typeof createMacOsNativeBrokerRuntime>> {
  const {
    helperKeyConfigPath,
    helperAuthoritySocketPath,
    helperAuthorityPeerPolicy,
    edgeKeyStore,
    socketPath,
    ...baseOptions
  } = options;
  if (helperAuthoritySocketPath === socketPath) {
    throw new NativeRuntimeStartupError(
      "HELPER_AUTHORITY_CONFIG_UNAVAILABLE",
      "Privileged helper authority socket must be separate from the Broker IPC socket"
    );
  }
  if (helperAuthorityPeerPolicy.allowedProcessIdentity === undefined) {
    throw new NativeRuntimeStartupError(
      "HELPER_AUTHORITY_CONFIG_UNAVAILABLE",
      "Privileged helper authority startup requires an explicit native helper process identity"
    );
  }
  const helperKeyManager = new PrivilegedHelperKeyManager(helperKeyConfigPath, edgeKeyStore);
  let authorityChannel: import("./privileged-helper-authority-ipc.js").PrivilegedHelperAuthorityIpcServer;
  try {
    await helperKeyManager.restore();
    authorityChannel = helperKeyManager.createAuthorityServer({
      socketPath: helperAuthoritySocketPath,
      peerPolicy: helperAuthorityPeerPolicy,
      authorizeCommand: (command) => assertPrivilegedHelperCommandAuthority(edgeKeyStore, command)
    });
  } catch (error) {
    helperKeyManager.dispose();
    throw new NativeRuntimeStartupError(
      "HELPER_AUTHORITY_CONFIG_UNAVAILABLE",
      error instanceof Error ? error.message : "Active helper key configuration could not be restored"
    );
  }
  // The endpoint owns a defensive key copy and keeps only its activation
  // binding for revocation/rotation checks after the manager is disposed.
  helperKeyManager.dispose();
  try {
    return await createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfig({
      ...baseOptions,
      socketPath,
      edgeKeyStore,
      operatorChannels: [...(baseOptions.operatorChannels ?? []), authorityChannel]
    });
  } catch (error) {
    await authorityChannel.close().catch(() => undefined);
    throw error;
  }
}

export function parseLaunchdEdgeProcessReadback(
  serviceId: string,
  result: ProcessExecutionResult
): LaunchdEdgeProcessReadback {
  const service = parseEdgeServiceId(serviceId);
  if (result.resultClass !== "SUCCEEDED") {
    if (/Could not find service|No such process|service .* not found/iu.test(result.stderr)) {
      throw new NativeRuntimeStartupError("EDGE_SERVICE_UNAVAILABLE", "Edge launchd service is unavailable");
    }
    throw new NativeRuntimeStartupError("EDGE_SERVICE_UNAVAILABLE", "Edge launchd readback failed");
  }
  const header = new RegExp(`^${escapeRegExp(service.serviceId)}\\s*=\\s*\\{`, "mu");
  if (!header.test(result.stdout)) throw new NativeRuntimeStartupError("EDGE_SERVICE_UNAVAILABLE", "Edge launchd readback identity is mismatched");
  const state = /^\s*state\s*=\s*([^\r\n]+)/mu.exec(result.stdout)?.[1]?.trim();
  if (state !== "running") throw new NativeRuntimeStartupError("EDGE_PROCESS_NOT_RUNNING", "Edge launchd service is not running");
  const pidText = /^\s*pid\s*=\s*([0-9]+)/mu.exec(result.stdout)?.[1];
  const pid = pidText === undefined ? NaN : Number(pidText);
  if (!Number.isSafeInteger(pid) || pid < 1 || pid > 99_999_999) {
    throw new NativeRuntimeStartupError("EDGE_PROCESS_NOT_RUNNING", "Edge launchd service has no valid process identity");
  }
  return { ...service, pid, state: "running" };
}

function parseEdgeServiceId(serviceId: string, expectedUid?: number): { serviceId: string; uid: number; label: string } {
  const match = typeof serviceId === "string" ? EDGE_SERVICE_PATTERN.exec(serviceId) : null;
  if (!match) throw new NativeRuntimeStartupError("INVALID_EDGE_SERVICE", "Edge launchd service ID is invalid");
  const uid = Number(match[1]);
  if (expectedUid !== undefined && (!Number.isSafeInteger(expectedUid) || expectedUid < 1 || uid !== expectedUid)) {
    throw new NativeRuntimeStartupError("INVALID_EDGE_SERVICE", "Edge launchd service user does not match the expected user");
  }
  return { serviceId, uid, label: match[2]! };
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function isXpcProxyState(output: string): boolean {
  return /(?:^|\n)\s*state\s*=\s*xpcproxy\s*(?:\r?\n|$)/u.test(output);
}
