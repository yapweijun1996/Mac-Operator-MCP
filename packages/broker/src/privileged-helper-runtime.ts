import { isAbsolute, resolve } from "node:path";
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
  | "HELPER_PEER_POLICY_INVALID";

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
