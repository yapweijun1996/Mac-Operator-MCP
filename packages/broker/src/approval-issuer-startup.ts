import type { Socket } from "node:net";
import { ApprovalAuthority } from "./approval-authority.js";
import { ApprovalIpcServer } from "./approval-ipc-server.js";
import { ApprovalIssuerKeyManager } from "./approval-keyring.js";
import type { BrokerStore } from "./persistence.js";
import type { NativePeerPolicy } from "./native-peer-ipc-server.js";

export interface ApprovalIssuerStartupOptions {
  /** Disabled unless the packaged startup explicitly opts in. */
  enabled?: boolean;
  /** Broker-owned, protected, activated issuer-key metadata. */
  keyConfigPath?: string;
  /** Separate owner-only approval socket; never the Broker IPC socket. */
  socketPath?: string;
  /** macOS native peer credentials for the owner-side local channel. */
  peerPolicy?: NativePeerPolicy;
  /** Test or non-native transport seam; production uses peerPolicy. */
  peerCredentialVerifier?: { verify(socket: Socket): unknown };
  maxRequestBytes?: number;
}

export interface ApprovalIssuerRuntimeAssembly {
  readonly authority: ApprovalAuthority;
  readonly keyManager: ApprovalIssuerKeyManager;
  readonly channel: ApprovalIpcServer;
  close(): Promise<void>;
}

/**
 * Restores and assembles the owner-only approval issuer without activating
 * new key material. The returned channel is a LocalBrokerRuntime operator
 * channel and remains stopped until that runtime starts.
 */
export async function createApprovalIssuerRuntime(options: {
  store: BrokerStore;
  startup: ApprovalIssuerStartupOptions;
  now?: () => number;
}): Promise<ApprovalIssuerRuntimeAssembly | undefined> {
  if (!options || typeof options !== "object" || !options.store || !options.startup || typeof options.startup !== "object") {
    throw new Error("Approval issuer startup options are malformed");
  }
  const startup = options.startup;
  if (startup.enabled !== true) return undefined;
  const keyConfigPath = startup.keyConfigPath;
  const socketPath = startup.socketPath;
  if (typeof keyConfigPath !== "string" || typeof socketPath !== "string") {
    throw new Error("Enabled approval issuer startup requires a key config and socket path");
  }
  if ((startup.peerPolicy === undefined) === (startup.peerCredentialVerifier === undefined)) {
    throw new Error("Approval issuer startup requires exactly one peer authentication boundary");
  }
  const now = options.now ?? Date.now;
  const keyManager = new ApprovalIssuerKeyManager(keyConfigPath, options.store, now);
  let authority: ApprovalAuthority | undefined;
  let channel: ApprovalIpcServer | undefined;
  try {
    const loaded = await keyManager.restore();
    authority = new ApprovalAuthority(options.store, loaded.keys, { now });
    channel = new ApprovalIpcServer({
      socketPath,
      authority,
      ...(startup.peerPolicy === undefined ? {} : { peerPolicy: startup.peerPolicy }),
      ...(startup.peerCredentialVerifier === undefined ? {} : { peerCredentialVerifier: startup.peerCredentialVerifier }),
      ...(startup.maxRequestBytes === undefined ? {} : { maxRequestBytes: startup.maxRequestBytes })
    });
    const assembledAuthority = authority;
    const assembledChannel = channel;
    return {
      authority: assembledAuthority,
      keyManager,
      channel: assembledChannel,
      async close() {
        let firstError: unknown;
        try { await assembledChannel.close(); } catch (error) { firstError = error; }
        try { assembledAuthority.dispose(); } catch (error) { firstError ??= error; }
        try { keyManager.dispose(); } catch (error) { firstError ??= error; }
        if (firstError !== undefined) throw firstError;
      }
    };
  } catch (error) {
    try { channel && await channel.close(); } catch { /* preserve startup error */ }
    try { authority?.dispose(); } catch { /* preserve startup error */ }
    keyManager.dispose();
    throw error;
  }
}
