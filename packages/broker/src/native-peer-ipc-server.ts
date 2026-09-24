import { lstat } from "node:fs/promises";
import { Socket } from "node:net";
import { dirname, isAbsolute, resolve } from "node:path";
import { captureSocketPathIdentity, removeStaleSocket, unlinkOwnedSocket, validateSocketParent, type SocketPathIdentity } from "./ipc-server.js";
import {
  authorizePeerCredentials,
  loadNativePeerAdapter,
  parsePeerCredentials,
  parsePeerProcessIdentity,
  type PeerCredentialPolicy,
  type PeerProcessIdentity,
  type PeerCredentials
} from "./peer-credentials.js";
import { validateGroupSocketParentChain, validateUserAclSocketParentChain } from "./owner-socket-path.js";

interface NativeUnixPeerAdapter {
  createUnixListener(path: string, backlog: number, peerGroupId?: number, peerUserId?: number): number;
  getUnixSocketAclPeerUid(path: string): unknown;
  hasExtendedAclEntries(path: string): unknown;
  acceptUnixClient(descriptor: number): unknown;
  closeUnixDescriptor(descriptor: number): void;
  getProcessIdentity(pid: number): unknown;
}

export interface NativePeerIpcServerOptions {
  socketPath: string;
  peerPolicy: NativePeerPolicy;
  /** Optional group access for a root-owned listener serving one Broker GID. */
  socketGroupGid?: number;
  /** Optional exact-user ACL access for a root-owned listener serving one Broker UID. */
  socketPeerUid?: number;
  backlog?: number;
  pollIntervalMs?: number;
  peerIdentityMonitorIntervalMs?: number;
  onSocket: (socket: Socket, credentials: PeerCredentials) => void;
  onError?: (error: unknown) => void;
  onPeerIdentityLost?: (identity: PeerProcessIdentity) => void;
}

export type NativePeerPolicy = PeerCredentialPolicy;

/**
 * Shared macOS-native UDS accept boundary for Broker-owned local channels.
 * Peer identity is checked before a request handler sees the socket.
 */
export class MacOsNativePeerIpcServer {
  private readonly native: NativeUnixPeerAdapter;
  private readonly backlog: number;
  private readonly pollIntervalMs: number;
  private readonly peerIdentityMonitorIntervalMs: number;
  private listenerFd: number | undefined;
  private socketIdentity: SocketPathIdentity | undefined;
  private acceptLoopPromise: Promise<void> | undefined;
  private peerIdentityMonitor: NodeJS.Timeout | undefined;
  private peerIdentityFailure: Promise<void> | undefined;
  private readonly sockets = new Set<Socket>();

  constructor(private readonly options: NativePeerIpcServerOptions) {
    this.native = loadNativePeerAdapter();
    this.backlog = options.backlog ?? 16;
    this.pollIntervalMs = options.pollIntervalMs ?? 10;
    this.peerIdentityMonitorIntervalMs = options.peerIdentityMonitorIntervalMs ?? 250;
    if (
      !Number.isSafeInteger(this.backlog) || this.backlog < 1 || this.backlog > 128 ||
      !Number.isSafeInteger(this.pollIntervalMs) || this.pollIntervalMs < 1 || this.pollIntervalMs > 1_000 ||
      !Number.isSafeInteger(this.peerIdentityMonitorIntervalMs) || this.peerIdentityMonitorIntervalMs < 25 || this.peerIdentityMonitorIntervalMs > 10_000
    ) {
      throw new Error("Native peer IPC limits are invalid");
    }
    if (options.socketGroupGid !== undefined &&
        (!Number.isSafeInteger(options.socketGroupGid) || options.socketGroupGid < 0 || options.socketGroupGid > 2_147_483_647 ||
         !Number.isSafeInteger(options.peerPolicy.expectedUid) || options.peerPolicy.expectedUid < 1 || options.peerPolicy.expectedUid > 2_147_483_647 ||
         options.peerPolicy.expectedGid !== options.socketGroupGid || options.socketPeerUid !== undefined)) {
      throw new Error("Native peer IPC socket group must match the authenticated peer group");
    }
    if (options.socketPeerUid !== undefined &&
        (!Number.isSafeInteger(options.socketPeerUid) || options.socketPeerUid < 1 || options.socketPeerUid > 2_147_483_647 ||
         options.socketPeerUid !== options.peerPolicy.expectedUid)) {
      throw new Error("Native peer IPC socket user ACL must match the authenticated peer user");
    }
    if (options.peerPolicy.allowedProcessIdentity !== undefined) {
      validatePeerIdentity(options.peerPolicy.allowedProcessIdentity);
    }
  }

  async listen(): Promise<void> {
    if (this.listenerFd !== undefined) throw new Error("Native peer IPC server is already running");
    assertNativeSocketPath(this.options.socketPath);
    if (this.options.socketGroupGid === undefined && this.options.socketPeerUid === undefined) {
      await validateSocketParent(this.options.socketPath);
    } else if (this.options.socketGroupGid !== undefined) {
      const ownerUid = process.geteuid?.();
      if (ownerUid === undefined || !Number.isSafeInteger(ownerUid) || ownerUid < 0) {
        throw new Error("Group-access native peer IPC requires a POSIX effective owner identity");
      }
      await validateGroupSocketParentChain(
        this.options.socketPath,
        ownerUid,
        this.options.peerPolicy.expectedUid,
        this.options.socketGroupGid
      );
    } else {
      const ownerUid = process.geteuid?.();
      const ownerGid = process.getegid?.();
      if (ownerUid === undefined || ownerGid === undefined || !Number.isSafeInteger(ownerUid) || ownerUid < 0 ||
          !Number.isSafeInteger(ownerGid) || ownerGid < 0) {
        throw new Error("User-ACL native peer IPC requires POSIX effective owner identities");
      }
      await validateUserAclSocketParentChain(
        this.options.socketPath,
        ownerUid,
        ownerUid === 0 ? 0 : ownerGid,
        this.options.socketPeerUid!,
        this.options.peerPolicy.expectedGid ?? process.getgid?.() ?? ownerGid,
        (path) => {
          const result = this.native.hasExtendedAclEntries(path);
          if (result !== false) throw new Error("Native path ACL readback is invalid");
          return false;
        }
      );
    }
    await removeStaleSocket(this.options.socketPath);
    this.assertExpectedPeerIdentity();
    this.peerIdentityFailure = undefined;
    const descriptor = this.native.createUnixListener(
      this.options.socketPath,
      this.backlog,
      ...(this.options.socketGroupGid !== undefined ? [this.options.socketGroupGid] :
        this.options.socketPeerUid !== undefined ? [undefined, this.options.socketPeerUid] : [])
    );
    this.listenerFd = descriptor;
    let createdSocketIdentity: SocketPathIdentity | undefined;
    try {
      createdSocketIdentity = await captureSocketPathIdentity(this.options.socketPath);
      const socket = await lstat(this.options.socketPath);
      const ownerUid = process.geteuid?.();
      const ownerGid = this.options.socketGroupGid ??
        (this.options.socketPeerUid !== undefined && ownerUid === 0 ? 0 : process.getegid?.());
      const expectedMode = this.options.socketGroupGid === undefined ? 0o600 : 0o620;
      if (ownerUid === undefined || !socket.isSocket() || socket.isSymbolicLink() || socket.uid !== ownerUid ||
          (ownerGid !== undefined && socket.gid !== ownerGid) || (socket.mode & 0o777) !== expectedMode) {
        throw new Error("Native peer IPC listener socket ownership or mode is invalid");
      }
      if (this.options.socketPeerUid !== undefined &&
          this.native.getUnixSocketAclPeerUid(this.options.socketPath) !== this.options.socketPeerUid) {
        throw new Error("Native peer IPC listener user ACL does not match the authenticated peer");
      }
      this.socketIdentity = createdSocketIdentity;
    } catch (error) {
      this.listenerFd = undefined;
      this.native.closeUnixDescriptor(descriptor);
      this.socketIdentity = undefined;
      await unlinkOwnedSocket(this.options.socketPath, createdSocketIdentity).catch(() => undefined);
      throw error;
    }
    this.acceptLoopPromise = this.acceptLoop();
    this.startPeerIdentityMonitor();
  }

  async close(): Promise<void> {
    this.stopPeerIdentityMonitor();
    const peerIdentityFailure = this.peerIdentityFailure;
    if (peerIdentityFailure) await peerIdentityFailure;
    const descriptor = this.listenerFd;
    this.listenerFd = undefined;
    const socketIdentity = this.socketIdentity;
    this.socketIdentity = undefined;
    if (descriptor !== undefined) this.native.closeUnixDescriptor(descriptor);
    const loop = this.acceptLoopPromise;
    this.acceptLoopPromise = undefined;
    if (loop) await loop;
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    await unlinkOwnedSocket(this.options.socketPath, socketIdentity);
  }

  private async acceptLoop(): Promise<void> {
    while (this.listenerFd !== undefined) {
      const descriptor = this.listenerFd;
      try {
        const accepted = parseAcceptedClient(this.native.acceptUnixClient(descriptor));
        if (accepted) this.handleAccepted(accepted);
        else await delay(this.pollIntervalMs);
      } catch (error) {
        if (this.listenerFd === undefined) return;
        await this.failClosed(error);
        return;
      }
    }
  }

  private handleAccepted(accepted: AcceptedUnixClient): void {
    let socket: Socket | undefined;
    try {
      authorizePeerCredentials(
        accepted.credentials,
        this.options.peerPolicy,
        (pid) => this.native.getProcessIdentity(pid)
      );
      const acceptedSocket = new Socket({ fd: accepted.fd, readable: true, writable: true });
      socket = acceptedSocket;
      this.sockets.add(acceptedSocket);
      acceptedSocket.once("close", () => this.sockets.delete(acceptedSocket));
      this.options.onSocket(acceptedSocket, accepted.credentials);
    } catch {
      if (socket) socket.destroy();
      else this.native.closeUnixDescriptor(accepted.fd);
    }
  }

  private async failClosed(error: unknown): Promise<void> {
    const descriptor = this.listenerFd;
    this.listenerFd = undefined;
    const socketIdentity = this.socketIdentity;
    this.socketIdentity = undefined;
    if (descriptor !== undefined) this.native.closeUnixDescriptor(descriptor);
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    await unlinkOwnedSocket(this.options.socketPath, socketIdentity).catch(() => undefined);
    try { this.options.onError?.(error); } catch { /* caller errors cannot reopen the listener */ }
  }

  private startPeerIdentityMonitor(): void {
    const expected = this.options.peerPolicy.allowedProcessIdentity;
    if (expected === undefined) return;
    const check = () => {
      this.peerIdentityMonitor = undefined;
      if (this.listenerFd === undefined || this.peerIdentityFailure !== undefined) return;
      try {
        this.assertExpectedPeerIdentity();
        this.peerIdentityMonitor = setTimeout(check, this.peerIdentityMonitorIntervalMs);
        this.peerIdentityMonitor.unref?.();
      } catch (error) {
        this.peerIdentityFailure = this.failClosed(error).then(() => {
          try {
            this.options.onPeerIdentityLost?.(expected);
          } catch (callbackError) {
            try { this.options.onError?.(callbackError); } catch { /* callback errors cannot reopen the listener */ }
          }
        });
      }
    };
    check();
  }

  private assertExpectedPeerIdentity(): void {
    const expected = this.options.peerPolicy.allowedProcessIdentity;
    if (expected === undefined) return;
    let observed: PeerProcessIdentity;
    try {
      observed = parsePeerProcessIdentity(this.native.getProcessIdentity(expected.pid));
    } catch {
      throw new Error("Native peer process identity is unavailable");
    }
    if (observed.pid !== expected.pid || observed.startTimeMicros !== expected.startTimeMicros) {
      throw new Error("Native peer process identity changed");
    }
  }

  private stopPeerIdentityMonitor(): void {
    if (this.peerIdentityMonitor) clearTimeout(this.peerIdentityMonitor);
    this.peerIdentityMonitor = undefined;
  }
}

interface AcceptedUnixClient {
  fd: number;
  credentials: PeerCredentials;
}

function parseAcceptedClient(value: unknown): AcceptedUnixClient | undefined {
  if (value === null) return undefined;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Native Unix accept result is malformed");
  }
  const record = value as Record<string, unknown>;
  if (!Number.isSafeInteger(record.fd) || (record.fd as number) < 0) {
    throw new Error("Native Unix accept descriptor is malformed");
  }
  return { fd: record.fd as number, credentials: parsePeerCredentials(value) };
}

export function assertNativeSocketPath(socketPath: string): void {
  if (typeof socketPath !== "string" || !isAbsolute(socketPath) || resolve(socketPath) !== socketPath || socketPath.includes("\0")) {
    throw new Error("Native peer IPC socket path must be canonical and absolute");
  }
  if (Buffer.byteLength(socketPath, "utf8") >= 104) throw new Error("Native peer IPC socket path is too long");
  if (dirname(socketPath) === socketPath) throw new Error("Native peer IPC socket path must name a file");
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

function validatePeerIdentity(identity: PeerProcessIdentity): void {
  if (!Number.isSafeInteger(identity.pid) || identity.pid < 1 || identity.pid > 99_999_999 ||
      !Number.isSafeInteger(identity.startTimeMicros) || identity.startTimeMicros < 1) {
    throw new Error("Native peer process identity is invalid");
  }
}
