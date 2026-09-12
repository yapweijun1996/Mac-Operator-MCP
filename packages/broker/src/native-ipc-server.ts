import { chmod, unlink } from "node:fs/promises";
import { Socket } from "node:net";
import { dirname, isAbsolute, resolve } from "node:path";
import { Broker } from "./broker.js";
import { handleBrokerSocket, removeStaleSocket, validateSocketParent } from "./ipc-server.js";
import {
  authorizePeerCredentials,
  loadNativePeerAdapter,
  parsePeerCredentials,
  type PeerCredentials
} from "./peer-credentials.js";

interface NativeUnixPeerAdapter {
  createUnixListener(path: string, backlog: number): number;
  acceptUnixClient(descriptor: number): unknown;
  closeUnixDescriptor(descriptor: number): void;
}

interface AcceptedUnixClient {
  fd: number;
  credentials: PeerCredentials;
}

export interface NativeBrokerIpcServerOptions {
  socketPath: string;
  broker: Broker;
  peerPolicy: {
    expectedUid: number;
    expectedGid?: number;
    allowedProcessIds?: ReadonlySet<number>;
  };
  maxRequestBytes?: number;
  backlog?: number;
  pollIntervalMs?: number;
  onError?: (error: unknown) => void;
}

/**
 * macOS-native UDS accept boundary. Native code owns accept and peer lookup;
 * accepted descriptors are handed to Node through the public Socket({ fd })
 * constructor, so the Broker does not inspect Node's private socket handle.
 */
export class MacOsNativeBrokerIpcServer {
  private readonly native: NativeUnixPeerAdapter;
  private readonly maxRequestBytes: number;
  private readonly backlog: number;
  private readonly pollIntervalMs: number;
  private listenerFd: number | undefined;
  private acceptLoopPromise: Promise<void> | undefined;
  private readonly sockets = new Set<Socket>();

  constructor(private readonly options: NativeBrokerIpcServerOptions) {
    if (process.platform !== "darwin") throw new Error("Native Broker IPC requires macOS");
    this.native = loadNativePeerAdapter();
    this.maxRequestBytes = options.maxRequestBytes ?? 1_048_576;
    this.backlog = options.backlog ?? 16;
    this.pollIntervalMs = options.pollIntervalMs ?? 10;
    if (!Number.isSafeInteger(this.maxRequestBytes) || this.maxRequestBytes < 256 || this.maxRequestBytes > 4 * 1024 * 1024 ||
        !Number.isSafeInteger(this.backlog) || this.backlog < 1 || this.backlog > 128 ||
        !Number.isSafeInteger(this.pollIntervalMs) || this.pollIntervalMs < 1 || this.pollIntervalMs > 1_000) {
      throw new Error("Native Broker IPC limits are invalid");
    }
  }

  async listen(): Promise<void> {
    if (this.listenerFd !== undefined) throw new Error("Native Broker IPC server is already running");
    assertSocketPath(this.options.socketPath);
    await validateSocketParent(this.options.socketPath);
    await removeStaleSocket(this.options.socketPath);
    const descriptor = this.native.createUnixListener(this.options.socketPath, this.backlog);
    this.listenerFd = descriptor;
    try {
      await chmod(this.options.socketPath, 0o600);
    } catch (error) {
      this.listenerFd = undefined;
      this.native.closeUnixDescriptor(descriptor);
      await unlink(this.options.socketPath).catch(() => undefined);
      throw error;
    }
    this.acceptLoopPromise = this.acceptLoop();
  }

  async close(): Promise<void> {
    const descriptor = this.listenerFd;
    this.listenerFd = undefined;
    if (descriptor !== undefined) this.native.closeUnixDescriptor(descriptor);
    const loop = this.acceptLoopPromise;
    this.acceptLoopPromise = undefined;
    if (loop) await loop;
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    try { await unlink(this.options.socketPath); } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
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
      authorizePeerCredentials(accepted.credentials, this.options.peerPolicy);
      const acceptedSocket = new Socket({ fd: accepted.fd, readable: true, writable: true });
      socket = acceptedSocket;
      this.sockets.add(acceptedSocket);
      acceptedSocket.once("close", () => this.sockets.delete(acceptedSocket));
      handleBrokerSocket(acceptedSocket, this.options.broker, this.maxRequestBytes);
    } catch {
      if (socket) socket.destroy();
      else this.native.closeUnixDescriptor(accepted.fd);
    }
  }

  private async failClosed(error: unknown): Promise<void> {
    const descriptor = this.listenerFd;
    this.listenerFd = undefined;
    if (descriptor !== undefined) this.native.closeUnixDescriptor(descriptor);
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    try { await unlink(this.options.socketPath); } catch { /* fail-closed cleanup is best effort */ }
    try { this.options.onError?.(error); } catch { /* caller errors cannot reopen the listener */ }
  }
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

function assertSocketPath(socketPath: string): void {
  if (typeof socketPath !== "string" || !isAbsolute(socketPath) || resolve(socketPath) !== socketPath || socketPath.includes("\0")) {
    throw new Error("Native Broker IPC socket path must be canonical and absolute");
  }
  if (Buffer.byteLength(socketPath, "utf8") >= 104) throw new Error("Native Broker IPC socket path is too long");
  if (dirname(socketPath) === socketPath) throw new Error("Native Broker IPC socket path must name a file");
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}
