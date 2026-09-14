import { lstat, realpath } from "node:fs/promises";
import { createConnection, type Socket } from "node:net";
import { dirname, isAbsolute, resolve } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import {
  authorizePeerCredentials,
  loadNativePeerAdapter,
  parsePeerCredentials,
  type PeerCredentialPolicy
} from "./peer-credentials.js";
import type { VirtualizationGuestChannel } from "./virtualization-guest-transport.js";

const MAX_SOCKET_PATH_BYTES = 4_096;
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_FRAME_BYTES = 4 * 1024 * 1024;
const MIN_FRAME_BYTES = 1;

interface SocketWithHandle extends Socket {
  _handle?: { fd?: unknown };
}

interface SocketIdentity {
  dev: number;
  ino: number;
}

export interface VirtualizationGuestChannelOptions {
  /** Broker-owned startup path; MCP arguments never select this socket. */
  socketPath: string;
  /** The native adapter process identity expected on the connected socket. */
  peerPolicy: PeerCredentialPolicy;
  timeoutMs?: number;
  maxFrameBytes?: number;
}

/**
 * Bounded Broker-side channel for a separately authenticated native guest
 * adapter. The adapter owns VM/virtio details; this channel only transports
 * one length-prefixed frame per authenticated Unix connection.
 */
export class MacOsVirtualizationGuestChannel implements VirtualizationGuestChannel {
  private readonly socketPath: string;
  private readonly peerPolicy: PeerCredentialPolicy;
  private readonly timeoutMs: number;
  private readonly maxFrameBytes: number;
  private readonly activeSockets = new Set<Socket>();
  private closed = false;

  constructor(options: VirtualizationGuestChannelOptions) {
    validateOptions(options);
    this.socketPath = options.socketPath;
    this.peerPolicy = { ...options.peerPolicy };
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxFrameBytes = options.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES;
  }

  async exchange(frame: Uint8Array, signal: AbortSignal): Promise<Uint8Array> {
    if (process.platform !== "darwin") {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest channel requires macOS");
    }
    if (this.closed) throw new BrokerError("POLICY_DENIED", "Virtualization guest channel is closed");
    if (!(frame instanceof Uint8Array) || frame.byteLength < MIN_FRAME_BYTES || frame.byteLength > this.maxFrameBytes) {
      throw new BrokerError("OUTPUT_LIMIT", "Virtualization guest request frame exceeded the byte limit");
    }
    if (signal.aborted) throw new BrokerError("CANCELLED", "Virtualization guest channel request was cancelled");

    const expectedIdentity = await validateVirtualizationGuestSocketTarget(this.socketPath);
    let native: ReturnType<typeof loadNativePeerAdapter>;
    try {
      native = loadNativePeerAdapter();
    } catch {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest channel native peer verifier is unavailable");
    }

    return new Promise<Uint8Array>((resolvePromise, rejectPromise) => {
      const socket = createConnection(this.socketPath);
      this.activeSockets.add(socket);
      let settled = false;
      let requestSent = false;
      let expectedResponseBytes: number | undefined;
      let received = Buffer.alloc(0);

      const finish = (error?: BrokerError, value?: Uint8Array): void => {
        if (settled) return;
        settled = true;
        this.activeSockets.delete(socket);
        signal.removeEventListener("abort", onAbort);
        socket.destroy();
        if (error !== undefined) rejectPromise(error);
        else resolvePromise(value ?? new Uint8Array());
      };

      const onAbort = (): void => {
        finish(new BrokerError("CANCELLED", "Virtualization guest channel request was cancelled"));
      };

      const failTransport = (): void => {
        finish(requestSent
          ? new BrokerError("UNKNOWN_OUTCOME", "Virtualization guest adapter outcome could not be established", true)
          : new BrokerError("EXECUTION_FAILED", "Virtualization guest adapter connection failed", true));
      };

      signal.addEventListener("abort", onAbort, { once: true });
      socket.setTimeout(this.timeoutMs, () => finish(new BrokerError("TIMEOUT", "Virtualization guest adapter channel timed out", true)));
      socket.on("connect", () => {
        void revalidateConnectedSocket(this.socketPath, expectedIdentity)
          .then(() => authenticatePeer(socket, native, this.peerPolicy))
          .then(() => {
            if (settled) return;
            const header = Buffer.allocUnsafe(4);
            header.writeUInt32BE(frame.byteLength, 0);
            requestSent = true;
            socket.write(Buffer.concat([header, Buffer.from(frame)]));
          })
          .catch(() => finish(new BrokerError("AUTH_INVALID", "Virtualization guest adapter socket identity is not authorized")));
      });
      socket.on("data", (chunk: Buffer) => {
        if (settled) return;
        received = Buffer.concat([received, chunk]);
        if (received.byteLength > this.maxFrameBytes + 4) {
          finish(new BrokerError("OUTPUT_LIMIT", "Virtualization guest adapter response exceeded the byte limit"));
          return;
        }
        if (expectedResponseBytes === undefined && received.byteLength >= 4) {
          expectedResponseBytes = received.readUInt32BE(0);
          if (expectedResponseBytes < MIN_FRAME_BYTES || expectedResponseBytes > this.maxFrameBytes) {
            finish(new BrokerError("OUTPUT_LIMIT", "Virtualization guest adapter response frame exceeded the byte limit"));
            return;
          }
        }
        if (expectedResponseBytes !== undefined && received.byteLength >= expectedResponseBytes + 4) {
          if (received.byteLength !== expectedResponseBytes + 4) {
            finish(new BrokerError("PRECONDITION_FAILED", "Virtualization guest adapter returned trailing frame data"));
            return;
          }
          finish(undefined, received.subarray(4));
        }
      });
      socket.on("end", () => {
        if (!settled) failTransport();
      });
      socket.on("error", () => {
        if (!settled) failTransport();
      });
      if (signal.aborted) onAbort();
    });
  }

  close(): void {
    this.closed = true;
    for (const socket of this.activeSockets) socket.destroy();
    this.activeSockets.clear();
  }
}

export async function validateVirtualizationGuestSocketTarget(socketPath: string): Promise<SocketIdentity> {
  if (process.platform !== "darwin") {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest channel requires macOS");
  }
  if (!isAbsolute(socketPath) || resolve(socketPath) !== socketPath || socketPath.includes("\0") || Buffer.byteLength(socketPath, "utf8") > MAX_SOCKET_PATH_BYTES) {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest channel socket path is not canonical");
  }
  const parentPath = dirname(socketPath);
  const parent = await lstat(parentPath).catch(() => undefined);
  const currentUid = process.getuid?.();
  if (!parent || !parent.isDirectory() || parent.isSymbolicLink() || currentUid === undefined || parent.uid !== currentUid || (parent.mode & 0o077) !== 0) {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest channel socket directory is not protected");
  }
  const canonicalParent = await realpath(parentPath).catch(() => undefined);
  if (canonicalParent === undefined) throw new BrokerError("POLICY_DENIED", "Virtualization guest channel socket directory is unavailable");
  const canonicalParentStat = await lstat(canonicalParent).catch(() => undefined);
  if (!canonicalParentStat || !canonicalParentStat.isDirectory() || canonicalParentStat.isSymbolicLink() ||
      canonicalParentStat.dev !== parent.dev || canonicalParentStat.ino !== parent.ino) {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest channel socket directory changed while canonicalizing");
  }
  const socket = await lstat(socketPath).catch(() => undefined);
  if (!socket || !socket.isSocket() || socket.isSymbolicLink() || socket.uid !== currentUid || (socket.mode & 0o177) !== 0) {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest channel socket is not protected");
  }
  return { dev: socket.dev, ino: socket.ino };
}

function validateOptions(options: VirtualizationGuestChannelOptions): void {
  if (options === null || typeof options !== "object" ||
      typeof options.socketPath !== "string" || !isAbsolute(options.socketPath) || resolve(options.socketPath) !== options.socketPath || options.socketPath.includes("\0") ||
      options.peerPolicy === null || typeof options.peerPolicy !== "object" ||
      !Number.isSafeInteger(options.peerPolicy.expectedUid) || options.peerPolicy.expectedUid < 0 ||
      (options.peerPolicy.expectedGid !== undefined && (!Number.isSafeInteger(options.peerPolicy.expectedGid) || options.peerPolicy.expectedGid < 0)) ||
      (options.timeoutMs !== undefined && (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1 || options.timeoutMs > 120_000)) ||
      (options.maxFrameBytes !== undefined && (!Number.isSafeInteger(options.maxFrameBytes) || options.maxFrameBytes < 256 || options.maxFrameBytes > DEFAULT_MAX_FRAME_BYTES))) {
    throw new Error("Virtualization guest channel options are invalid");
  }
}

async function revalidateConnectedSocket(socketPath: string, expected: SocketIdentity): Promise<void> {
  const current = await lstat(socketPath).catch(() => undefined);
  if (!current || !current.isSocket() || current.isSymbolicLink() || current.dev !== expected.dev || current.ino !== expected.ino) {
    throw new Error("Virtualization guest channel socket target changed while connecting");
  }
}

function authenticatePeer(
  socket: Socket,
  native: ReturnType<typeof loadNativePeerAdapter>,
  policy: PeerCredentialPolicy
): void {
  const descriptor = (socket as SocketWithHandle)._handle?.fd;
  if (!Number.isSafeInteger(descriptor) || (descriptor as number) < 0) throw new Error("Connected socket descriptor is unavailable");
  const credentials = parsePeerCredentials(native.getPeerCredentials(descriptor as number));
  authorizePeerCredentials(credentials, policy, policy.allowedProcessIdentity === undefined
    ? undefined
    : (pid) => native.getProcessIdentity(pid));
}
