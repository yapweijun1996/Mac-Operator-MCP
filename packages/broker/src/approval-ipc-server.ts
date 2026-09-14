import { chmod } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { BrokerError, type ErrorClass } from "@mac-operator/contracts";
import type { ApprovalAuthority } from "./approval-authority.js";
import { MacOsNativePeerIpcServer, type NativePeerPolicy } from "./native-peer-ipc-server.js";
import { captureSocketPathIdentity, detachOwnedSocket, removeDetachedSocket, removeStaleSocket, validateSocketParent, type SocketPathIdentity } from "./ipc-server.js";

export interface ApprovalIpcServerOptions {
  socketPath: string;
  authority: ApprovalAuthority;
  peerCredentialVerifier?: { verify(socket: Socket): unknown };
  peerPolicy?: NativePeerPolicy;
  maxRequestBytes?: number;
  onError?: (error: unknown) => void;
}

export type ApprovalIpcResponse =
  | { ok: true; approval_id: string; expires_at_ms: number; revision: number }
  | { ok: false; result_class: ErrorClass; error: { message: string; retryable: boolean } };

/**
 * Separate local channel for operator-issued approvals. It is intentionally
 * not part of the remote MCP Edge and requires both OS peer credentials and
 * the ApprovalAuthority's signed issuer envelope.
 */
export class ApprovalIpcServer {
  private server: Server | undefined;
  private nativeTransport: MacOsNativePeerIpcServer | undefined;
  private socketIdentity: SocketPathIdentity | undefined;
  private readonly sockets = new Set<Socket>();
  private readonly maxRequestBytes: number;

  constructor(private readonly options: ApprovalIpcServerOptions) {
    if (!options.peerCredentialVerifier && !options.peerPolicy) {
      throw new Error("Approval IPC requires a peer verifier or native peer policy");
    }
    this.maxRequestBytes = options.maxRequestBytes ?? 1_048_576;
    if (!Number.isSafeInteger(this.maxRequestBytes) || this.maxRequestBytes < 1 || this.maxRequestBytes > 4 * 1024 * 1024) {
      throw new Error("Approval IPC request limit is invalid");
    }
  }

  async listen(): Promise<void> {
    if (this.server || this.nativeTransport) throw new Error("Approval IPC server is already running");
    if (this.options.peerPolicy) {
      this.nativeTransport = new MacOsNativePeerIpcServer({
        socketPath: this.options.socketPath,
        peerPolicy: this.options.peerPolicy,
        ...(this.options.onError === undefined ? {} : { onError: this.options.onError }),
        onSocket: (socket) => this.handleAuthenticatedSocket(socket)
      });
      try {
        await this.nativeTransport.listen();
      } catch (error) {
        this.nativeTransport = undefined;
        throw error;
      }
      return;
    }
    await validateSocketParent(this.options.socketPath);
    await removeStaleSocket(this.options.socketPath);
    this.server = createServer((socket) => {
      this.sockets.add(socket);
      socket.once("close", () => this.sockets.delete(socket));
      this.handleSocket(socket);
    });
    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(this.options.socketPath, resolve);
    });
    try {
      await chmod(this.options.socketPath, 0o600);
      this.socketIdentity = await captureSocketPathIdentity(this.options.socketPath);
    } catch (error) {
      await this.close().catch(() => undefined);
      throw error;
    }
  }

  async close(): Promise<void> {
    const nativeTransport = this.nativeTransport;
    this.nativeTransport = undefined;
    if (nativeTransport) {
      await nativeTransport.close();
      return;
    }
    const server = this.server;
    this.server = undefined;
    const socketIdentity = this.socketIdentity;
    this.socketIdentity = undefined;
    const detached = await detachOwnedSocket(this.options.socketPath, socketIdentity);
    try {
      for (const socket of this.sockets) socket.destroy();
      this.sockets.clear();
      if (server) await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    } finally {
      await removeDetachedSocket(detached);
    }
  }

  private handleSocket(socket: Socket): void {
    try {
      this.options.peerCredentialVerifier!.verify(socket);
    } catch {
      socket.destroy();
      return;
    }
    this.handleAuthenticatedSocket(socket);
  }

  private handleAuthenticatedSocket(socket: Socket): void {
    socket.setTimeout(15_000, () => socket.destroy());
    let chunks: Buffer[] = [];
    let total = 0;
    let handled = false;
    socket.on("data", (chunk: Buffer) => {
      if (handled) return;
      total += chunk.byteLength;
      if (total > this.maxRequestBytes) {
        handled = true;
        writeApprovalResponse(socket, failure("OUTPUT_LIMIT", "Approval IPC request exceeded the byte limit"));
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      handled = true;
      socket.pause();
      chunks = [];
      let response: ApprovalIpcResponse;
      try {
        const trailing = combined.subarray(newline + 1);
        if (trailing.some((byte) => !isAsciiWhitespace(byte))) {
          response = failure("PRECONDITION_FAILED", "Approval IPC request contains trailing data");
          writeApprovalResponse(socket, response);
          return;
        }
        const request = JSON.parse(combined.subarray(0, newline).toString("utf8")) as unknown;
        const approval = this.options.authority.issue(request);
        response = {
          ok: true,
          approval_id: approval.approvalId,
          expires_at_ms: approval.expiresAtMs,
          revision: approval.revision
        };
      } catch (error) {
        const brokerError = error instanceof BrokerError
          ? error
          : new BrokerError("PRECONDITION_FAILED", "Approval issuance request is invalid");
        response = failure(brokerError.errorClass, brokerError.message, brokerError.retryable);
      }
      writeApprovalResponse(socket, response);
    });
  }
}

function isAsciiWhitespace(byte: number): boolean {
  return byte === 0x09 || byte === 0x0a || byte === 0x0c || byte === 0x0d || byte === 0x20;
}

function writeApprovalResponse(socket: Socket, response: ApprovalIpcResponse): void {
  if (!socket.destroyed) socket.end(`${JSON.stringify(response)}\n`);
}

function failure(errorClass: ErrorClass, message: string, retryable = false): ApprovalIpcResponse {
  return { ok: false, result_class: errorClass, error: { message, retryable } };
}
