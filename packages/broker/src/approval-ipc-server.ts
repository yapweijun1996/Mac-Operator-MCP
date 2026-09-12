import { chmod, unlink } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { BrokerError, type ErrorClass } from "@mac-operator/contracts";
import type { ApprovalAuthority } from "./approval-authority.js";
import { removeStaleSocket, validateSocketParent } from "./ipc-server.js";

export interface ApprovalIpcServerOptions {
  socketPath: string;
  authority: ApprovalAuthority;
  peerCredentialVerifier: { verify(socket: Socket): unknown };
  maxRequestBytes?: number;
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
  private readonly maxRequestBytes: number;

  constructor(private readonly options: ApprovalIpcServerOptions) {
    this.maxRequestBytes = options.maxRequestBytes ?? 1_048_576;
    if (!Number.isSafeInteger(this.maxRequestBytes) || this.maxRequestBytes < 1 || this.maxRequestBytes > 4 * 1024 * 1024) {
      throw new Error("Approval IPC request limit is invalid");
    }
  }

  async listen(): Promise<void> {
    if (this.server) throw new Error("Approval IPC server is already running");
    await validateSocketParent(this.options.socketPath);
    await removeStaleSocket(this.options.socketPath);
    this.server = createServer((socket) => this.handleSocket(socket));
    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(this.options.socketPath, resolve);
    });
    await chmod(this.options.socketPath, 0o600);
  }

  async close(): Promise<void> {
    const server = this.server;
    this.server = undefined;
    if (server) await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    try { await unlink(this.options.socketPath); } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }

  private handleSocket(socket: Socket): void {
    try {
      this.options.peerCredentialVerifier.verify(socket);
    } catch {
      socket.destroy();
      return;
    }
    socket.setTimeout(15_000, () => socket.destroy());
    let chunks: Buffer[] = [];
    let total = 0;
    socket.on("data", (chunk: Buffer) => {
      total += chunk.byteLength;
      if (total > this.maxRequestBytes) {
        writeApprovalResponse(socket, failure("OUTPUT_LIMIT", "Approval IPC request exceeded the byte limit"));
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      socket.pause();
      chunks = [];
      let response: ApprovalIpcResponse;
      try {
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

function writeApprovalResponse(socket: Socket, response: ApprovalIpcResponse): void {
  if (!socket.destroyed) socket.end(`${JSON.stringify(response)}\n`);
}

function failure(errorClass: ErrorClass, message: string, retryable = false): ApprovalIpcResponse {
  return { ok: false, result_class: errorClass, error: { message, retryable } };
}
