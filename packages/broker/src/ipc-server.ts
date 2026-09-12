import { chmod, lstat, stat, unlink } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { dirname } from "node:path";
import { BrokerError, type AuthenticatedBrokerResponse, type BrokerResult } from "@mac-operator/contracts";
import type { Broker } from "./broker.js";
import type { PeerCredentialVerifier } from "./peer-credentials.js";

export interface IpcServerOptions {
  socketPath: string;
  broker: Broker;
  peerCredentialVerifier: PeerCredentialVerifier;
  maxRequestBytes?: number;
}

export class BrokerIpcServer {
  private server: Server | undefined;
  private readonly maxRequestBytes: number;

  constructor(private readonly options: IpcServerOptions) {
    this.maxRequestBytes = options.maxRequestBytes ?? 1_048_576;
  }

  async listen(): Promise<void> {
    if (this.server) throw new Error("IPC server is already running");
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
    socket.on("data", async (chunk: Buffer) => {
      total += chunk.byteLength;
      if (total > this.maxRequestBytes) {
        writeResult(socket, failure("OUTPUT_LIMIT", "IPC request exceeded the byte limit"));
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      socket.pause();
      chunks = [];
      try {
        const request = JSON.parse(combined.subarray(0, newline).toString("utf8")) as unknown;
        writeResult(socket, await this.options.broker.handleForIpc(request));
      } catch {
        writeResult(socket, failure("AUTH_INVALID", "IPC request is not valid JSON"));
      }
    });
  }
}

function writeResult(socket: Socket, result: BrokerResult | AuthenticatedBrokerResponse): void {
  if (!socket.destroyed) socket.end(`${JSON.stringify(result)}\n`);
}

function failure(errorClass: "AUTH_INVALID" | "OUTPUT_LIMIT", message: string): BrokerResult {
  const error = new BrokerError(errorClass, message);
  return { ok: false, request_id: "invalid-request", tool: "unknown", result_class: error.errorClass, error: { message, retryable: false }, duration_ms: 0 };
}

export async function removeStaleSocket(path: string): Promise<void> {
  try {
    const stat = await lstat(path);
    if (!stat.isSocket()) throw new Error("Refusing to replace a non-socket IPC path");
    await unlink(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

export async function validateSocketParent(socketPath: string): Promise<void> {
  const parent = await stat(dirname(socketPath));
  const currentUid = process.getuid?.();
  if (currentUid === undefined || parent.uid !== currentUid) {
    throw new Error("IPC socket directory must be owned by the Broker user");
  }
  if ((parent.mode & 0o022) !== 0) {
    throw new Error("IPC socket directory must not be writable by group or other users");
  }
}
