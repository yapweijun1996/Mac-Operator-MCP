import { chmod, lstat, rename, stat, symlink, unlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { dirname, join } from "node:path";
import { BrokerError, type AuthenticatedBrokerResponse, type BrokerResult } from "@mac-operator/contracts";
import type { Broker } from "./broker.js";
import type { PeerCredentialVerifier } from "./peer-credentials.js";

export interface IpcServerOptions {
  socketPath: string;
  broker: Broker;
  peerCredentialVerifier: PeerCredentialVerifier;
  maxRequestBytes?: number;
}

export interface SocketPathIdentity {
  device: number;
  inode: number;
}

export interface DetachedSocketPath {
  path: string;
  identity: SocketPathIdentity;
}

export class BrokerIpcServer {
  private server: Server | undefined;
  private socketIdentity: SocketPathIdentity | undefined;
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
    try {
      await chmod(this.options.socketPath, 0o600);
      this.socketIdentity = await captureSocketPathIdentity(this.options.socketPath);
    } catch (error) {
      await this.close().catch(() => undefined);
      throw error;
    }
  }

  async close(): Promise<void> {
    const server = this.server;
    this.server = undefined;
    const socketIdentity = this.socketIdentity;
    this.socketIdentity = undefined;
    const detached = await detachOwnedSocket(this.options.socketPath, socketIdentity);
    try {
      if (server) await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    } finally {
      await removeDetachedSocket(detached);
    }
  }

  private handleSocket(socket: Socket): void {
    try {
      this.options.peerCredentialVerifier.verify(socket);
    } catch {
      socket.destroy();
      return;
    }
    handleBrokerSocket(socket, this.options.broker, this.maxRequestBytes);
  }
}

/** Handles an already peer-authenticated socket for both Node and native UDS transports. */
export function handleBrokerSocket(socket: Socket, broker: Broker, maxRequestBytes: number): void {
  socket.setTimeout(15_000, () => socket.destroy());
  let chunks: Buffer[] = [];
  let total = 0;
  let handled = false;
  socket.on("data", async (chunk: Buffer) => {
    if (handled) return;
    total += chunk.byteLength;
    if (total > maxRequestBytes) {
      handled = true;
      writeResult(socket, failure("OUTPUT_LIMIT", "IPC request exceeded the byte limit"));
      return;
    }
    chunks.push(chunk);
    const combined = Buffer.concat(chunks);
    const newline = combined.indexOf(0x0a);
    if (newline === -1) return;
    handled = true;
    socket.pause();
    chunks = [];
    try {
      const request = JSON.parse(combined.subarray(0, newline).toString("utf8")) as unknown;
      writeResult(socket, await broker.handleForIpc(request));
    } catch {
      writeResult(socket, failure("AUTH_INVALID", "IPC request is not valid JSON"));
    }
  });
}

function writeResult(socket: Socket, result: BrokerResult | AuthenticatedBrokerResponse): void {
  if (!socket.destroyed) socket.end(`${JSON.stringify(result)}\n`);
}

function failure(errorClass: "AUTH_INVALID" | "OUTPUT_LIMIT", message: string): BrokerResult {
  const error = new BrokerError(errorClass, message);
  return { ok: false, request_id: "invalid-request", tool: "unknown", result_class: error.errorClass, error: { message, retryable: false }, duration_ms: 0 };
}

export async function removeStaleSocket(path: string): Promise<void> {
  const initial = await readSocketIdentity(path);
  if (initial === undefined) return;
  const active = await probeSocket(path);
  const current = await readSocketIdentity(path);
  if (current === undefined) return;
  if (current.device !== initial.device || current.inode !== initial.inode) {
    throw new Error("IPC socket changed while checking ownership");
  }
  if (active) throw new Error("IPC socket is already active");
  try {
    await unlink(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

/** Fails closed when a live listener already owns the configured pathname. */
export async function assertSocketNotActive(path: string): Promise<void> {
  const initial = await readSocketIdentity(path);
  if (initial === undefined) return;
  const active = await probeSocket(path);
  const current = await readSocketIdentity(path);
  if (current === undefined) return;
  if (current.device !== initial.device || current.inode !== initial.inode) {
    throw new Error("IPC socket changed while checking startup ownership");
  }
  if (active) throw new Error("IPC socket is already active");
}

async function readSocketIdentity(path: string): Promise<SocketPathIdentity | undefined> {
  try {
    const value = await lstat(path);
    if (!value.isSocket()) throw new Error("Refusing to replace a non-socket IPC path");
    return { device: value.dev, inode: value.ino };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

export async function captureSocketPathIdentity(path: string): Promise<SocketPathIdentity> {
  const identity = await readSocketIdentity(path);
  if (identity === undefined) throw new Error("IPC socket disappeared after startup");
  return identity;
}

export async function unlinkOwnedSocket(path: string, expected: SocketPathIdentity | undefined): Promise<void> {
  if (expected === undefined) return;
  const current = await readSocketIdentity(path);
  if (current === undefined) return;
  if (current.device !== expected.device || current.inode !== expected.inode) {
    throw new Error("IPC socket ownership changed before close");
  }
  try {
    await unlink(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

/**
 * Moves a generic Node Unix listener away from its public path before
 * `server.close()`. Node's close implementation unlinks the path itself, so
 * a temporary symlink barrier prevents it from deleting a replacement
 * listener that races into the original pathname.
 */
export async function detachOwnedSocket(path: string, expected: SocketPathIdentity | undefined): Promise<DetachedSocketPath | undefined> {
  if (expected === undefined) return undefined;
  const current = await readSocketIdentity(path);
  if (current === undefined) return undefined;
  if (current.device !== expected.device || current.inode !== expected.inode) {
    throw new Error("IPC socket ownership changed before close");
  }
  const detachedPath = join(dirname(path), `.mac-operator-closing-${randomUUID()}.sock`);
  await renameSocket(path, detachedPath);
  const detachedIdentity = await captureSocketPathIdentity(detachedPath);
  try {
    await createSocketBarrier(path, detachedPath);
  } catch (error) {
    await renameSocket(detachedPath, path).catch(() => undefined);
    throw error;
  }
  return { path: detachedPath, identity: detachedIdentity };
}

export async function removeDetachedSocket(detached: DetachedSocketPath | undefined): Promise<void> {
  if (detached === undefined) return;
  await unlinkOwnedSocket(detached.path, detached.identity);
}

async function renameSocket(path: string, target: string): Promise<void> {
  await rename(path, target);
}

async function createSocketBarrier(path: string, target: string): Promise<void> {
  await symlink(target, path);
}

/**
 * Distinguishes an active listener from a stale pathname before unlinking it.
 * Any result other than a definitive refused/missing connection fails closed.
 */
function probeSocket(path: string): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(path);
    let settled = false;
    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      callback();
    };
    socket.once("connect", () => finish(() => resolve(true)));
    socket.once("error", (error: NodeJS.ErrnoException) => {
      if (error.code === "ECONNREFUSED" || error.code === "ENOENT") {
        finish(() => resolve(false));
        return;
      }
      finish(() => reject(new Error("IPC socket liveness probe failed")));
    });
    socket.setTimeout(250, () => finish(() => reject(new Error("IPC socket liveness probe timed out"))));
  });
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
