import { chmod, lstat, readdir, rename, stat, symlink, unlink } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { BrokerError, parseJsonUtf8Strict, type AuthenticatedBrokerResponse, type BrokerResult } from "@mac-operator/contracts";
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

export interface SocketRecoveryResult {
  status: "recovered" | "absent" | "not_stale" | "ambiguous";
  path: string;
  quarantinePath: string | null;
  identity: SocketPathIdentity;
}

const MIN_SOCKET_RECOVERY_AGE_MS = 1_000;
const MAX_SOCKET_RECOVERY_AGE_MS = 604_800_000;
const SOCKET_QUARANTINE_PREFIX = ".mac-operator-removing-";

export class BrokerIpcServer {
  private server: Server | undefined;
  private socketIdentity: SocketPathIdentity | undefined;
  private readonly sockets = new Set<Socket>();
  private readonly maxRequestBytes: number;

  constructor(private readonly options: IpcServerOptions) {
    this.maxRequestBytes = options.maxRequestBytes ?? 1_048_576;
  }

  async listen(): Promise<void> {
    if (this.server) throw new Error("IPC server is already running");
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
      const trailing = combined.subarray(newline + 1);
      if (trailing.some((byte) => !isAsciiWhitespace(byte))) {
        writeResult(socket, failure("PRECONDITION_FAILED", "IPC request contains trailing data"));
        return;
      }
      const request = parseJsonUtf8Strict(combined.subarray(0, newline));
      writeResult(socket, await broker.handleForIpc(request));
    } catch {
      writeResult(socket, failure("AUTH_INVALID", "IPC request is not valid JSON"));
    }
  });
}

function writeResult(socket: Socket, result: BrokerResult | AuthenticatedBrokerResponse): void {
  if (!socket.destroyed) socket.end(`${JSON.stringify(result)}\n`);
}

function isAsciiWhitespace(byte: number): boolean {
  return byte === 0x09 || byte === 0x0a || byte === 0x0c || byte === 0x0d || byte === 0x20;
}

function failure(errorClass: "AUTH_INVALID" | "OUTPUT_LIMIT" | "PRECONDITION_FAILED", message: string): BrokerResult {
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
  await removeSocketByIdentity(path, initial, "IPC socket changed before removal", "IPC socket changed during removal");
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
  await removeSocketByIdentity(path, expected, "IPC socket ownership changed before close", "IPC socket ownership changed during close");
}

/**
 * Removes an exact socket inode without unlinking a replacement pathname.
 * The rename selects the pathname atomically; the private quarantine is then
 * rechecked before deletion. A mismatch is left as a recovery artifact rather
 * than deleting a socket that appeared after the initial identity read.
 */
async function removeSocketByIdentity(
  path: string,
  expected: SocketPathIdentity,
  beforeError: string,
  duringError: string
): Promise<void> {
  const current = await readSocketIdentity(path);
  if (current === undefined) return;
  if (current.device !== expected.device || current.inode !== expected.inode) {
    throw new Error(beforeError);
  }
  const quarantine = join(dirname(path), `${SOCKET_QUARANTINE_PREFIX}${Date.now()}-${randomUUID()}-${socketPathBasenameHash(path)}.sock`);
  try {
    await rename(path, quarantine);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  const quarantined = await readSocketIdentity(quarantine);
  if (quarantined === undefined || quarantined.device !== expected.device || quarantined.inode !== expected.inode) {
    throw new Error(duringError);
  }
  await unlink(quarantine);
}

/**
 * Explicitly removes one stale socket quarantine left by a crash between the
 * identity check and unlink. Recovery is never automatic and cannot select an
 * artifact by nonce alone: the original basename fingerprint, socket
 * identity, owner-only parent, and minimum age must all agree.
 */
export async function recoverOrphanedSocket(
  path: string,
  expected: SocketPathIdentity,
  minAgeMs = 60_000
): Promise<SocketRecoveryResult> {
  assertRecoverableSocketPath(path);
  if (!validSocketIdentity(expected) || !Number.isSafeInteger(minAgeMs) ||
      minAgeMs < MIN_SOCKET_RECOVERY_AGE_MS || minAgeMs > MAX_SOCKET_RECOVERY_AGE_MS) {
    throw new Error("IPC socket recovery precondition is malformed");
  }
  await validateSocketParent(path);
  const parentPath = dirname(path);
  const parentBefore = await readDirectoryIdentity(parentPath);
  const candidateHash = socketPathBasenameHash(path);
  const names = await readdir(parentPath);
  const stale: string[] = [];
  const recent: string[] = [];
  let activeMatches = 0;
  const now = Date.now();
  for (const name of names) {
    const createdAt = parseSocketQuarantineTimestamp(name, candidateHash);
    if (createdAt === undefined) continue;
    const candidatePath = join(parentPath, name);
    const identity = await readSocketIdentity(candidatePath);
    if (identity === undefined || identity.device !== expected.device || identity.inode !== expected.inode) continue;
    const active = await probeRecoverySocket(candidatePath);
    if (active) {
      activeMatches += 1;
      recent.push(name);
      continue;
    }
    if (now >= createdAt && now - createdAt >= minAgeMs) stale.push(name);
    else recent.push(name);
  }
  const parentAfter = await readDirectoryIdentity(parentPath);
  if (parentBefore.device !== parentAfter.device || parentBefore.inode !== parentAfter.inode) {
    throw new Error("IPC socket recovery parent changed during scan");
  }
  const makeResult = (status: SocketRecoveryResult["status"], quarantinePath: string | null): SocketRecoveryResult => ({
    status,
    path,
    quarantinePath,
    identity: expected
  });
  if (activeMatches > 0 || stale.length > 1 || recent.length > 1 || (stale.length > 0 && recent.length > 0)) {
    return makeResult("ambiguous", null);
  }
  if (stale.length === 0) {
    return makeResult(recent.length === 1 ? "not_stale" : "absent", recent.length === 1 ? join(parentPath, recent[0]!) : null);
  }
  const candidatePath = join(parentPath, stale[0]!);
  const parentFinal = await readDirectoryIdentity(parentPath);
  if (parentBefore.device !== parentFinal.device || parentBefore.inode !== parentFinal.inode) {
    throw new Error("IPC socket recovery parent changed before removal");
  }
  const current = await readSocketIdentity(candidatePath);
  if (current === undefined) return makeResult("absent", null);
  if (current.device !== expected.device || current.inode !== expected.inode || await probeRecoverySocket(candidatePath)) {
    throw new Error("IPC socket recovery artifact changed or became active");
  }
  await unlink(candidatePath);
  if (await readSocketIdentity(candidatePath) !== undefined) {
    throw new Error("IPC socket recovery postcondition failed");
  }
  return makeResult("recovered", candidatePath);
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

function assertRecoverableSocketPath(path: string): void {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path || path.includes("\0") || basename(path).length === 0) {
    throw new Error("IPC socket recovery path must be canonical and absolute");
  }
}

function validSocketIdentity(identity: SocketPathIdentity): boolean {
  return Number.isSafeInteger(identity.device) && identity.device >= 0 &&
    Number.isSafeInteger(identity.inode) && identity.inode > 0;
}

async function readDirectoryIdentity(path: string): Promise<SocketPathIdentity> {
  const value = await lstat(path);
  if (!value.isDirectory()) throw new Error("IPC socket recovery parent is not a directory");
  return { device: value.dev, inode: value.ino };
}

function socketPathBasenameHash(path: string): string {
  return createHash("sha256").update(basename(path), "utf8").digest("hex");
}

function parseSocketQuarantineTimestamp(name: string, basenameHash: string): number | undefined {
  const prefix = SOCKET_QUARANTINE_PREFIX.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const pattern = new RegExp(`^${prefix}(\\d{1,13})-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-${basenameHash}\\.sock$`, "u");
  const match = pattern.exec(name);
  if (!match) return undefined;
  const timestamp = Number(match[1]);
  return Number.isSafeInteger(timestamp) ? timestamp : undefined;
}

async function probeRecoverySocket(path: string): Promise<boolean> {
  try {
    return await probeSocket(path);
  } catch (error) {
    // macOS reports EINVAL for a detached Unix socket inode that no longer
    // has a listening endpoint. That is the expected inactive state for a
    // crash orphan; every other liveness ambiguity remains fail-closed.
    if ((error as NodeJS.ErrnoException).code === "EINVAL") return false;
    throw error;
  }
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
      const failure = new Error("IPC socket liveness probe failed") as NodeJS.ErrnoException;
      failure.code = error.code;
      finish(() => reject(failure));
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
