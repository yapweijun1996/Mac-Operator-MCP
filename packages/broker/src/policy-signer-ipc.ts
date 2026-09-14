import { chmod } from "node:fs/promises";
import { createHmac, timingSafeEqual } from "node:crypto";
import { createServer, type Server, type Socket } from "node:net";
import { BrokerError, canonicalJson, decodeUtf8Strict, sha256, type ErrorClass } from "@mac-operator/contracts";
import { MacOsNativePeerIpcServer, type NativePeerPolicy } from "./native-peer-ipc-server.js";
import { captureSocketPathIdentity, detachOwnedSocket, removeDetachedSocket, removeStaleSocket, validateSocketParent, type SocketPathIdentity } from "./ipc-server.js";
import type { PolicySignerKeyManager } from "./policy-signer-keyring.js";
import type { BrokerStore } from "./persistence.js";

const POLICY_SIGNER_COMMAND_DOMAIN = "mac-operator-policy-signer-command-v0.1\0";

export type PolicySignerOperation = "reload" | "rollback" | "revoke";

export interface UnsignedPolicySignerCommand {
  protocolVersion: "0.1";
  requestId: string;
  nonce: string;
  nonceExpiresAtMs: number;
  timestampMs: number;
  operation: PolicySignerOperation;
  expectedPreviousRevision?: number;
  expectedCurrentRevision?: number;
  reasonCode?: string;
  keyId?: string;
  reason?: string;
}

export interface SignedPolicySignerCommand extends UnsignedPolicySignerCommand {
  authenticationProof: string;
}

export type PolicySignerIpcResponse =
  | { ok: true; operation: PolicySignerOperation; revision: number; key_id?: string }
  | { ok: false; result_class: ErrorClass; error: { message: string; retryable: boolean } };

export interface PolicySignerIpcServerOptions {
  socketPath: string;
  manager: PolicySignerKeyManager;
  store: BrokerStore;
  authenticationKey: Buffer;
  peerCredentialVerifier?: { verify(socket: Socket): unknown };
  peerPolicy?: NativePeerPolicy;
  maxRequestBytes?: number;
  maxRequestAgeMs?: number;
  allowedClockSkewMs?: number;
  now?: () => number;
  onError?: (error: unknown) => void;
}

/**
 * Separate local operator channel for signer reload, rollback, and revocation.
 * It is never registered with the MCP Edge and requires both OS peer
 * credentials and an HMAC-authenticated, replay-bound command.
 */
export class PolicySignerIpcServer {
  private server: Server | undefined;
  private nativeTransport: MacOsNativePeerIpcServer | undefined;
  private socketIdentity: SocketPathIdentity | undefined;
  private readonly sockets = new Set<Socket>();
  private readonly authenticationKey: Buffer;
  private readonly maxRequestBytes: number;
  private readonly maxRequestAgeMs: number;
  private readonly allowedClockSkewMs: number;
  private readonly now: () => number;

  constructor(private readonly options: PolicySignerIpcServerOptions) {
    if (!options.peerCredentialVerifier && !options.peerPolicy) {
      throw new Error("Policy signer IPC requires a peer verifier or native peer policy");
    }
    if (options.authenticationKey.byteLength < 32) throw new Error("Policy signer IPC key must contain at least 32 bytes");
    this.authenticationKey = Buffer.from(options.authenticationKey);
    this.maxRequestBytes = options.maxRequestBytes ?? 64 * 1024;
    this.maxRequestAgeMs = options.maxRequestAgeMs ?? 60_000;
    this.allowedClockSkewMs = options.allowedClockSkewMs ?? 5_000;
    this.now = options.now ?? Date.now;
    if (!Number.isSafeInteger(this.maxRequestBytes) || this.maxRequestBytes < 256 || this.maxRequestBytes > 1_048_576 ||
        !Number.isSafeInteger(this.maxRequestAgeMs) || this.maxRequestAgeMs < 1 || this.maxRequestAgeMs > 600_000 ||
        !Number.isSafeInteger(this.allowedClockSkewMs) || this.allowedClockSkewMs < 0 || this.allowedClockSkewMs > 60_000) {
      throw new Error("Policy signer IPC limits are invalid");
    }
  }

  async listen(): Promise<void> {
    if (this.server || this.nativeTransport) throw new Error("Policy signer IPC server is already running");
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
      try { await nativeTransport.close(); }
      finally { this.authenticationKey.fill(0); }
      return;
    }
    const server = this.server;
    this.server = undefined;
    const socketIdentity = this.socketIdentity;
    this.socketIdentity = undefined;
    try {
      const detached = await detachOwnedSocket(this.options.socketPath, socketIdentity);
      try {
        for (const socket of this.sockets) socket.destroy();
        this.sockets.clear();
        if (server) await new Promise<void>((resolve, reject) => server.close((error) => {
          if (error && (error as NodeJS.ErrnoException).code !== "ERR_SERVER_NOT_RUNNING") reject(error);
          else resolve();
        }));
      } finally {
        await removeDetachedSocket(detached);
      }
    } finally {
      this.authenticationKey.fill(0);
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
    socket.on("data", async (chunk: Buffer) => {
      if (handled) return;
      total += chunk.byteLength;
      if (total > this.maxRequestBytes) {
        handled = true;
        writePolicySignerResponse(socket, failure("OUTPUT_LIMIT", "Policy signer IPC request exceeded the byte limit"));
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      handled = true;
      socket.pause();
      let response: PolicySignerIpcResponse;
      try {
        const raw = JSON.parse(decodeUtf8Strict(combined.subarray(0, newline))) as unknown;
        const command = authenticatePolicySignerCommand(
          raw,
          this.authenticationKey,
          this.now(),
          this.maxRequestAgeMs,
          this.allowedClockSkewMs
        );
        if (combined.subarray(newline + 1).some((byte) => !isAsciiWhitespace(byte))) {
          throw new BrokerError("PRECONDITION_FAILED", "Policy signer IPC request contained trailing data");
        }
        this.options.store.admitPolicySignerCommand({
          requestId: command.requestId,
          nonce: command.nonce,
          acceptedAtMs: this.now(),
          expiresAtMs: command.nonceExpiresAtMs
        });
        response = await this.execute(command);
      } catch (error) {
        const brokerError = error instanceof BrokerError
          ? error
          : new BrokerError("PRECONDITION_FAILED", "Policy signer command is invalid");
        response = failure(brokerError.errorClass, brokerError.message, brokerError.retryable);
      }
      writePolicySignerResponse(socket, response);
    });
  }

  private async execute(command: UnsignedPolicySignerCommand): Promise<PolicySignerIpcResponse> {
    if (command.operation === "reload") {
      const loaded = await this.options.manager.reload(command.expectedPreviousRevision);
      return { ok: true, operation: command.operation, revision: loaded.document.revision };
    }
    if (command.operation === "rollback") {
      const loaded = await this.options.manager.rollback({
        expectedCurrentRevision: command.expectedCurrentRevision!,
        reasonCode: command.reasonCode!
      });
      return { ok: true, operation: command.operation, revision: loaded.document.revision };
    }
    await this.options.manager.revoke(command.keyId!, command.reason!, command.timestampMs);
    return { ok: true, operation: command.operation, revision: this.options.manager.current().document.revision, key_id: command.keyId! };
  }
}

export function signPolicySignerCommand(command: UnsignedPolicySignerCommand, authenticationKey: Buffer): SignedPolicySignerCommand {
  validateUnsignedCommand(command);
  return { ...command, authenticationProof: policySignerCommandProof(command, authenticationKey) };
}

export function policySignerCommandDigest(command: UnsignedPolicySignerCommand): string {
  validateUnsignedCommand(command);
  return sha256(canonicalJson(command));
}

export function policySignerCommandProof(command: UnsignedPolicySignerCommand, authenticationKey: Buffer): string {
  if (authenticationKey.byteLength < 32) throw new Error("Policy signer IPC key must contain at least 32 bytes");
  const digest = policySignerCommandDigest(command);
  return createHmac("sha256", authenticationKey)
    .update(POLICY_SIGNER_COMMAND_DOMAIN, "utf8")
    .update(digest, "utf8")
    .digest("hex");
}

export function authenticatePolicySignerCommand(
  raw: unknown,
  authenticationKey: Buffer,
  nowMs: number,
  maxRequestAgeMs = 60_000,
  allowedClockSkewMs = 5_000
): UnsignedPolicySignerCommand {
  if (authenticationKey.byteLength < 32) throw new BrokerError("AUTH_INVALID", "Policy signer IPC key is invalid");
  const parsed = parseSignedPolicySignerCommand(raw);
  const command = parsed.unsigned;
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || command.timestampMs > nowMs + allowedClockSkewMs ||
      nowMs - command.timestampMs > maxRequestAgeMs || command.nonceExpiresAtMs <= nowMs) {
    throw new BrokerError("AUTH_EXPIRED", "Policy signer command timestamp is outside the accepted window");
  }
  if (command.nonceExpiresAtMs <= command.timestampMs ||
      command.nonceExpiresAtMs > command.timestampMs + maxRequestAgeMs + allowedClockSkewMs) {
    throw new BrokerError("AUTH_EXPIRED", "Policy signer command nonce window is invalid");
  }
  const expected = policySignerCommandProof(command, authenticationKey);
  if (!safeEqualHex(parsed.authenticationProof, expected)) {
    throw new BrokerError("AUTH_INVALID", "Policy signer command authentication failed");
  }
  return command;
}

function parseSignedPolicySignerCommand(value: unknown): {
  unsigned: UnsignedPolicySignerCommand;
  authenticationProof: string;
} {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("PRECONDITION_FAILED", "Policy signer command envelope is malformed");
  }
  const record = value as Record<string, unknown>;
  const allowed = new Set([
    "protocolVersion", "requestId", "nonce", "nonceExpiresAtMs", "timestampMs", "operation",
    "expectedPreviousRevision", "expectedCurrentRevision", "reasonCode", "keyId", "reason", "authenticationProof"
  ]);
  if (Object.keys(record).some((key) => !allowed.has(key)) || typeof record.authenticationProof !== "string") {
    throw new BrokerError("PRECONDITION_FAILED", "Policy signer command envelope is malformed");
  }
  const unsigned: UnsignedPolicySignerCommand = {
    protocolVersion: record.protocolVersion as "0.1",
    requestId: record.requestId as string,
    nonce: record.nonce as string,
    nonceExpiresAtMs: record.nonceExpiresAtMs as number,
    timestampMs: record.timestampMs as number,
    operation: record.operation as PolicySignerOperation,
    ...(record.expectedPreviousRevision !== undefined ? { expectedPreviousRevision: record.expectedPreviousRevision as number } : {}),
    ...(record.expectedCurrentRevision !== undefined ? { expectedCurrentRevision: record.expectedCurrentRevision as number } : {}),
    ...(record.reasonCode !== undefined ? { reasonCode: record.reasonCode as string } : {}),
    ...(record.keyId !== undefined ? { keyId: record.keyId as string } : {}),
    ...(record.reason !== undefined ? { reason: record.reason as string } : {})
  };
  validateUnsignedCommand(unsigned);
  if (!/^[a-f0-9]{64}$/u.test(record.authenticationProof)) {
    throw new BrokerError("AUTH_INVALID", "Policy signer command proof is malformed");
  }
  return { unsigned, authenticationProof: record.authenticationProof as string };
}

function validateUnsignedCommand(command: UnsignedPolicySignerCommand): void {
  if (command.protocolVersion !== "0.1" ||
      !/^[A-Za-z0-9._:-]{1,128}$/u.test(command.requestId) ||
      !/^[A-Za-z0-9._:-]{16,128}$/u.test(command.nonce) ||
      !Number.isSafeInteger(command.nonceExpiresAtMs) || command.nonceExpiresAtMs < 0 ||
      !Number.isSafeInteger(command.timestampMs) || command.timestampMs < 0 ||
      !["reload", "rollback", "revoke"].includes(command.operation)) {
    throw new BrokerError("PRECONDITION_FAILED", "Policy signer command fields are malformed");
  }
  if (command.operation === "reload") {
    if (command.expectedPreviousRevision !== undefined &&
        (!Number.isSafeInteger(command.expectedPreviousRevision) || command.expectedPreviousRevision < 0) ||
        command.expectedCurrentRevision !== undefined || command.reasonCode !== undefined ||
        command.keyId !== undefined || command.reason !== undefined) {
      throw new BrokerError("PRECONDITION_FAILED", "Policy signer reload command is malformed");
    }
    return;
  }
  if (command.operation === "rollback") {
    if (!Number.isSafeInteger(command.expectedCurrentRevision) ||
        typeof command.expectedCurrentRevision !== "number" || command.expectedCurrentRevision < 1 ||
        typeof command.reasonCode !== "string" || !/^[A-Z0-9_:-]{1,64}$/u.test(command.reasonCode) ||
        command.expectedPreviousRevision !== undefined || command.keyId !== undefined || command.reason !== undefined) {
      throw new BrokerError("PRECONDITION_FAILED", "Policy signer rollback command is malformed");
    }
    return;
  }
  if (command.expectedPreviousRevision !== undefined || command.expectedCurrentRevision !== undefined ||
      command.reasonCode !== undefined || typeof command.keyId !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(command.keyId) ||
      typeof command.reason !== "string" || command.reason.length < 1 || command.reason.length > 128) {
    throw new BrokerError("PRECONDITION_FAILED", "Policy signer revoke command is malformed");
  }
}

function safeEqualHex(actual: string, expected: string): boolean {
  if (!/^[a-f0-9]{64}$/u.test(actual) || !/^[a-f0-9]{64}$/u.test(expected)) return false;
  return timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}

function writePolicySignerResponse(socket: Socket, response: PolicySignerIpcResponse): void {
  if (!socket.destroyed) socket.end(`${JSON.stringify(response)}\n`);
}

function failure(errorClass: ErrorClass, message: string, retryable = false): PolicySignerIpcResponse {
  return { ok: false, result_class: errorClass, error: { message, retryable } };
}

function isAsciiWhitespace(byte: number): boolean {
  return byte === 0x09 || byte === 0x0a || byte === 0x0c || byte === 0x0d || byte === 0x20;
}
