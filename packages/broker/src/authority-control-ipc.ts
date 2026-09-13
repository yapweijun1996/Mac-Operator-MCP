import { chmod, unlink } from "node:fs/promises";
import { createHmac, timingSafeEqual } from "node:crypto";
import { createServer, type Server, type Socket } from "node:net";
import { BrokerError, canonicalJson, type ErrorClass } from "@mac-operator/contracts";
import { MacOsNativePeerIpcServer, type NativePeerPolicy } from "./native-peer-ipc-server.js";
import { removeStaleSocket, validateSocketParent } from "./ipc-server.js";
import type { BrokerStore, RevocationKind, SwitchName } from "./persistence.js";

const AUTHORITY_CONTROL_DOMAIN = "mac-operator-authority-control-v0.1\0";
const SWITCH_NAMES: readonly SwitchName[] = ["global", "mutations", "process", "network", "gui", "destructive", "privileged"];
const REVOCATION_KINDS: readonly RevocationKind[] = ["principal", "session", "edge", "edge_key", "approval_key", "policy_signer"];

export type AuthorityControlOperation = "set_switch" | "revoke";

export interface UnsignedAuthorityControlCommand {
  protocolVersion: "0.1";
  requestId: string;
  nonce: string;
  nonceExpiresAtMs: number;
  timestampMs: number;
  operation: AuthorityControlOperation;
  switchName?: SwitchName;
  disabled?: boolean;
  expectedDisabled?: boolean;
  revocationKind?: RevocationKind;
  subjectId?: string;
  reason: string;
}

export interface SignedAuthorityControlCommand extends UnsignedAuthorityControlCommand {
  authenticationProof: string;
}

export type AuthorityControlIpcResponse =
  | { ok: true; operation: AuthorityControlOperation; switch_name?: SwitchName; disabled?: boolean; revocation_kind?: RevocationKind; subject_id?: string }
  | { ok: false; result_class: ErrorClass; error: { message: string; retryable: boolean } };

export interface AuthorityControlIpcServerOptions {
  socketPath: string;
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
 * Separate owner-only authority channel for emergency switch and revocation
 * changes. It is never registered with the MCP Edge and cannot execute a
 * command or grant a capability. Every command is OS-peer-authenticated,
 * HMAC-bound, and admitted through a durable replay ledger before mutation.
 */
export class AuthorityControlIpcServer {
  private server: Server | undefined;
  private nativeTransport: MacOsNativePeerIpcServer | undefined;
  private readonly maxRequestBytes: number;
  private readonly maxRequestAgeMs: number;
  private readonly allowedClockSkewMs: number;
  private readonly now: () => number;

  constructor(private readonly options: AuthorityControlIpcServerOptions) {
    if (!options.store) throw new Error("Authority control IPC requires a BrokerStore");
    if (!options.peerCredentialVerifier && !options.peerPolicy) {
      throw new Error("Authority control IPC requires a peer verifier or native peer policy");
    }
    if (options.authenticationKey.byteLength < 32) throw new Error("Authority control IPC key must contain at least 32 bytes");
    this.maxRequestBytes = options.maxRequestBytes ?? 64 * 1024;
    this.maxRequestAgeMs = options.maxRequestAgeMs ?? 60_000;
    this.allowedClockSkewMs = options.allowedClockSkewMs ?? 5_000;
    this.now = options.now ?? Date.now;
    if (!Number.isSafeInteger(this.maxRequestBytes) || this.maxRequestBytes < 256 || this.maxRequestBytes > 1_048_576 ||
        !Number.isSafeInteger(this.maxRequestAgeMs) || this.maxRequestAgeMs < 1 || this.maxRequestAgeMs > 600_000 ||
        !Number.isSafeInteger(this.allowedClockSkewMs) || this.allowedClockSkewMs < 0 || this.allowedClockSkewMs > 60_000) {
      throw new Error("Authority control IPC limits are invalid");
    }
  }

  async listen(): Promise<void> {
    if (this.server || this.nativeTransport) throw new Error("Authority control IPC server is already running");
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
    this.server = createServer((socket) => this.handleSocket(socket));
    await new Promise<void>((resolvePromise, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(this.options.socketPath, resolvePromise);
    });
    await chmod(this.options.socketPath, 0o600);
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
    if (server) {
      await new Promise<void>((resolvePromise, reject) => server.close((error) => {
        if (error && (error as NodeJS.ErrnoException).code !== "ERR_SERVER_NOT_RUNNING") reject(error);
        else resolvePromise();
      }));
    }
    try { await unlink(this.options.socketPath); } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
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
        socket.pause();
        writeAuthorityControlResponse(socket, failure("OUTPUT_LIMIT", "Authority control IPC request exceeded the byte limit"));
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      handled = true;
      socket.pause();
      let response: AuthorityControlIpcResponse;
      try {
        const raw = JSON.parse(combined.subarray(0, newline).toString("utf8")) as unknown;
        const command = authenticateAuthorityControlCommand(
          raw,
          this.options.authenticationKey,
          this.now(),
          this.maxRequestAgeMs,
          this.allowedClockSkewMs
        );
        this.options.store.admitAuthorityControlCommand({
          requestId: command.requestId,
          nonce: command.nonce,
          acceptedAtMs: this.now(),
          expiresAtMs: command.nonceExpiresAtMs
        });
        response = this.execute(command);
      } catch (error) {
        const brokerError = error instanceof BrokerError
          ? error
          : new BrokerError("PRECONDITION_FAILED", "Authority control command is invalid");
        response = failure(brokerError.errorClass, brokerError.message, brokerError.retryable);
      }
      writeAuthorityControlResponse(socket, response);
    });
  }

  private execute(command: UnsignedAuthorityControlCommand): AuthorityControlIpcResponse {
    if (command.operation === "set_switch") {
    this.options.store.setSwitch(
        command.switchName!,
        command.disabled!,
        command.reason,
        command.timestampMs,
        command.expectedDisabled,
        command.requestId
      );
      return {
        ok: true,
        operation: command.operation,
        switch_name: command.switchName!,
        disabled: command.disabled!
      };
    }
    this.options.store.revoke(command.revocationKind!, command.subjectId!, command.reason, command.timestampMs, command.requestId);
    return {
      ok: true,
      operation: command.operation,
      revocation_kind: command.revocationKind!,
      subject_id: command.subjectId!
    };
  }
}

export function signAuthorityControlCommand(
  command: UnsignedAuthorityControlCommand,
  authenticationKey: Buffer
): SignedAuthorityControlCommand {
  validateUnsignedAuthorityControlCommand(command);
  if (authenticationKey.byteLength < 32) throw new Error("Authority control IPC key must contain at least 32 bytes");
  return { ...command, authenticationProof: authorityControlCommandProof(command, authenticationKey) };
}

export function authorityControlCommandProof(
  command: UnsignedAuthorityControlCommand,
  authenticationKey: Buffer
): string {
  if (authenticationKey.byteLength < 32) throw new Error("Authority control IPC key must contain at least 32 bytes");
  return createHmac("sha256", authenticationKey)
    .update(AUTHORITY_CONTROL_DOMAIN, "utf8")
    .update(canonicalJson(command), "utf8")
    .digest("hex");
}

export function authenticateAuthorityControlCommand(
  raw: unknown,
  authenticationKey: Buffer,
  nowMs: number,
  maxRequestAgeMs = 60_000,
  allowedClockSkewMs = 5_000
): UnsignedAuthorityControlCommand {
  if (authenticationKey.byteLength < 32) throw new BrokerError("AUTH_INVALID", "Authority control IPC key is invalid");
  const parsed = parseSignedAuthorityControlCommand(raw);
  const command = parsed.unsigned;
  if (command.timestampMs > nowMs + allowedClockSkewMs || nowMs - command.timestampMs > maxRequestAgeMs) {
    throw new BrokerError("AUTH_EXPIRED", "Authority control command timestamp is outside the accepted window");
  }
  if (command.nonceExpiresAtMs <= nowMs) {
    throw new BrokerError("AUTH_EXPIRED", "Authority control command nonce has expired");
  }
  if (command.nonceExpiresAtMs <= command.timestampMs ||
      command.nonceExpiresAtMs > command.timestampMs + maxRequestAgeMs + allowedClockSkewMs) {
    throw new BrokerError("AUTH_EXPIRED", "Authority control command nonce window is invalid");
  }
  const expected = authorityControlCommandProof(command, authenticationKey);
  if (!safeEqualHex(parsed.authenticationProof, expected)) {
    throw new BrokerError("AUTH_INVALID", "Authority control command authentication failed");
  }
  return command;
}

function parseSignedAuthorityControlCommand(value: unknown): {
  unsigned: UnsignedAuthorityControlCommand;
  authenticationProof: string;
} {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("PRECONDITION_FAILED", "Authority control command envelope is malformed");
  }
  const record = value as Record<string, unknown>;
  const allowed = new Set([
    "protocolVersion", "requestId", "nonce", "nonceExpiresAtMs", "timestampMs", "operation",
    "switchName", "disabled", "expectedDisabled", "revocationKind", "subjectId", "reason", "authenticationProof"
  ]);
  if (Object.keys(record).some((key) => !allowed.has(key)) || typeof record.authenticationProof !== "string") {
    throw new BrokerError("PRECONDITION_FAILED", "Authority control command envelope is malformed");
  }
  const unsigned: UnsignedAuthorityControlCommand = {
    protocolVersion: record.protocolVersion as "0.1",
    requestId: record.requestId as string,
    nonce: record.nonce as string,
    nonceExpiresAtMs: record.nonceExpiresAtMs as number,
    timestampMs: record.timestampMs as number,
    operation: record.operation as AuthorityControlOperation,
    ...(record.switchName !== undefined ? { switchName: record.switchName as SwitchName } : {}),
    ...(record.disabled !== undefined ? { disabled: record.disabled as boolean } : {}),
    ...(record.expectedDisabled !== undefined ? { expectedDisabled: record.expectedDisabled as boolean } : {}),
    ...(record.revocationKind !== undefined ? { revocationKind: record.revocationKind as RevocationKind } : {}),
    ...(record.subjectId !== undefined ? { subjectId: record.subjectId as string } : {}),
    reason: record.reason as string
  };
  validateUnsignedAuthorityControlCommand(unsigned);
  if (!/^[a-f0-9]{64}$/u.test(record.authenticationProof)) {
    throw new BrokerError("AUTH_INVALID", "Authority control command proof is malformed");
  }
  return { unsigned, authenticationProof: record.authenticationProof as string };
}

export function validateUnsignedAuthorityControlCommand(command: UnsignedAuthorityControlCommand): void {
  if (command.protocolVersion !== "0.1" ||
      !/^[A-Za-z0-9._:-]{1,128}$/u.test(command.requestId) ||
      !/^[A-Za-z0-9._:-]{16,128}$/u.test(command.nonce) ||
      !Number.isSafeInteger(command.nonceExpiresAtMs) || command.nonceExpiresAtMs < 0 ||
      !Number.isSafeInteger(command.timestampMs) || command.timestampMs < 0 ||
      typeof command.reason !== "string" || command.reason.length < 1 || command.reason.length > 200 || command.reason.includes("\0") ||
      (command.operation === "revoke" && !REVOCATION_KINDS.includes(command.revocationKind as RevocationKind)) ||
      (command.operation === "set_switch" && !SWITCH_NAMES.includes(command.switchName as SwitchName))) {
    throw new BrokerError("PRECONDITION_FAILED", "Authority control command fields are malformed");
  }
  if (command.operation === "set_switch") {
    if (typeof command.disabled !== "boolean" || typeof command.expectedDisabled !== "boolean" ||
        command.revocationKind !== undefined || command.subjectId !== undefined) {
      throw new BrokerError("PRECONDITION_FAILED", "Authority control switch command is malformed");
    }
    return;
  }
  if (command.operation === "revoke") {
    if (typeof command.subjectId !== "string" ||
        !/^[A-Za-z0-9._:@/-]{1,256}$/u.test(command.subjectId) ||
        command.switchName !== undefined || command.disabled !== undefined || command.expectedDisabled !== undefined) {
      throw new BrokerError("PRECONDITION_FAILED", "Authority control revocation command is malformed");
    }
    return;
  }
  throw new BrokerError("PRECONDITION_FAILED", "Authority control operation is unsupported");
}

function safeEqualHex(actual: string, expected: string): boolean {
  if (!/^[a-f0-9]{64}$/u.test(actual) || !/^[a-f0-9]{64}$/u.test(expected)) return false;
  return timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}

function writeAuthorityControlResponse(socket: Socket, response: AuthorityControlIpcResponse): void {
  if (!socket.destroyed) socket.end(`${JSON.stringify(response)}\n`);
}

function failure(errorClass: ErrorClass, message: string, retryable = false): AuthorityControlIpcResponse {
  return { ok: false, result_class: errorClass, error: { message, retryable } };
}
