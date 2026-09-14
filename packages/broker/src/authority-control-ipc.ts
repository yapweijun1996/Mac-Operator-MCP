import { lstat, realpath, chmod } from "node:fs/promises";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { dirname, isAbsolute, resolve } from "node:path";
import { BrokerError, canonicalJson, sha256, type ErrorClass } from "@mac-operator/contracts";
import { MacOsNativePeerIpcServer, type NativePeerPolicy } from "./native-peer-ipc-server.js";
import { captureSocketPathIdentity, detachOwnedSocket, removeDetachedSocket, removeStaleSocket, validateSocketParent, type SocketPathIdentity } from "./ipc-server.js";
import type { BrokerStore, RevocationKind, SwitchName } from "./persistence.js";

const AUTHORITY_CONTROL_DOMAIN = "mac-operator-authority-control-v0.1\0";
const AUTHORITY_CONTROL_RESPONSE_DOMAIN = "mac-operator-authority-control-response-v0.1\0";
export const AUTHORITY_CONTROL_SWITCH_NAMES = ["global", "mutations", "process", "network", "gui", "destructive", "privileged"] as const satisfies readonly SwitchName[];
export const AUTHORITY_CONTROL_REVOCATION_KINDS = ["principal", "session", "edge", "edge_key", "approval_key", "policy_signer", "authority_key", "helper_key", "guest_attestation_key"] as const satisfies readonly RevocationKind[];
const SWITCH_NAMES: readonly SwitchName[] = AUTHORITY_CONTROL_SWITCH_NAMES;
const REVOCATION_KINDS: readonly RevocationKind[] = AUTHORITY_CONTROL_REVOCATION_KINDS;

export type AuthorityControlOperation = "set_switch" | "revoke" | "read";

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
  | { ok: true; operation: AuthorityControlOperation; switch_name?: SwitchName; disabled?: boolean; revocation_kind?: RevocationKind; subject_id?: string; revoked?: boolean; responseProof: string }
  | { ok: false; result_class: ErrorClass; error: { message: string; retryable: boolean }; responseProof: string };

type AuthorityControlSuccessResponse = Extract<AuthorityControlIpcResponse, { ok: true }>;

export interface AuthorityControlIpcClientOptions {
  socketPath: string;
  authenticationKey: Buffer;
  timeoutMs?: number;
  maxResponseBytes?: number;
  maxRequestAgeMs?: number;
  allowedClockSkewMs?: number;
  now?: () => number;
}

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
  private socketIdentity: SocketPathIdentity | undefined;
  private readonly sockets = new Set<Socket>();
  private readonly authenticationKey: Buffer;
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
    this.authenticationKey = Buffer.from(options.authenticationKey);
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
    this.server = createServer((socket) => {
      this.sockets.add(socket);
      socket.once("close", () => this.sockets.delete(socket));
      this.handleSocket(socket);
    });
    await new Promise<void>((resolvePromise, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(this.options.socketPath, resolvePromise);
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
        if (server) {
          await new Promise<void>((resolvePromise, reject) => server.close((error) => {
            if (error && (error as NodeJS.ErrnoException).code !== "ERR_SERVER_NOT_RUNNING") reject(error);
            else resolvePromise();
          }));
        }
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
    socket.on("data", (chunk: Buffer) => {
      if (handled) return;
      total += chunk.byteLength;
      if (total > this.maxRequestBytes) {
        handled = true;
        socket.pause();
        writeAuthorityControlResponse(socket, failure("OUTPUT_LIMIT", "Authority control IPC request exceeded the byte limit", false, undefined, this.authenticationKey));
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      handled = true;
      socket.pause();
      let response: AuthorityControlIpcResponse;
      let command: UnsignedAuthorityControlCommand | undefined;
      try {
        const raw = JSON.parse(combined.subarray(0, newline).toString("utf8")) as unknown;
        command = unsignedAuthorityControlCandidate(raw);
        command = authenticateAuthorityControlCommand(
          raw,
          this.authenticationKey,
          this.now(),
          this.maxRequestAgeMs,
          this.allowedClockSkewMs
        );
        if (combined.subarray(newline + 1).some((byte) => !isAsciiWhitespace(byte))) {
          throw new BrokerError("PRECONDITION_FAILED", "Authority control IPC request contained trailing data");
        }
        this.options.store.admitAuthorityControlCommand({
          requestId: command.requestId,
          nonce: command.nonce,
          acceptedAtMs: this.now(),
          expiresAtMs: command.nonceExpiresAtMs
        });
        response = signAuthorityControlResponse(this.execute(command), command, this.authenticationKey);
      } catch (error) {
        const brokerError = error instanceof BrokerError
          ? error
          : new BrokerError("PRECONDITION_FAILED", "Authority control command is invalid");
        response = failure(brokerError.errorClass, brokerError.message, brokerError.retryable, command, this.authenticationKey);
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
        disabled: command.disabled!,
        responseProof: ""
      };
    }
    if (command.operation === "revoke") {
      this.options.store.revoke(command.revocationKind!, command.subjectId!, command.reason, command.timestampMs, command.requestId);
      return {
        ok: true,
        operation: command.operation,
        revocation_kind: command.revocationKind!,
        subject_id: command.subjectId!,
        responseProof: ""
      };
    }
    if (command.switchName !== undefined) {
      return { ok: true, operation: command.operation, switch_name: command.switchName, disabled: this.options.store.isSwitchDisabled(command.switchName), responseProof: "" };
    }
    return {
      ok: true,
      operation: command.operation,
      revocation_kind: command.revocationKind!,
      subject_id: command.subjectId!,
      revoked: this.options.store.isRevoked(command.revocationKind!, command.subjectId!),
      responseProof: ""
    };
  }
}

/**
 * Recover a structurally valid unsigned command before freshness/auth checks
 * so a client can authenticate stable failures such as AUTH_EXPIRED or
 * REPLAY_DENIED. This candidate is never admitted or executed on its own.
 */
function unsignedAuthorityControlCandidate(raw: unknown): UnsignedAuthorityControlCommand | undefined {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const record = raw as Record<string, unknown>;
  if (typeof record.authenticationProof !== "string") return undefined;
  const candidate: UnsignedAuthorityControlCommand = {
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
  try {
    validateUnsignedAuthorityControlCommand(candidate);
    return candidate;
  } catch {
    return undefined;
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

export function authenticateAuthorityControlResponse(
  raw: unknown,
  command: UnsignedAuthorityControlCommand,
  authenticationKey: Buffer
): AuthorityControlIpcResponse {
  if (authenticationKey.byteLength < 32 || raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new BrokerError("AUTH_INVALID", "Authority control response is invalid");
  }
  const record = raw as Record<string, unknown>;
  if (typeof record.responseProof !== "string" || !/^[a-f0-9]{64}$/u.test(record.responseProof)) {
    throw new BrokerError("AUTH_INVALID", "Authority control response proof is malformed");
  }
  const body = { ...record };
  delete body.responseProof;
  if (!safeEqualHex(record.responseProof, authorityControlResponseProof(command, body, authenticationKey))) {
    throw new BrokerError("AUTH_INVALID", "Authority control response authentication failed");
  }
  if (record.ok === true) {
    if (!["set_switch", "revoke", "read"].includes(record.operation as string)) {
      throw new BrokerError("PRECONDITION_FAILED", "Authority control response operation is invalid");
    }
    return record as unknown as AuthorityControlIpcResponse;
  }
  if (record.ok !== false || typeof record.result_class !== "string" || record.error === null ||
      typeof record.error !== "object" || typeof (record.error as Record<string, unknown>).message !== "string" ||
      typeof (record.error as Record<string, unknown>).retryable !== "boolean") {
    throw new BrokerError("PRECONDITION_FAILED", "Authority control response is malformed");
  }
  return record as unknown as AuthorityControlIpcResponse;
}

export class AuthorityControlIpcClient {
  private readonly authenticationKey: Buffer;
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;
  private readonly maxRequestAgeMs: number;
  private readonly allowedClockSkewMs: number;
  private readonly now: () => number;
  private disposed = false;

  constructor(private readonly options: AuthorityControlIpcClientOptions) {
    if (!isAbsolute(options.socketPath) || resolve(options.socketPath) !== options.socketPath || options.socketPath.includes("\0")) {
      throw new Error("Authority control IPC socket path must be canonical");
    }
    if (options.authenticationKey.byteLength < 32) throw new Error("Authority control IPC key must contain at least 32 bytes");
    this.authenticationKey = Buffer.from(options.authenticationKey);
    this.timeoutMs = options.timeoutMs ?? 15_000;
    this.maxResponseBytes = options.maxResponseBytes ?? 64 * 1024;
    this.maxRequestAgeMs = options.maxRequestAgeMs ?? 60_000;
    this.allowedClockSkewMs = options.allowedClockSkewMs ?? 5_000;
    this.now = options.now ?? Date.now;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > 600_000 ||
        !Number.isSafeInteger(this.maxResponseBytes) || this.maxResponseBytes < 256 || this.maxResponseBytes > 1_048_576) {
      throw new Error("Authority control IPC client limits are invalid");
    }
  }

  /** Wipe the client-owned HMAC key after the host operation completes. */
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.authenticationKey.fill(0);
  }

  async execute(command: UnsignedAuthorityControlCommand, signal?: AbortSignal): Promise<AuthorityControlSuccessResponse> {
    if (this.disposed) throw new BrokerError("CANCELLED", "Authority control IPC client is disposed");
    validateUnsignedAuthorityControlCommand(command);
    const signed = signAuthorityControlCommand(command, this.authenticationKey);
    const identity = await validateAuthorityControlSocketTarget(this.options.socketPath);
    const raw = await this.exchange(`${JSON.stringify(signed)}\n`, command, identity, signal);
    const response = authenticateAuthorityControlResponse(raw, command, this.authenticationKey);
    if (!response.ok) throw new BrokerError(response.result_class, response.error.message, response.error.retryable);
    return response as AuthorityControlSuccessResponse;
  }

  async setSwitch(
    switchName: SwitchName,
    disabled: boolean,
    expectedDisabled: boolean,
    reason: string,
    signal?: AbortSignal
  ): Promise<void> {
    const response = await this.execute(this.command({ operation: "set_switch", switchName, disabled, expectedDisabled, reason }), signal);
    if (response.operation !== "set_switch" || response.switch_name !== switchName || response.disabled !== disabled) {
      throw new BrokerError("AUTH_INVALID", "Authority control switch response does not match the command");
    }
  }

  async revoke(kind: RevocationKind, subjectId: string, reason: string, signal?: AbortSignal): Promise<void> {
    const response = await this.execute(this.command({ operation: "revoke", revocationKind: kind, subjectId, reason }), signal);
    if (response.operation !== "revoke" || response.revocation_kind !== kind || response.subject_id !== subjectId) {
      throw new BrokerError("AUTH_INVALID", "Authority control revocation response does not match the command");
    }
  }

  async readSwitch(switchName: SwitchName, signal?: AbortSignal): Promise<boolean> {
    const response = await this.execute(this.command({ operation: "read", switchName, reason: "authority-readback" }), signal);
    if (response.operation !== "read" || response.switch_name !== switchName || typeof response.disabled !== "boolean") {
      throw new BrokerError("AUTH_INVALID", "Authority control switch readback does not match the command");
    }
    return response.disabled;
  }

  async readRevocation(kind: RevocationKind, subjectId: string, signal?: AbortSignal): Promise<boolean> {
    const response = await this.execute(this.command({ operation: "read", revocationKind: kind, subjectId, reason: "authority-readback" }), signal);
    if (response.operation !== "read" || response.revocation_kind !== kind || response.subject_id !== subjectId || typeof response.revoked !== "boolean") {
      throw new BrokerError("AUTH_INVALID", "Authority control revocation readback does not match the command");
    }
    return response.revoked;
  }

  private command(fields: Pick<UnsignedAuthorityControlCommand, "operation" | "reason" | "switchName" | "disabled" | "expectedDisabled" | "revocationKind" | "subjectId">): UnsignedAuthorityControlCommand {
    const nowMs = this.now();
    const nonce = `authority-client-nonce:${randomBytes(24).toString("hex")}`;
    return {
      protocolVersion: "0.1",
      requestId: `authority-client-request:${randomBytes(18).toString("hex")}`,
      nonce,
      nonceExpiresAtMs: nowMs + this.maxRequestAgeMs,
      timestampMs: nowMs,
      ...fields
    };
  }

  private exchange(
    body: string,
    command: UnsignedAuthorityControlCommand,
    expectedIdentity: { dev: number; ino: number },
    signal: AbortSignal | undefined
  ): Promise<unknown> {
    return new Promise((resolvePromise, rejectPromise) => {
      const socket = createConnection(this.options.socketPath);
      let settled = false;
      let total = 0;
      const chunks: Buffer[] = [];
      const finish = (error?: Error, value?: unknown) => {
        if (settled) return;
        settled = true;
        signal?.removeEventListener("abort", onAbort);
        socket.destroy();
        if (error) rejectPromise(error);
        else resolvePromise(value);
      };
      const onAbort = () => finish(new BrokerError("CANCELLED", "Authority control IPC request was cancelled"));
      signal?.addEventListener("abort", onAbort, { once: true });
      if (signal?.aborted) return onAbort();
      socket.setTimeout(this.timeoutMs, () => finish(new BrokerError("TIMEOUT", "Authority control IPC request timed out", true)));
      socket.on("connect", () => {
        void lstat(this.options.socketPath).then((after) => {
          if (!after.isSocket() || after.isSymbolicLink() || after.dev !== expectedIdentity.dev || after.ino !== expectedIdentity.ino) {
            finish(new BrokerError("AUTH_INVALID", "Authority control IPC target changed while connecting"));
            return;
          }
          socket.write(body);
        }).catch(() => finish(new BrokerError("AUTH_INVALID", "Authority control IPC target could not be revalidated")));
      });
      socket.on("data", (chunk: Buffer) => {
        total += chunk.byteLength;
        if (total > this.maxResponseBytes) {
          finish(new BrokerError("OUTPUT_LIMIT", "Authority control IPC response exceeded the byte limit"));
          return;
        }
        chunks.push(chunk);
      });
      socket.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8").trim();
        try { finish(undefined, JSON.parse(text) as unknown); }
        catch { finish(new BrokerError("AUTH_INVALID", "Authority control IPC response is not valid JSON")); }
      });
      socket.on("error", () => finish(new BrokerError("EXECUTION_FAILED", "Authority control IPC transport failed", true)));
    });
  }
}

export async function validateAuthorityControlSocketTarget(socketPath: string): Promise<{ dev: number; ino: number }> {
  if (!isAbsolute(socketPath) || resolve(socketPath) !== socketPath || socketPath.includes("\0")) {
    throw new BrokerError("AUTH_INVALID", "Authority control IPC socket path is not canonical");
  }
  const parentPath = dirname(socketPath);
  const parent = await lstat(parentPath);
  const currentUid = process.getuid?.();
  if (!parent.isDirectory() || parent.isSymbolicLink() || currentUid === undefined || parent.uid !== currentUid || (parent.mode & 0o077) !== 0) {
    throw new BrokerError("AUTH_INVALID", "Authority control IPC socket directory failed ownership or permission checks");
  }
  const canonicalParent = await realpath(parentPath).catch(() => { throw new BrokerError("AUTH_INVALID", "Authority control IPC socket directory could not be canonicalized"); });
  const canonicalParentStat = await lstat(canonicalParent);
  if (!canonicalParentStat.isDirectory() || canonicalParentStat.dev !== parent.dev || canonicalParentStat.ino !== parent.ino) {
    throw new BrokerError("AUTH_INVALID", "Authority control IPC socket directory target changed while canonicalizing");
  }
  const socket = await lstat(socketPath);
  if (!socket.isSocket() || socket.isSymbolicLink() || currentUid === undefined || socket.uid !== currentUid || (socket.mode & 0o177) !== 0) {
    throw new BrokerError("AUTH_INVALID", "Authority control IPC target failed ownership or permission checks");
  }
  return { dev: socket.dev, ino: socket.ino };
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
  if (command.operation === "read") {
    const switchRead = command.switchName !== undefined && SWITCH_NAMES.includes(command.switchName) && command.revocationKind === undefined && command.subjectId === undefined;
    const revocationRead = command.switchName === undefined && REVOCATION_KINDS.includes(command.revocationKind as RevocationKind) &&
      typeof command.subjectId === "string" && /^[A-Za-z0-9._:@/-]{1,256}$/u.test(command.subjectId);
    if ((!switchRead && !revocationRead) || command.disabled !== undefined || command.expectedDisabled !== undefined) {
      throw new BrokerError("PRECONDITION_FAILED", "Authority control read command is malformed");
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

function isAsciiWhitespace(byte: number): boolean {
  return byte === 0x09 || byte === 0x0a || byte === 0x0d || byte === 0x20;
}

function signAuthorityControlResponse(
  response: AuthorityControlIpcResponse,
  command: UnsignedAuthorityControlCommand,
  authenticationKey: Buffer
): AuthorityControlIpcResponse {
  const body = { ...response };
  delete (body as { responseProof?: string }).responseProof;
  return { ...body, responseProof: authorityControlResponseProof(command, body, authenticationKey) } as AuthorityControlIpcResponse;
}

function authorityControlResponseProof(
  command: UnsignedAuthorityControlCommand,
  body: object,
  authenticationKey: Buffer
): string {
  if (authenticationKey.byteLength < 32) throw new Error("Authority control IPC key must contain at least 32 bytes");
  return createHmac("sha256", authenticationKey)
    .update(AUTHORITY_CONTROL_RESPONSE_DOMAIN, "utf8")
    .update(sha256(canonicalJson(command)), "utf8")
    .update(canonicalJson(body), "utf8")
    .digest("hex");
}

function failure(
  errorClass: ErrorClass,
  message: string,
  retryable = false,
  command: UnsignedAuthorityControlCommand | undefined,
  authenticationKey: Buffer
): AuthorityControlIpcResponse {
  const body = { ok: false as const, result_class: errorClass, error: { message, retryable } };
  const responseProof = command === undefined
    ? createHmac("sha256", authenticationKey).update(AUTHORITY_CONTROL_RESPONSE_DOMAIN, "utf8").update("invalid-command", "utf8").update(canonicalJson(body), "utf8").digest("hex")
    : authorityControlResponseProof(command, body, authenticationKey);
  return { ...body, responseProof };
}
