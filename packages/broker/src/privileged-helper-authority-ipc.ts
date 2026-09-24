import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { chmod } from "node:fs/promises";
import { connect, createServer, type Server, type Socket } from "node:net";
import { isAbsolute, resolve } from "node:path";
import {
  BrokerError,
  canonicalJson,
  CONTRACT_VERSION,
  parseJsonUtf8Strict,
  PROTOCOL_VERSION,
  sha256,
  type ErrorClass
} from "@mac-operator/contracts";
import {
  assertPrivilegedHelperCommandAuthority,
  assertPrivilegedHelperReadbackAuthority,
  authenticatePrivilegedHelperCommand,
  authenticatePrivilegedHelperJobReadbackRequest,
  type SignedPrivilegedHelperCommand,
  type SignedPrivilegedHelperJobReadbackRequest,
  type UnsignedPrivilegedHelperCommand,
  type UnsignedPrivilegedHelperJobReadbackRequest
} from "./privileged-helper.js";
import { captureSocketPathIdentity, detachOwnedSocket, removeDetachedSocket, removeStaleSocket, validateSocketParent, type SocketPathIdentity } from "./ipc-server.js";
import type { BrokerStore } from "./persistence.js";
import type { NativePeerPolicy } from "./native-peer-ipc-server.js";
import { MacOsPeerCredentialVerifier } from "./peer-credentials.js";
import { isPlainDataRecord } from "./plain-record.js";

const AUTHORITY_REQUEST_DOMAIN = "mac-operator-privileged-helper-authority-request-v0.1\0";
const AUTHORITY_RESPONSE_DOMAIN = "mac-operator-privileged-helper-authority-response-v0.1\0";
const MAX_REQUEST_BYTES = 512 * 1024;
const MAX_RESPONSE_BYTES = 64 * 1024;
const MAX_REQUEST_AGE_MS = 60_000;
const REQUEST_ID_PATTERN = /^request:helper-authority-[A-Za-z0-9._:-]{16,128}$/u;
const NONCE_PATTERN = /^helper-authority-nonce-[A-Za-z0-9._:-]{16,128}$/u;

/** One short-lived authority poll from the helper to the unprivileged Broker. */
export interface UnsignedPrivilegedHelperAuthorityRequest {
  protocolVersion: typeof PROTOCOL_VERSION;
  contractVersion: typeof CONTRACT_VERSION;
  requestId: string;
  nonce: string;
  nonceExpiresAtMs: number;
  timestampMs: number;
  expiresAtMs: number;
  kind: "authority_check";
  command: SignedPrivilegedHelperCommand;
}

export interface UnsignedPrivilegedHelperReadbackAuthorityRequest {
  protocolVersion: typeof PROTOCOL_VERSION;
  contractVersion: typeof CONTRACT_VERSION;
  requestId: string;
  nonce: string;
  nonceExpiresAtMs: number;
  timestampMs: number;
  expiresAtMs: number;
  kind: "readback_check";
  readback: SignedPrivilegedHelperJobReadbackRequest;
}

export type UnsignedPrivilegedHelperAuthorityEnvelope = UnsignedPrivilegedHelperAuthorityRequest | UnsignedPrivilegedHelperReadbackAuthorityRequest;
export type SignedPrivilegedHelperAuthorityEnvelope =
  | (UnsignedPrivilegedHelperAuthorityRequest & { authenticationProof: string })
  | (UnsignedPrivilegedHelperReadbackAuthorityRequest & { authenticationProof: string });

export interface SignedPrivilegedHelperAuthorityRequest extends UnsignedPrivilegedHelperAuthorityRequest {
  authenticationProof: string;
}

export type PrivilegedHelperAuthorityResponse =
  | {
      ok: true;
      kind: "authority_check" | "readback_check";
      requestId: string;
      commandId: string;
      authorized: true;
      responseProof: string;
    }
  | {
      ok: false;
      kind: "authority_check" | "readback_check";
      requestId: string;
      commandId: string;
      resultClass: ErrorClass;
      error: { message: string; retryable: boolean };
      responseProof: string;
    };

export interface PrivilegedHelperAuthorityReplayGuard {
  admit(input: Pick<UnsignedPrivilegedHelperAuthorityRequest, "requestId" | "nonce" | "timestampMs" | "nonceExpiresAtMs">): void;
}

/** Uses the durable helper replay ledger while keeping a direction-specific protocol domain. */
export class BrokerStorePrivilegedHelperAuthorityReplayGuard implements PrivilegedHelperAuthorityReplayGuard {
  constructor(private readonly store: Pick<BrokerStore, "admitPrivilegedHelperCommand">) {}

  admit(input: Pick<UnsignedPrivilegedHelperAuthorityRequest, "requestId" | "nonce" | "timestampMs" | "nonceExpiresAtMs">): void {
    validateAuthorityReplayInput(input);
    this.store.admitPrivilegedHelperCommand({
      requestId: input.requestId,
      nonce: input.nonce,
      acceptedAtMs: input.timestampMs,
      expiresAtMs: input.nonceExpiresAtMs
    });
  }
}

export interface PrivilegedHelperAuthorityIpcServerOptions {
  socketPath: string;
  authenticationKey: Buffer;
  replayGuard: PrivilegedHelperAuthorityReplayGuard;
  /** Broker-owned final authority. It must re-read active Job and policy state. */
  authorizeCommand: (command: UnsignedPrivilegedHelperCommand) => void;
  authorizeReadback?: (request: UnsignedPrivilegedHelperJobReadbackRequest) => void;
  peerCredentialVerifier?: { verify(socket: Socket): unknown };
  peerPolicy?: NativePeerPolicy;
  /** Optional active-key/revocation check owned by the key manager. */
  keyAuthorityCheck?: () => void;
  maxRequestBytes?: number;
  maxResponseBytes?: number;
  maxRequestAgeMs?: number;
  allowedClockSkewMs?: number;
  now?: () => number;
  onError?: (error: unknown) => void;
}

export interface BrokerPrivilegedHelperAuthorityIpcServerOptions extends Omit<PrivilegedHelperAuthorityIpcServerOptions, "replayGuard" | "authorizeCommand"> {
  store: BrokerStore;
}

/**
 * Constructs the Broker endpoint with the final persisted authority gate and
 * durable replay admission. The caller cannot replace either callback with a
 * permissive implementation.
 */
export function createBrokerPrivilegedHelperAuthorityIpcServer(
  options: BrokerPrivilegedHelperAuthorityIpcServerOptions
): PrivilegedHelperAuthorityIpcServer {
  const { store, ...serverOptions } = options;
  return new PrivilegedHelperAuthorityIpcServer({
    ...serverOptions,
    replayGuard: new BrokerStorePrivilegedHelperAuthorityReplayGuard(store),
    authorizeCommand: (command) => assertPrivilegedHelperCommandAuthority(store, command),
    authorizeReadback: (request) => assertPrivilegedHelperReadbackAuthority(store, request)
  });
}

/**
 * Broker-side endpoint used only by the privileged helper's authority polls.
 * It is intentionally separate from both the MCP Broker socket and the
 * helper command socket, and authenticates the helper peer before parsing.
 */
export class PrivilegedHelperAuthorityIpcServer {
  private server: Server | undefined;
  private nativeTransport: import("./native-peer-ipc-server.js").MacOsNativePeerIpcServer | undefined;
  private socketIdentity: SocketPathIdentity | undefined;
  private readonly sockets = new Set<Socket>();
  private readonly authenticationKey: Buffer;
  private readonly maxRequestBytes: number;
  private readonly maxResponseBytes: number;
  private readonly maxRequestAgeMs: number;
  private readonly allowedClockSkewMs: number;
  private readonly now: () => number;

  constructor(private readonly options: PrivilegedHelperAuthorityIpcServerOptions) {
    if (!canonicalAuthoritySocketPath(options.socketPath) || Buffer.byteLength(options.socketPath, "utf8") >= 104) {
      throw new Error("Privileged helper authority IPC socket path is invalid");
    }
    if (!options.peerCredentialVerifier && !options.peerPolicy) {
      throw new Error("Privileged helper authority IPC requires a peer verifier or native peer policy");
    }
    if (!Buffer.isBuffer(options.authenticationKey) || options.authenticationKey.byteLength < 32) {
      throw new Error("Privileged helper authority IPC key must contain at least 32 bytes");
    }
    if (!options.replayGuard || typeof options.authorizeCommand !== "function") {
      throw new Error("Privileged helper authority IPC requires replay and authority callbacks");
    }
    this.authenticationKey = Buffer.from(options.authenticationKey);
    this.maxRequestBytes = options.maxRequestBytes ?? MAX_REQUEST_BYTES;
    this.maxResponseBytes = options.maxResponseBytes ?? MAX_RESPONSE_BYTES;
    this.maxRequestAgeMs = options.maxRequestAgeMs ?? MAX_REQUEST_AGE_MS;
    this.allowedClockSkewMs = options.allowedClockSkewMs ?? 5_000;
    this.now = options.now ?? Date.now;
    if (!Number.isSafeInteger(this.maxRequestBytes) || this.maxRequestBytes < 512 || this.maxRequestBytes > MAX_REQUEST_BYTES * 2 ||
        !Number.isSafeInteger(this.maxResponseBytes) || this.maxResponseBytes < 256 || this.maxResponseBytes > MAX_RESPONSE_BYTES * 2 ||
        !Number.isSafeInteger(this.maxRequestAgeMs) || this.maxRequestAgeMs < 1 || this.maxRequestAgeMs > MAX_REQUEST_AGE_MS ||
        !Number.isSafeInteger(this.allowedClockSkewMs) || this.allowedClockSkewMs < 0 || this.allowedClockSkewMs > 60_000) {
      this.authenticationKey.fill(0);
      throw new Error("Privileged helper authority IPC limits are invalid");
    }
  }

  async listen(): Promise<void> {
    if (this.server || this.nativeTransport) throw new Error("Privileged helper authority IPC server is already running");
    if (this.options.peerPolicy) {
      const { MacOsNativePeerIpcServer } = await import("./native-peer-ipc-server.js");
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
        if (server) await new Promise<void>((resolvePromise, reject) => server.close((error) => {
          if (error && (error as NodeJS.ErrnoException).code !== "ERR_SERVER_NOT_RUNNING") reject(error);
          else resolvePromise();
        }));
      } finally {
        await removeDetachedSocket(detached);
      }
    } finally {
      this.authenticationKey.fill(0);
    }
  }

  private handleSocket(socket: Socket): void {
    try { this.options.peerCredentialVerifier!.verify(socket); }
    catch { socket.destroy(); return; }
    this.handleAuthenticatedSocket(socket);
  }

  private handleAuthenticatedSocket(socket: Socket): void {
    socket.setTimeout(Math.min(this.maxRequestAgeMs + this.allowedClockSkewMs, MAX_REQUEST_AGE_MS + 60_000), () => socket.destroy());
    let chunks: Buffer[] = [];
    let total = 0;
    let handled = false;
    socket.on("data", (chunk: Buffer) => {
      if (handled) return;
      total += chunk.byteLength;
      if (total > this.maxRequestBytes) {
        handled = true;
        writeAuthorityResponse(socket, authorityFailure("OUTPUT_LIMIT", "Privileged helper authority request exceeded the byte limit", "invalid-request", "invalid-command", false, undefined, this.authenticationKey), this.maxResponseBytes);
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      handled = true;
      socket.pause();
      let request: UnsignedPrivilegedHelperAuthorityEnvelope | undefined;
      let response: PrivilegedHelperAuthorityResponse;
      try {
        const raw = parseJsonUtf8Strict(combined.subarray(0, newline));
        request = unsignedAuthorityCandidate(raw);
        request = authenticatePrivilegedHelperAuthorityRequest(raw, this.authenticationKey, this.now(), this.maxRequestAgeMs, this.allowedClockSkewMs);
        if (combined.subarray(newline + 1).some((byte) => !isAsciiWhitespace(byte))) {
          throw new BrokerError("PRECONDITION_FAILED", "Privileged helper authority request contained trailing data");
        }
        this.options.keyAuthorityCheck?.();
        this.options.replayGuard.admit(request);
        const bindingId = request.kind === "authority_check"
          ? (() => {
            const command = authenticatePrivilegedHelperCommand(request.command, this.authenticationKey, this.now(), this.maxRequestAgeMs, this.allowedClockSkewMs);
            this.options.authorizeCommand(command);
            return command.commandId;
          })()
          : (() => {
            if (!this.options.authorizeReadback) throw new BrokerError("PRIVILEGE_DENIED", "Privileged helper readback authority is not enabled");
            const readback = authenticatePrivilegedHelperJobReadbackRequest(request.readback, this.authenticationKey, this.now(), this.maxRequestAgeMs, this.allowedClockSkewMs);
            this.options.authorizeReadback(readback);
            return readback.jobId;
          })();
        response = authoritySuccess(request, bindingId, this.authenticationKey);
      } catch (error) {
        const brokerError = error instanceof BrokerError ? error : new BrokerError("PRECONDITION_FAILED", "Privileged helper authority request is invalid");
        const fallback = request ?? fallbackAuthorityRequest();
        response = authorityFailure(brokerError.errorClass, brokerError.message, fallback.requestId, authorityBindingId(fallback), brokerError.retryable, request, this.authenticationKey);
      }
      writeAuthorityResponse(socket, response, this.maxResponseBytes);
    });
  }
}

export interface PrivilegedHelperAuthorityPoller {
  assertAuthorized(command: SignedPrivilegedHelperCommand): Promise<void>;
  assertReadbackAuthorized?(request: SignedPrivilegedHelperJobReadbackRequest): Promise<void>;
  dispose?: () => void;
}

export interface PrivilegedHelperAuthorityClientOptions {
  socketPath: string;
  authenticationKey: Buffer;
  /** Broker peer authentication is mandatory for the helper-side client. */
  peerCredentialVerifier?: { verify(socket: Socket): unknown };
  peerPolicy?: NativePeerPolicy;
  timeoutMs?: number;
  maxRequestAgeMs?: number;
  allowedClockSkewMs?: number;
  now?: () => number;
  keyAuthorityCheck?: () => void;
}

/** Helper-side client used by the runtime polling loop. */
export class PrivilegedHelperAuthorityClient implements PrivilegedHelperAuthorityPoller {
  private readonly authenticationKey: Buffer;
  private readonly now: () => number;
  private readonly timeoutMs: number;
  private readonly maxRequestAgeMs: number;
  private readonly allowedClockSkewMs: number;
  private readonly peerCredentialVerifier: { verify(socket: Socket): unknown };
  private disposed = false;

  constructor(private readonly options: PrivilegedHelperAuthorityClientOptions) {
    if (!canonicalAuthoritySocketPath(options.socketPath) || Buffer.byteLength(options.socketPath, "utf8") >= 104 ||
        !Buffer.isBuffer(options.authenticationKey) || options.authenticationKey.byteLength < 32) {
      throw new Error("Privileged helper authority client options are invalid");
    }
    if (!options.peerCredentialVerifier && !options.peerPolicy) {
      throw new Error("Privileged helper authority client requires a Broker peer verifier or native peer policy");
    }
    if (options.peerPolicy !== undefined && (!Number.isSafeInteger(options.peerPolicy.expectedUid) || options.peerPolicy.expectedUid < 1)) {
      throw new Error("Privileged helper authority client requires a non-root Broker peer identity");
    }
    const keyCopy = Buffer.from(options.authenticationKey);
    try {
      this.peerCredentialVerifier = options.peerCredentialVerifier ?? new MacOsPeerCredentialVerifier(options.peerPolicy!);
      this.authenticationKey = keyCopy;
    } catch (error) {
      keyCopy.fill(0);
      throw error;
    }
    this.now = options.now ?? Date.now;
    this.timeoutMs = options.timeoutMs ?? 5_000;
    this.maxRequestAgeMs = options.maxRequestAgeMs ?? MAX_REQUEST_AGE_MS;
    this.allowedClockSkewMs = options.allowedClockSkewMs ?? 5_000;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > 15_000 ||
        !Number.isSafeInteger(this.maxRequestAgeMs) || this.maxRequestAgeMs < 1 || this.maxRequestAgeMs > MAX_REQUEST_AGE_MS ||
        !Number.isSafeInteger(this.allowedClockSkewMs) || this.allowedClockSkewMs < 0 || this.allowedClockSkewMs > 60_000) {
      this.authenticationKey.fill(0);
      throw new Error("Privileged helper authority client limits are invalid");
    }
  }

  async assertAuthorized(command: SignedPrivilegedHelperCommand): Promise<void> {
    if (this.disposed) throw new BrokerError("CANCELLED", "Privileged helper authority client is disposed");
    this.options.keyAuthorityCheck?.();
    const timestampMs = this.now();
    if (!Number.isSafeInteger(timestampMs) || timestampMs < 0) throw new BrokerError("PRECONDITION_FAILED", "Privileged helper authority client clock is invalid");
    const expiresAtMs = Math.min(timestampMs + this.timeoutMs, command.expiresAtMs);
    if (expiresAtMs <= timestampMs) throw new BrokerError("AUTH_EXPIRED", "Privileged helper command is no longer executable");
    const request: UnsignedPrivilegedHelperAuthorityRequest = {
      protocolVersion: PROTOCOL_VERSION,
      contractVersion: CONTRACT_VERSION,
      requestId: `request:helper-authority-${randomBytes(16).toString("hex")}`,
      nonce: `helper-authority-nonce-${randomBytes(16).toString("hex")}`,
      nonceExpiresAtMs: expiresAtMs,
      timestampMs,
      expiresAtMs,
      kind: "authority_check",
      command
    };
    const signed = signPrivilegedHelperAuthorityRequest(request, this.authenticationKey);
    const before = await this.captureSocket();
    try {
      const response = await exchangeAuthoritySocket(this.options.socketPath, `${JSON.stringify(signed)}\n`, this.timeoutMs, this.peerCredentialVerifier);
      const after = await this.captureSocket();
      if (before.device !== after.device || before.inode !== after.inode) {
        throw new BrokerError("CONFLICT", "Privileged helper authority socket identity changed during polling", true);
      }
      const verified = authenticatePrivilegedHelperAuthorityResponse(response, request, this.authenticationKey);
      if (!verified.ok) throw new BrokerError(verified.resultClass, verified.error.message, verified.error.retryable);
    } finally {
      this.options.keyAuthorityCheck?.();
    }
  }

  async assertReadbackAuthorized(readback: SignedPrivilegedHelperJobReadbackRequest): Promise<void> {
    if (this.disposed) throw new BrokerError("CANCELLED", "Privileged helper authority client is disposed");
    this.options.keyAuthorityCheck?.();
    const timestampMs = this.now();
    if (!Number.isSafeInteger(timestampMs) || timestampMs < 0) throw new BrokerError("PRECONDITION_FAILED", "Privileged helper authority client clock is invalid");
    const expiresAtMs = Math.min(timestampMs + this.timeoutMs, readback.expiresAtMs);
    if (expiresAtMs <= timestampMs) throw new BrokerError("AUTH_EXPIRED", "Privileged helper readback is no longer authorized");
    const request: UnsignedPrivilegedHelperReadbackAuthorityRequest = {
      protocolVersion: PROTOCOL_VERSION,
      contractVersion: CONTRACT_VERSION,
      requestId: `request:helper-authority-${randomBytes(16).toString("hex")}`,
      nonce: `helper-authority-nonce-${randomBytes(16).toString("hex")}`,
      nonceExpiresAtMs: expiresAtMs,
      timestampMs,
      expiresAtMs,
      kind: "readback_check",
      readback
    };
    const signed = signPrivilegedHelperAuthorityRequest(request, this.authenticationKey);
    const before = await this.captureSocket();
    try {
      const response = await exchangeAuthoritySocket(this.options.socketPath, `${JSON.stringify(signed)}\n`, this.timeoutMs, this.peerCredentialVerifier);
      const after = await this.captureSocket();
      if (before.device !== after.device || before.inode !== after.inode) {
        throw new BrokerError("CONFLICT", "Privileged helper authority socket identity changed during readback polling", true);
      }
      const verified = authenticatePrivilegedHelperAuthorityResponse(response, request, this.authenticationKey);
      if (!verified.ok) throw new BrokerError(verified.resultClass, verified.error.message, verified.error.retryable);
    } finally {
      this.options.keyAuthorityCheck?.();
    }
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.authenticationKey.fill(0);
  }

  private async captureSocket(): Promise<SocketPathIdentity> {
    try { return await captureSocketPathIdentity(this.options.socketPath); }
    catch { throw new BrokerError("TARGET_NOT_FOUND", "Privileged helper authority socket is unavailable"); }
  }
}

export function signPrivilegedHelperAuthorityRequest(
  request: UnsignedPrivilegedHelperAuthorityEnvelope,
  authenticationKey: Buffer
): SignedPrivilegedHelperAuthorityEnvelope {
  validateUnsignedPrivilegedHelperAuthorityRequest(request);
  if (authenticationKey.byteLength < 32) throw new BrokerError("AUTH_INVALID", "Privileged helper authority key is invalid");
  return { ...request, authenticationProof: authorityRequestProof(request, authenticationKey) };
}

export function authenticatePrivilegedHelperAuthorityRequest(
  raw: unknown,
  authenticationKey: Buffer,
  nowMs: number,
  maxRequestAgeMs = MAX_REQUEST_AGE_MS,
  allowedClockSkewMs = 5_000
): UnsignedPrivilegedHelperAuthorityEnvelope {
  if (authenticationKey.byteLength < 32) throw new BrokerError("AUTH_INVALID", "Privileged helper authority key is invalid");
  const parsed = parseSignedAuthorityRequest(raw);
  const request = parsed.unsigned;
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || request.timestampMs > nowMs + allowedClockSkewMs ||
      nowMs - request.timestampMs > maxRequestAgeMs || request.expiresAtMs <= nowMs ||
      request.expiresAtMs <= request.timestampMs || request.expiresAtMs > request.timestampMs + maxRequestAgeMs + allowedClockSkewMs ||
      request.nonceExpiresAtMs <= nowMs || request.nonceExpiresAtMs <= request.timestampMs ||
      request.nonceExpiresAtMs > request.timestampMs + maxRequestAgeMs + allowedClockSkewMs) {
    throw new BrokerError("AUTH_EXPIRED", "Privileged helper authority timestamp is outside the accepted window");
  }
  if (!safeEqualHex(parsed.authenticationProof, authorityRequestProof(request, authenticationKey))) {
    throw new BrokerError("AUTH_INVALID", "Privileged helper authority authentication failed");
  }
  return request;
}

export function validateUnsignedPrivilegedHelperAuthorityRequest(request: UnsignedPrivilegedHelperAuthorityEnvelope): void {
  if (!isPlainDataRecord(request)) throw new BrokerError("PRECONDITION_FAILED", "Privileged helper authority request fields are malformed");
  const keys = Object.keys(request);
  const common = ["protocolVersion", "contractVersion", "requestId", "nonce", "nonceExpiresAtMs", "timestampMs", "expiresAtMs", "kind"];
  const target = request.kind === "authority_check" ? ["command"] : request.kind === "readback_check" ? ["readback"] : [];
  if (target.length === 0 || keys.length !== common.length + target.length || [...common, ...target].some((key) => !keys.includes(key)) ||
      request.protocolVersion !== PROTOCOL_VERSION || request.contractVersion !== CONTRACT_VERSION ||
      !REQUEST_ID_PATTERN.test(request.requestId) || !NONCE_PATTERN.test(request.nonce) ||
      !Number.isSafeInteger(request.timestampMs) || request.timestampMs < 0 ||
      !Number.isSafeInteger(request.expiresAtMs) || request.expiresAtMs <= request.timestampMs ||
      !Number.isSafeInteger(request.nonceExpiresAtMs) || request.nonceExpiresAtMs <= request.timestampMs ||
      (request.kind === "authority_check" && !isPlainDataRecord(request.command)) ||
      (request.kind === "readback_check" && !isPlainDataRecord(request.readback))) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper authority request fields are malformed");
  }
}

export function authenticatePrivilegedHelperAuthorityResponse(
  raw: unknown,
  request: UnsignedPrivilegedHelperAuthorityEnvelope,
  authenticationKey: Buffer
): PrivilegedHelperAuthorityResponse {
  validateUnsignedPrivilegedHelperAuthorityRequest(request);
  if (authenticationKey.byteLength < 32 || !isPlainDataRecord(raw)) throw new BrokerError("AUTH_INVALID", "Privileged helper authority response is invalid");
  const response = raw as Record<string, unknown>;
  if (response.kind !== request.kind || response.requestId !== request.requestId || response.commandId !== authorityBindingId(request) ||
      typeof response.responseProof !== "string") {
    throw new BrokerError("AUTH_INVALID", "Privileged helper authority response identity is invalid");
  }
  const successKeys = ["ok", "kind", "requestId", "commandId", "authorized", "responseProof"];
  const failureKeys = ["ok", "kind", "requestId", "commandId", "resultClass", "error", "responseProof"];
  const expected = response.ok === true ? successKeys : response.ok === false ? failureKeys : [];
  const keys = Object.keys(response);
  if (expected.length === 0 || keys.length !== expected.length || expected.some((key) => !keys.includes(key))) {
    throw new BrokerError("EXECUTION_FAILED", "Privileged helper authority response fields are malformed");
  }
  const body = { ...response };
  delete body.responseProof;
  if (!safeEqualHex(response.responseProof as string, authorityResponseProof(request, body, authenticationKey))) {
    throw new BrokerError("AUTH_INVALID", "Privileged helper authority response authentication failed");
  }
  if (response.ok === true) {
    if (response.authorized !== true) throw new BrokerError("EXECUTION_FAILED", "Privileged helper authority success is malformed");
    return response as unknown as PrivilegedHelperAuthorityResponse;
  }
  const errorRecord = response.error as Record<string, unknown>;
  if (response.ok !== false || typeof response.resultClass !== "string" || !isHelperErrorClass(response.resultClass) ||
      !isPlainDataRecord(response.error) || Object.keys(errorRecord).length !== 2 ||
      !Object.hasOwn(errorRecord, "message") || !Object.hasOwn(errorRecord, "retryable") ||
      typeof errorRecord.message !== "string" || typeof errorRecord.retryable !== "boolean" ||
      boundedMessage(errorRecord.message) !== errorRecord.message) {
    throw new BrokerError("EXECUTION_FAILED", "Privileged helper authority failure is malformed");
  }
  return response as unknown as PrivilegedHelperAuthorityResponse;
}

function authoritySuccess(request: UnsignedPrivilegedHelperAuthorityEnvelope, bindingId: string, key: Buffer): Extract<PrivilegedHelperAuthorityResponse, { ok: true }> {
  const body = { ok: true as const, kind: request.kind, requestId: request.requestId, commandId: bindingId, authorized: true as const };
  return { ...body, responseProof: authorityResponseProof(request, body, key) };
}

function authorityFailure(
  resultClass: ErrorClass,
  message: string,
  requestId: string,
  commandId: string,
  retryable: boolean,
  request: UnsignedPrivilegedHelperAuthorityEnvelope | undefined,
  key: Buffer
): Extract<PrivilegedHelperAuthorityResponse, { ok: false }> {
  const body = { ok: false as const, kind: request?.kind ?? "authority_check" as const, requestId, commandId, resultClass, error: { message: boundedMessage(message), retryable } };
  return { ...body, responseProof: authorityResponseProof(request, body, key) };
}

function parseSignedAuthorityRequest(value: unknown): { unsigned: UnsignedPrivilegedHelperAuthorityEnvelope; authenticationProof: string } {
  if (!isPlainDataRecord(value)) throw new BrokerError("PRECONDITION_FAILED", "Privileged helper authority envelope is malformed");
  const record = value as Record<string, unknown>;
  const common = ["protocolVersion", "contractVersion", "requestId", "nonce", "nonceExpiresAtMs", "timestampMs", "expiresAtMs", "kind"];
  const target = record.kind === "authority_check" ? ["command"] : record.kind === "readback_check" ? ["readback"] : [];
  const allowed = [...common, ...target, "authenticationProof"];
  if (target.length === 0 || Object.keys(record).length !== allowed.length || allowed.some((key) => !Object.hasOwn(record, key)) ||
      typeof record.authenticationProof !== "string" || !/^[a-f0-9]{64}$/u.test(record.authenticationProof)) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper authority envelope is malformed");
  }
  const commonFields = {
    protocolVersion: record.protocolVersion as typeof PROTOCOL_VERSION,
    contractVersion: record.contractVersion as typeof CONTRACT_VERSION,
    requestId: record.requestId as string,
    nonce: record.nonce as string,
    nonceExpiresAtMs: record.nonceExpiresAtMs as number,
    timestampMs: record.timestampMs as number,
    expiresAtMs: record.expiresAtMs as number,
    kind: record.kind as "authority_check" | "readback_check"
  };
  const unsigned = record.kind === "authority_check"
    ? { ...commonFields, kind: "authority_check" as const, command: record.command as SignedPrivilegedHelperCommand }
    : { ...commonFields, kind: "readback_check" as const, readback: record.readback as SignedPrivilegedHelperJobReadbackRequest };
  validateUnsignedPrivilegedHelperAuthorityRequest(unsigned);
  return { unsigned, authenticationProof: record.authenticationProof as string };
}

function unsignedAuthorityCandidate(raw: unknown): UnsignedPrivilegedHelperAuthorityEnvelope | undefined {
  try { return parseSignedAuthorityRequest(raw).unsigned; }
  catch { return undefined; }
}

function validateAuthorityReplayInput(input: Pick<UnsignedPrivilegedHelperAuthorityEnvelope, "requestId" | "nonce" | "timestampMs" | "nonceExpiresAtMs">): void {
  if (!REQUEST_ID_PATTERN.test(input.requestId) || !NONCE_PATTERN.test(input.nonce) || !Number.isSafeInteger(input.timestampMs) ||
      input.timestampMs < 0 || !Number.isSafeInteger(input.nonceExpiresAtMs) || input.nonceExpiresAtMs <= input.timestampMs) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper authority replay admission is malformed");
  }
}

function authorityRequestProof(request: UnsignedPrivilegedHelperAuthorityEnvelope, key: Buffer): string {
  if (key.byteLength < 32) throw new Error("Privileged helper authority key must contain at least 32 bytes");
  return createHmac("sha256", key).update(AUTHORITY_REQUEST_DOMAIN, "utf8").update(sha256(canonicalJson(request)), "utf8").digest("hex");
}

function authorityResponseProof(request: UnsignedPrivilegedHelperAuthorityEnvelope | undefined, body: object, key: Buffer): string {
  if (key.byteLength < 32) throw new Error("Privileged helper authority key must contain at least 32 bytes");
  return createHmac("sha256", key)
    .update(AUTHORITY_RESPONSE_DOMAIN, "utf8")
    .update(request ? sha256(canonicalJson(request)) : "invalid-authority-request", "utf8")
    .update(canonicalJson(body), "utf8")
    .digest("hex");
}

async function exchangeAuthoritySocket(
  socketPath: string,
  serialized: string,
  timeoutMs: number,
  peerCredentialVerifier: { verify(socket: Socket): unknown }
): Promise<unknown> {
  return new Promise<unknown>((resolvePromise, reject) => {
    const socket = connect(socketPath);
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const fail = (error: unknown) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(error);
    };
    socket.setTimeout(timeoutMs, () => fail(new BrokerError("TIMEOUT", "Privileged helper authority poll timed out", true)));
    socket.once("error", () => fail(new BrokerError("UNKNOWN_OUTCOME", "Privileged helper authority transport failed", true)));
    socket.on("data", (chunk: Buffer) => {
      if (settled) return;
      total += chunk.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        fail(new BrokerError("OUTPUT_LIMIT", "Privileged helper authority response exceeded the byte limit"));
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      if (combined.subarray(newline + 1).some((byte) => !isAsciiWhitespace(byte))) {
        fail(new BrokerError("AUTH_INVALID", "Privileged helper authority response contained trailing data"));
        return;
      }
      settled = true;
      socket.destroy();
      try { resolvePromise(parseJsonUtf8Strict(combined.subarray(0, newline))); }
      catch { reject(new BrokerError("EXECUTION_FAILED", "Privileged helper authority response is not valid JSON")); }
    });
    socket.on("close", () => {
      if (!settled) fail(new BrokerError("UNKNOWN_OUTCOME", "Privileged helper authority channel closed without a response", true));
    });
    socket.once("connect", () => {
      try {
        peerCredentialVerifier.verify(socket);
        socket.write(serialized);
      } catch {
        fail(new BrokerError("AUTH_INVALID", "Privileged helper authority Broker peer authentication failed"));
      }
    });
  });
}

function writeAuthorityResponse(socket: Socket, response: PrivilegedHelperAuthorityResponse, maxBytes: number): void {
  if (socket.destroyed) return;
  const serialized = `${JSON.stringify(response)}\n`;
  if (Buffer.byteLength(serialized, "utf8") <= maxBytes) socket.end(serialized);
  else socket.destroy();
}

function authorityBindingId(request: UnsignedPrivilegedHelperAuthorityEnvelope): string {
  return request.kind === "authority_check" ? request.command.commandId : request.readback.jobId;
}

function fallbackAuthorityRequest(): UnsignedPrivilegedHelperAuthorityRequest {
  return {
    protocolVersion: PROTOCOL_VERSION,
    contractVersion: CONTRACT_VERSION,
    requestId: "request:helper-authority-invalid",
    nonce: "helper-authority-nonce-invalid-invalid",
    nonceExpiresAtMs: 1,
    timestampMs: 0,
    expiresAtMs: 1,
    kind: "authority_check",
    command: {
      protocolVersion: PROTOCOL_VERSION,
      contractVersion: CONTRACT_VERSION,
      commandId: "priv-command:invalid",
      requestId: "request:invalid",
      nonce: "invalid-invalid-invalid",
      nonceExpiresAtMs: 1,
      timestampMs: 0,
      expiresAtMs: 1,
      operation: "power",
      targetRef: "host:local",
      payload: { operation: "power", action: "reboot" },
      payloadDigest: "0".repeat(64),
      policyVersion: "policy-invalid",
      approvalId: "approval:invalid",
      intentId: "intent:invalid",
      authenticationProof: "0".repeat(64)
    }
  };
}

function canonicalAuthoritySocketPath(value: unknown): value is string {
  return typeof value === "string" && isAbsolute(value) && resolve(value) === value && !value.includes("\0");
}

function safeEqualHex(actual: string, expected: string): boolean {
  if (!/^[a-f0-9]{64}$/u.test(actual) || !/^[a-f0-9]{64}$/u.test(expected)) return false;
  return timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}

function isAsciiWhitespace(byte: number): boolean {
  return byte === 0x09 || byte === 0x0a || byte === 0x0c || byte === 0x0d || byte === 0x20;
}

function boundedMessage(value: string): string {
  return value.length <= 512 && !value.includes("\0") && !/[\r\n]/u.test(value) ? value : "Privileged helper authority request failed";
}

function isHelperErrorClass(value: string): value is ErrorClass {
  return (Object.values([
    "AUTH_REQUIRED", "AUTH_INVALID", "AUTH_EXPIRED", "REPLAY_DENIED", "REVOKED", "SCOPE_DENIED",
    "SECRET_BOUNDARY_DENIED", "PATH_DENIED", "NETWORK_DENIED", "PRIVILEGE_DENIED", "POLICY_DENIED",
    "TARGET_NOT_FOUND", "PRECONDITION_FAILED", "CONFLICT", "TIMEOUT", "OUTPUT_LIMIT", "CANCELLED",
    "EXECUTION_FAILED", "VERIFICATION_FAILED", "AUDIT_UNAVAILABLE", "UNKNOWN_OUTCOME", "UNSUPPORTED_CAPABILITY"
  ] as const) as readonly string[]).includes(value);
}
