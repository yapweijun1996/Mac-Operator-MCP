import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { chmod, lstat, realpath } from "node:fs/promises";
import { connect, createServer, type Server, type Socket } from "node:net";
import { dirname, isAbsolute, resolve } from "node:path";
import { BrokerError, canonicalJson, CONTRACT_VERSION, parseJsonUtf8Strict, PROTOCOL_VERSION, sha256, type ErrorClass } from "@mac-operator/contracts";
import type { BrokerServiceReadback } from "./service-entrypoint.js";
import { MacOsNativePeerIpcServer, type NativePeerPolicy } from "./native-peer-ipc-server.js";
import { captureSocketPathIdentity, detachOwnedSocket, removeDetachedSocket, removeStaleSocket, validateSocketParent, type SocketPathIdentity } from "./ipc-server.js";
import type { BrokerStore } from "./persistence.js";
import { isPlainDataRecord } from "./plain-record.js";

const STATUS_REQUEST_DOMAIN = "mac-operator-broker-status-request-v0.1\0";
const STATUS_RESPONSE_DOMAIN = "mac-operator-broker-status-response-v0.1\0";
const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 128 * 1024;
const MAX_REQUEST_AGE_MS = 60_000;
const STATUS_REQUEST_ID_PATTERN = /^request:broker-status-[A-Za-z0-9._:-]{16,128}$/u;
const STATUS_NONCE_PATTERN = /^broker-status-nonce-[A-Za-z0-9._:-]{16,128}$/u;

export interface UnsignedBrokerStatusRequest {
  protocolVersion: typeof PROTOCOL_VERSION;
  contractVersion: typeof CONTRACT_VERSION;
  requestId: string;
  nonce: string;
  timestampMs: number;
  expiresAtMs: number;
  kind: "broker_status";
}

export interface SignedBrokerStatusRequest extends UnsignedBrokerStatusRequest {
  authenticationProof: string;
}

export type BrokerStatusSuccessResponse = {
  ok: true;
  kind: "broker_status";
  requestId: string;
  status: BrokerServiceReadback;
  responseProof: string;
};

export type BrokerStatusFailureResponse = {
  ok: false;
  kind: "broker_status";
  requestId: string;
  resultClass: ErrorClass;
  error: { message: string; retryable: boolean };
  responseProof: string;
};

export type BrokerStatusResponse = BrokerStatusSuccessResponse | BrokerStatusFailureResponse;

export interface BrokerStatusReplayGuard {
  admit(input: Pick<UnsignedBrokerStatusRequest, "requestId" | "nonce" | "timestampMs" | "expiresAtMs">): void;
}

export class BrokerStoreBrokerStatusReplayGuard implements BrokerStatusReplayGuard {
  constructor(private readonly store: Pick<BrokerStore, "admitBrokerStatusRequest">) {}

  admit(input: Pick<UnsignedBrokerStatusRequest, "requestId" | "nonce" | "timestampMs" | "expiresAtMs">): void {
    this.store.admitBrokerStatusRequest(input);
  }
}

export interface BrokerStatusIpcServerOptions {
  socketPath: string;
  authenticationKey: Buffer;
  replayGuard: BrokerStatusReplayGuard;
  readStatus: () => BrokerServiceReadback;
  authorizeStatus: () => void;
  peerCredentialVerifier?: { verify(socket: Socket): unknown };
  peerPolicy?: NativePeerPolicy;
  maxRequestBytes?: number;
  maxRequestAgeMs?: number;
  allowedClockSkewMs?: number;
  now?: () => number;
  onError?: (error: unknown) => void;
}

export class BrokerStatusIpcServer {
  private server: Server | undefined;
  private nativeTransport: MacOsNativePeerIpcServer | undefined;
  private socketIdentity: SocketPathIdentity | undefined;
  private readonly sockets = new Set<Socket>();
  private readonly authenticationKey: Buffer;
  private readonly maxRequestBytes: number;
  private readonly maxRequestAgeMs: number;
  private readonly allowedClockSkewMs: number;
  private readonly now: () => number;

  constructor(private readonly options: BrokerStatusIpcServerOptions) {
    if (!canonicalStatusPath(options.socketPath) || Buffer.byteLength(options.socketPath, "utf8") >= 104) {
      throw new Error("Broker status IPC socket path is invalid");
    }
    if (!options.peerCredentialVerifier && !options.peerPolicy) {
      throw new Error("Broker status IPC requires a peer verifier or native peer policy");
    }
    if (!Buffer.isBuffer(options.authenticationKey) || options.authenticationKey.byteLength < 32) {
      throw new Error("Broker status IPC key must contain at least 32 bytes");
    }
    if (typeof options.readStatus !== "function" || typeof options.authorizeStatus !== "function") {
      throw new Error("Broker status IPC requires Broker-owned read and authority callbacks");
    }
    const maxRequestBytes = options.maxRequestBytes ?? MAX_REQUEST_BYTES;
    const maxRequestAgeMs = options.maxRequestAgeMs ?? MAX_REQUEST_AGE_MS;
    const allowedClockSkewMs = options.allowedClockSkewMs ?? 5_000;
    if (!Number.isSafeInteger(maxRequestBytes) || maxRequestBytes < 256 || maxRequestBytes > MAX_REQUEST_BYTES * 4 ||
        !Number.isSafeInteger(maxRequestAgeMs) || maxRequestAgeMs < 1 || maxRequestAgeMs > MAX_REQUEST_AGE_MS ||
        !Number.isSafeInteger(allowedClockSkewMs) || allowedClockSkewMs < 0 || allowedClockSkewMs > 60_000) {
      throw new Error("Broker status IPC limits are invalid");
    }
    this.authenticationKey = Buffer.from(options.authenticationKey);
    this.maxRequestBytes = maxRequestBytes;
    this.maxRequestAgeMs = maxRequestAgeMs;
    this.allowedClockSkewMs = allowedClockSkewMs;
    this.now = options.now ?? Date.now;
  }

  async listen(): Promise<void> {
    if (this.server || this.nativeTransport) throw new Error("Broker status IPC server is already running");
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
        writeStatusResponse(socket, statusFailure("OUTPUT_LIMIT", "Broker status request exceeded the byte limit", "invalid-request", false, undefined, this.authenticationKey));
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      handled = true;
      socket.pause();
      let request: UnsignedBrokerStatusRequest | undefined;
      let response: BrokerStatusResponse;
      try {
        const raw = parseJsonUtf8Strict(combined.subarray(0, newline));
        request = unsignedBrokerStatusCandidate(raw);
        request = authenticateBrokerStatusRequest(raw, this.authenticationKey, this.now(), this.maxRequestAgeMs, this.allowedClockSkewMs);
        if (combined.subarray(newline + 1).some((byte) => !isAsciiWhitespace(byte))) {
          throw new BrokerError("PRECONDITION_FAILED", "Broker status request contained trailing data");
        }
        this.options.replayGuard.admit(request);
        this.options.authorizeStatus();
        response = statusSuccess(request, validateBrokerStatusReadback(this.options.readStatus()), this.authenticationKey);
      } catch (error) {
        const brokerError = error instanceof BrokerError ? error : new BrokerError("PRECONDITION_FAILED", "Broker status request is invalid");
        const fallback = request ?? fallbackRequest();
        response = statusFailure(brokerError.errorClass, brokerError.message, fallback.requestId, brokerError.retryable, request, this.authenticationKey);
      }
      writeStatusResponse(socket, response);
    });
  }
}

export interface BrokerStatusClientOptions {
  socketPath: string;
  authenticationKey: Buffer;
  timeoutMs?: number;
  maxResponseBytes?: number;
  maxRequestAgeMs?: number;
  allowedClockSkewMs?: number;
  now?: () => number;
}

export async function readBrokerStatus(options: BrokerStatusClientOptions): Promise<BrokerServiceReadback> {
  if (options === null || typeof options !== "object" || !canonicalStatusPath(options.socketPath) ||
      !Buffer.isBuffer(options.authenticationKey) || options.authenticationKey.byteLength < 32) {
    throw new BrokerError("PRECONDITION_FAILED", "Broker status client options are invalid");
  }
  const timeoutMs = options.timeoutMs ?? 5_000;
  const maxRequestAgeMs = options.maxRequestAgeMs ?? MAX_REQUEST_AGE_MS;
  const allowedClockSkewMs = options.allowedClockSkewMs ?? 5_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 15_000 ||
      !Number.isSafeInteger(maxRequestAgeMs) || maxRequestAgeMs < 1 || maxRequestAgeMs > MAX_REQUEST_AGE_MS ||
      !Number.isSafeInteger(allowedClockSkewMs) || allowedClockSkewMs < 0 || allowedClockSkewMs > 60_000) {
    throw new BrokerError("PRECONDITION_FAILED", "Broker status client limits are invalid");
  }
  const now = options.now ?? Date.now;
  const timestampMs = now();
  if (!Number.isSafeInteger(timestampMs) || timestampMs < 0) throw new BrokerError("PRECONDITION_FAILED", "Broker status client clock is invalid");
  const request: UnsignedBrokerStatusRequest = {
    protocolVersion: PROTOCOL_VERSION,
    contractVersion: CONTRACT_VERSION,
    requestId: `request:broker-status-${randomBytes(16).toString("hex")}`,
    nonce: `broker-status-nonce-${randomBytes(16).toString("hex")}`,
    timestampMs,
    expiresAtMs: timestampMs + Math.min(timeoutMs, maxRequestAgeMs),
    kind: "broker_status"
  };
  const key = Buffer.from(options.authenticationKey);
  const signed = signBrokerStatusRequest(request, key);
  const before = await validateBrokerStatusSocketTarget(options.socketPath);
  try {
    const response = await exchangeStatusSocket(options.socketPath, `${JSON.stringify(signed)}\n`, timeoutMs, options.maxResponseBytes ?? MAX_RESPONSE_BYTES);
    const after = await validateBrokerStatusSocketTarget(options.socketPath);
    if (before.device !== after.device || before.inode !== after.inode) throw new BrokerError("CONFLICT", "Broker status socket identity changed during readback");
    const verified = authenticateBrokerStatusResponse(response, request, key);
    if (!verified.ok) throw new BrokerError(verified.resultClass, verified.error.message, verified.error.retryable);
    return verified.status;
  } finally {
    key.fill(0);
  }
}

export function signBrokerStatusRequest(request: UnsignedBrokerStatusRequest, authenticationKey: Buffer): SignedBrokerStatusRequest {
  validateUnsignedBrokerStatusRequest(request);
  return { ...request, authenticationProof: statusRequestProof(request, authenticationKey) };
}

export function authenticateBrokerStatusRequest(
  raw: unknown,
  authenticationKey: Buffer,
  nowMs: number,
  maxRequestAgeMs = MAX_REQUEST_AGE_MS,
  allowedClockSkewMs = 5_000
): UnsignedBrokerStatusRequest {
  const parsed = parseSignedBrokerStatusRequest(raw);
  const request = parsed.unsigned;
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || request.timestampMs > nowMs + allowedClockSkewMs ||
      nowMs - request.timestampMs > maxRequestAgeMs || request.expiresAtMs <= nowMs ||
      request.expiresAtMs <= request.timestampMs || request.expiresAtMs > request.timestampMs + maxRequestAgeMs + allowedClockSkewMs) {
    throw new BrokerError("AUTH_EXPIRED", "Broker status timestamp is outside the accepted window");
  }
  if (!safeEqualHex(parsed.authenticationProof, statusRequestProof(request, authenticationKey))) {
    throw new BrokerError("AUTH_INVALID", "Broker status authentication failed");
  }
  return request;
}

export function validateUnsignedBrokerStatusRequest(request: UnsignedBrokerStatusRequest): void {
  const allowed = ["protocolVersion", "contractVersion", "requestId", "nonce", "timestampMs", "expiresAtMs", "kind"];
  if (!isPlainDataRecord(request)) {
    throw new BrokerError("PRECONDITION_FAILED", "Broker status request fields are malformed");
  }
  const keys = Object.keys(request);
  if (keys.length !== allowed.length || allowed.some((key) => !keys.includes(key)) ||
      request.protocolVersion !== PROTOCOL_VERSION || request.contractVersion !== CONTRACT_VERSION ||
      !STATUS_REQUEST_ID_PATTERN.test(request.requestId) || !STATUS_NONCE_PATTERN.test(request.nonce) ||
      !Number.isSafeInteger(request.timestampMs) || request.timestampMs < 0 ||
      !Number.isSafeInteger(request.expiresAtMs) || request.expiresAtMs <= request.timestampMs || request.kind !== "broker_status") {
    throw new BrokerError("PRECONDITION_FAILED", "Broker status request fields are malformed");
  }
}

export function validateBrokerStatusReadback(status: BrokerServiceReadback): BrokerServiceReadback {
  if (!isPlainDataRecord(status) ||
      status.component !== "mac-operator-broker" ||
      !["stopped", "starting", "running", "stopping", "failed"].includes(status.state) ||
      !["stopped", "starting", "running", "stopping", "failed"].includes(status.runtimeState) ||
      status.nativeTransportRequired !== true || !/^[0-9a-f]{7,64}$/u.test(status.sourceRevision) ||
      !/^v?\d+\.\d+(?:\.\d+)?(?:[-+].*)?$/u.test(status.contractVersion) ||
      !/^(?:policy-[1-9][0-9]*|\d+\.\d+(?:\.\d+)?(?:[-+].*)?)$/u.test(status.policyVersion) ||
      !isDenseArray(status.enabledCapabilities, 128) ||
      status.enabledCapabilities.some((capability) => typeof capability !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(capability))) {
    throw new BrokerError("EXECUTION_FAILED", "Broker status readback is malformed");
  }
  return { ...status, enabledCapabilities: [...status.enabledCapabilities] };
}

export function authenticateBrokerStatusResponse(
  raw: unknown,
  request: UnsignedBrokerStatusRequest,
  authenticationKey: Buffer
): BrokerStatusResponse {
  validateUnsignedBrokerStatusRequest(request);
  if (authenticationKey.byteLength < 32 || !isPlainDataRecord(raw)) {
    throw new BrokerError("AUTH_INVALID", "Broker status response is invalid");
  }
  const response = raw as Record<string, unknown>;
  if (response.kind !== "broker_status" || response.requestId !== request.requestId || typeof response.responseProof !== "string") {
    throw new BrokerError("AUTH_INVALID", "Broker status response identity is invalid");
  }
  const body = { ...response };
  delete body.responseProof;
  if (!safeEqualHex(response.responseProof as string, statusResponseProof(request, body, authenticationKey))) {
    throw new BrokerError("AUTH_INVALID", "Broker status response authentication failed");
  }
  if (response.ok === true) {
    const expected = ["ok", "kind", "requestId", "status", "responseProof"];
    if (!sameKeys(response, expected)) throw new BrokerError("EXECUTION_FAILED", "Broker status response fields are malformed");
    return { ...(response as unknown as BrokerStatusSuccessResponse), status: validateBrokerStatusReadback(response.status as BrokerServiceReadback) };
  }
  const expected = ["ok", "kind", "requestId", "resultClass", "error", "responseProof"];
  if (response.ok !== false || !sameKeys(response, expected) || typeof response.resultClass !== "string" ||
      !isPlainDataRecord(response.error) || !sameKeys(response.error as Record<string, unknown>, ["message", "retryable"]) ||
      typeof (response.error as Record<string, unknown>).message !== "string" ||
      typeof (response.error as Record<string, unknown>).retryable !== "boolean" ||
      !boundedStatusMessage((response.error as Record<string, unknown>).message as string)) {
    throw new BrokerError("EXECUTION_FAILED", "Broker status failure is malformed");
  }
  return response as unknown as BrokerStatusFailureResponse;
}

export async function validateBrokerStatusSocketTarget(socketPath: string): Promise<SocketPathIdentity> {
  if (!canonicalStatusPath(socketPath)) throw new BrokerError("AUTH_INVALID", "Broker status socket path is not canonical");
  const parentPath = dirname(socketPath);
  const parent = await lstat(parentPath);
  const uid = process.getuid?.();
  if (!parent.isDirectory() || parent.isSymbolicLink() || uid === undefined || parent.uid !== uid || (parent.mode & 0o077) !== 0) {
    throw new BrokerError("AUTH_INVALID", "Broker status socket directory failed ownership or permission checks");
  }
  const canonicalParent = await realpath(parentPath).catch(() => { throw new BrokerError("AUTH_INVALID", "Broker status socket directory could not be canonicalized"); });
  const canonicalParentStat = await lstat(canonicalParent);
  if (!canonicalParentStat.isDirectory() || canonicalParentStat.dev !== parent.dev || canonicalParentStat.ino !== parent.ino) {
    throw new BrokerError("AUTH_INVALID", "Broker status socket directory target changed while canonicalizing");
  }
  const socket = await lstat(socketPath);
  if (!socket.isSocket() || socket.isSymbolicLink() || socket.uid !== uid || (socket.mode & 0o177) !== 0) {
    throw new BrokerError("AUTH_INVALID", "Broker status socket target failed ownership or permission checks");
  }
  return { device: socket.dev, inode: socket.ino };
}

function parseSignedBrokerStatusRequest(raw: unknown): { unsigned: UnsignedBrokerStatusRequest; authenticationProof: string } {
  if (!isPlainDataRecord(raw)) throw new BrokerError("PRECONDITION_FAILED", "Broker status request is malformed");
  const value = raw as Record<string, unknown>;
  const allowed = ["protocolVersion", "contractVersion", "requestId", "nonce", "timestampMs", "expiresAtMs", "kind", "authenticationProof"];
  if (!sameKeys(value, allowed) || typeof value.authenticationProof !== "string" || !/^[a-f0-9]{64}$/u.test(value.authenticationProof)) {
    throw new BrokerError("PRECONDITION_FAILED", "Broker status request authentication envelope is malformed");
  }
  const unsigned = { ...value } as unknown as UnsignedBrokerStatusRequest;
  delete (unsigned as unknown as Record<string, unknown>).authenticationProof;
  validateUnsignedBrokerStatusRequest(unsigned);
  return { unsigned, authenticationProof: value.authenticationProof };
}

/**
 * Recover a structurally valid unsigned request before freshness/auth checks
 * so callers can authenticate stable failures such as AUTH_EXPIRED or
 * REPLAY_DENIED. This candidate is never admitted or used for status access.
 */
function unsignedBrokerStatusCandidate(raw: unknown): UnsignedBrokerStatusRequest | undefined {
  if (!isPlainDataRecord(raw)) return undefined;
  const record = raw as Record<string, unknown>;
  const allowed = [
    "protocolVersion", "contractVersion", "requestId", "nonce", "timestampMs", "expiresAtMs", "kind", "authenticationProof"
  ];
  if (!sameKeys(record, allowed) || typeof record.authenticationProof !== "string") return undefined;
  const candidate = { ...record } as unknown as UnsignedBrokerStatusRequest & { authenticationProof?: string };
  delete candidate.authenticationProof;
  try {
    validateUnsignedBrokerStatusRequest(candidate);
    return candidate;
  } catch {
    return undefined;
  }
}

function fallbackRequest(): UnsignedBrokerStatusRequest {
  const now = Date.now();
  return { protocolVersion: PROTOCOL_VERSION, contractVersion: CONTRACT_VERSION, requestId: "request:broker-status-invalid", nonce: `broker-status-nonce-${"0".repeat(16)}`, timestampMs: now, expiresAtMs: now + 1, kind: "broker_status" };
}

function statusSuccess(request: UnsignedBrokerStatusRequest, status: BrokerServiceReadback, key: Buffer): BrokerStatusSuccessResponse {
  const body = { ok: true as const, kind: "broker_status" as const, requestId: request.requestId, status };
  return { ...body, responseProof: statusResponseProof(request, body, key) };
}

function statusFailure(errorClass: ErrorClass, message: string, requestId: string, retryable: boolean, request: UnsignedBrokerStatusRequest | undefined, key: Buffer): BrokerStatusFailureResponse {
  const body = { ok: false as const, kind: "broker_status" as const, requestId, resultClass: errorClass, error: { message: boundedStatusMessage(message), retryable } };
  return { ...body, responseProof: statusResponseProof(request, body, key) };
}

function statusRequestProof(request: UnsignedBrokerStatusRequest, key: Buffer): string {
  if (key.byteLength < 32) throw new BrokerError("AUTH_INVALID", "Broker status key is invalid");
  return createHmac("sha256", key).update(STATUS_REQUEST_DOMAIN, "utf8").update(sha256(canonicalJson(request)), "utf8").digest("hex");
}

function statusResponseProof(request: UnsignedBrokerStatusRequest | undefined, body: object, key: Buffer): string {
  if (key.byteLength < 32) throw new BrokerError("AUTH_INVALID", "Broker status key is invalid");
  return createHmac("sha256", key).update(STATUS_RESPONSE_DOMAIN, "utf8").update(request ? sha256(canonicalJson(request)) : "invalid-broker-status-request", "utf8").update(canonicalJson(body), "utf8").digest("hex");
}

function safeEqualHex(left: string, right: string): boolean {
  if (!/^[a-f0-9]{64}$/u.test(left) || !/^[a-f0-9]{64}$/u.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function boundedStatusMessage(value: string): string {
  return typeof value === "string" && value.length <= 512 && !value.includes("\0") && !/[\r\n]/u.test(value)
    ? value
    : "Broker status request failed";
}

function sameKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function canonicalStatusPath(path: string): boolean {
  return typeof path === "string" && isAbsolute(path) && resolve(path) === path && path.endsWith(".sock") &&
    !path.includes("\0") && !path.includes("\n") && !path.includes("\r");
}

function isAsciiWhitespace(byte: number): boolean {
  return byte === 0x09 || byte === 0x0a || byte === 0x0c || byte === 0x0d || byte === 0x20;
}

function isDenseArray(value: unknown, maxLength: number): value is readonly unknown[] {
  if (!Array.isArray(value) || value.length > maxLength || Object.getOwnPropertySymbols(value).length > 0) return false;
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== value.length + 1 || Object.keys(value).length !== value.length) return false;
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor)) return false;
  }
  return true;
}

function writeStatusResponse(socket: Socket, response: BrokerStatusResponse): void {
  if (socket.destroyed) return;
  const serialized = `${JSON.stringify(response)}\n`;
  if (Buffer.byteLength(serialized, "utf8") <= MAX_RESPONSE_BYTES) socket.end(serialized);
  else socket.destroy();
}

function exchangeStatusSocket(socketPath: string, body: string, timeoutMs: number, maxResponseBytes: number): Promise<unknown> {
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 256 || maxResponseBytes > MAX_RESPONSE_BYTES) {
    throw new BrokerError("PRECONDITION_FAILED", "Broker status response limit is invalid");
  }
  return new Promise((resolvePromise, rejectPromise) => {
    const socket = connect(socketPath);
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const finish = (error?: Error, value?: unknown) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (error) rejectPromise(error); else resolvePromise(value);
    };
    socket.setTimeout(timeoutMs, () => finish(new BrokerError("TIMEOUT", "Broker status readback timed out", true)));
    socket.once("error", () => finish(new BrokerError("EXECUTION_FAILED", "Broker status transport failed", true)));
    socket.on("data", (chunk: Buffer) => {
      if (settled) return;
      total += chunk.byteLength;
      if (total > maxResponseBytes) { finish(new BrokerError("OUTPUT_LIMIT", "Broker status response exceeded the byte limit")); return; }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      if (combined.subarray(newline + 1).some((byte) => !isAsciiWhitespace(byte))) {
        finish(new BrokerError("AUTH_INVALID", "Broker status response contained trailing data"));
        return;
      }
      try { finish(undefined, parseJsonUtf8Strict(combined.subarray(0, newline))); }
      catch { finish(new BrokerError("AUTH_INVALID", "Broker status response is not valid JSON")); }
    });
    socket.once("connect", () => {
      void lstat(socketPath).then((after) => {
        if (!after.isSocket() || after.isSymbolicLink()) { finish(new BrokerError("AUTH_INVALID", "Broker status socket target changed while connecting")); return; }
        socket.write(body);
      }).catch(() => finish(new BrokerError("AUTH_INVALID", "Broker status socket target could not be revalidated")));
    });
  });
}
