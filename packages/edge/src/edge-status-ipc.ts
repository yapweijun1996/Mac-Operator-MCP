import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { chmod, lstat, realpath, unlink } from "node:fs/promises";
import { connect, createServer, type Server, type Socket } from "node:net";
import { dirname, isAbsolute, resolve } from "node:path";
import { BrokerError, canonicalJson, CONTRACT_VERSION, parseJsonUtf8Strict, PROTOCOL_VERSION, sha256, type ErrorClass } from "@mac-operator/contracts";
import { isPlainDataRecord } from "./plain-record.js";
import type { EdgeServiceReadback } from "./service-startup.js";

const STATUS_REQUEST_DOMAIN = "mac-operator-edge-status-request-v0.1\0";
const STATUS_RESPONSE_DOMAIN = "mac-operator-edge-status-response-v0.1\0";
const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 128 * 1024;
const MAX_REQUEST_AGE_MS = 60_000;
const SOCKET_TIMEOUT_MS = 15_000;
const MAX_REPLAY_ENTRIES = 1_024;
const STATUS_REQUEST_ID_PATTERN = /^request:edge-status-[A-Za-z0-9._:-]{16,128}$/u;
const STATUS_NONCE_PATTERN = /^edge-status-nonce-[A-Za-z0-9._:-]{16,128}$/u;

export interface UnsignedEdgeStatusRequest {
  protocolVersion: typeof PROTOCOL_VERSION;
  contractVersion: typeof CONTRACT_VERSION;
  requestId: string;
  nonce: string;
  timestampMs: number;
  expiresAtMs: number;
  kind: "edge_status";
}

export interface SignedEdgeStatusRequest extends UnsignedEdgeStatusRequest {
  authenticationProof: string;
}

export type EdgeStatusSuccessResponse = {
  ok: true;
  kind: "edge_status";
  requestId: string;
  status: EdgeServiceReadback;
  responseProof: string;
};

export type EdgeStatusFailureResponse = {
  ok: false;
  kind: "edge_status";
  requestId: string;
  resultClass: ErrorClass;
  error: { message: string; retryable: boolean };
  responseProof: string;
};

export type EdgeStatusResponse = EdgeStatusSuccessResponse | EdgeStatusFailureResponse;

export interface EdgeStatusIpcServerOptions {
  socketPath: string;
  authenticationKey: Buffer;
  readStatus: () => EdgeServiceReadback;
  authorizeStatus: () => void;
  maxRequestBytes?: number;
  maxResponseBytes?: number;
  maxRequestAgeMs?: number;
  allowedClockSkewMs?: number;
  now?: () => number;
}

export class EdgeStatusIpcServer {
  private server: Server | undefined;
  private socketIdentity: SocketIdentity | undefined;
  private readonly sockets = new Set<Socket>();
  private readonly seenRequests = new Map<string, number>();
  private readonly authenticationKey: Buffer;
  private readonly maxRequestBytes: number;
  private readonly maxResponseBytes: number;
  private readonly maxRequestAgeMs: number;
  private readonly allowedClockSkewMs: number;
  private readonly now: () => number;

  constructor(private readonly options: EdgeStatusIpcServerOptions) {
    if (!canonicalStatusPath(options.socketPath) || Buffer.byteLength(options.socketPath, "utf8") >= 104) {
      throw new Error("Edge status IPC socket path is invalid");
    }
    if (!Buffer.isBuffer(options.authenticationKey) || options.authenticationKey.byteLength < 32) {
      throw new Error("Edge status IPC key must contain at least 32 bytes");
    }
    if (typeof options.readStatus !== "function" || typeof options.authorizeStatus !== "function") {
      throw new Error("Edge status IPC requires Edge-owned read and authority callbacks");
    }
    this.maxRequestBytes = boundedLimit(options.maxRequestBytes ?? MAX_REQUEST_BYTES, 256, MAX_REQUEST_BYTES * 4, "request");
    this.maxResponseBytes = boundedLimit(options.maxResponseBytes ?? MAX_RESPONSE_BYTES, 256, MAX_RESPONSE_BYTES, "response");
    this.maxRequestAgeMs = boundedLimit(options.maxRequestAgeMs ?? MAX_REQUEST_AGE_MS, 1, MAX_REQUEST_AGE_MS, "request age");
    this.allowedClockSkewMs = boundedLimit(options.allowedClockSkewMs ?? 5_000, 0, 60_000, "clock skew");
    this.authenticationKey = Buffer.from(options.authenticationKey);
    this.now = options.now ?? Date.now;
  }

  async listen(): Promise<void> {
    if (this.server) throw new Error("Edge status IPC server is already running");
    await validateStatusSocketParent(this.options.socketPath);
    await removeStaleStatusSocket(this.options.socketPath);
    const server = createServer((socket) => {
      this.sockets.add(socket);
      socket.once("close", () => this.sockets.delete(socket));
      this.handleSocket(socket);
    });
    this.server = server;
    try {
      await new Promise<void>((resolveListen, rejectListen) => {
        server.once("error", rejectListen);
        server.listen(this.options.socketPath, resolveListen);
      });
      await chmod(this.options.socketPath, 0o600);
      this.socketIdentity = await validateEdgeStatusSocketTarget(this.options.socketPath);
    } catch (error) {
      this.server = undefined;
      await closeServer(server).catch(() => undefined);
      await removeStaleStatusSocket(this.options.socketPath).catch(() => undefined);
      throw error;
    }
  }

  async close(): Promise<void> {
    const server = this.server;
    this.server = undefined;
    const identity = this.socketIdentity;
    this.socketIdentity = undefined;
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    if (server) await closeServer(server);
    if (identity !== undefined) await removeOwnedStatusSocket(this.options.socketPath, identity);
    this.authenticationKey.fill(0);
  }

  private handleSocket(socket: Socket): void {
    socket.setTimeout(Math.min(this.maxRequestAgeMs + this.allowedClockSkewMs, SOCKET_TIMEOUT_MS), () => socket.destroy());
    let chunks: Buffer[] = [];
    let total = 0;
    let handled = false;
    socket.on("data", (chunk: Buffer) => {
      if (handled) return;
      total += chunk.byteLength;
      if (total > this.maxRequestBytes) {
        handled = true;
        writeStatusResponse(socket, statusFailure("OUTPUT_LIMIT", "Edge status request exceeded the byte limit", "invalid-edge-status-request", false, undefined, this.authenticationKey), this.maxResponseBytes);
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      handled = true;
      socket.pause();
      let request: UnsignedEdgeStatusRequest | undefined;
      let response: EdgeStatusResponse;
      try {
        const raw = parseJsonUtf8Strict(combined.subarray(0, newline));
        request = unsignedEdgeStatusCandidate(raw);
        request = authenticateEdgeStatusRequest(raw, this.authenticationKey, this.now(), this.maxRequestAgeMs, this.allowedClockSkewMs);
        if (combined.subarray(newline + 1).some((byte) => !isAsciiWhitespace(byte))) {
          throw new BrokerError("PRECONDITION_FAILED", "Edge status request contained trailing data");
        }
        this.admitReplay(request);
        this.options.authorizeStatus();
        response = statusSuccess(request, validateEdgeStatusReadback(this.options.readStatus()), this.authenticationKey);
      } catch (error) {
        const brokerError = error instanceof BrokerError ? error : new BrokerError("PRECONDITION_FAILED", "Edge status request is invalid");
        const fallback = request ?? fallbackRequest();
        response = statusFailure(brokerError.errorClass, brokerError.message, fallback.requestId, brokerError.retryable, request, this.authenticationKey);
      }
      writeStatusResponse(socket, response, this.maxResponseBytes);
    });
  }

  private admitReplay(request: UnsignedEdgeStatusRequest): void {
    const now = this.now();
    for (const [key, expiresAt] of this.seenRequests) if (expiresAt <= now) this.seenRequests.delete(key);
    const key = `${request.requestId}\0${request.nonce}`;
    if (this.seenRequests.has(key)) throw new BrokerError("REPLAY_DENIED", "Edge status request replay was rejected");
    if (this.seenRequests.size >= MAX_REPLAY_ENTRIES) throw new BrokerError("EXECUTION_FAILED", "Edge status replay guard is at capacity", true);
    this.seenRequests.set(key, request.expiresAtMs);
  }
}

export interface EdgeStatusIpcClientOptions {
  socketPath: string;
  authenticationKey: Buffer;
  timeoutMs?: number;
  maxResponseBytes?: number;
  maxRequestAgeMs?: number;
  allowedClockSkewMs?: number;
  now?: () => number;
}

export async function readEdgeStatus(options: EdgeStatusIpcClientOptions): Promise<EdgeServiceReadback> {
  if (options === null || typeof options !== "object" || !canonicalStatusPath(options.socketPath) ||
      !Buffer.isBuffer(options.authenticationKey) || options.authenticationKey.byteLength < 32) {
    throw new BrokerError("PRECONDITION_FAILED", "Edge status client options are invalid");
  }
  const timeoutMs = boundedLimit(options.timeoutMs ?? 5_000, 1, SOCKET_TIMEOUT_MS, "timeout");
  const maxResponseBytes = boundedLimit(options.maxResponseBytes ?? MAX_RESPONSE_BYTES, 256, MAX_RESPONSE_BYTES, "response");
  const maxRequestAgeMs = boundedLimit(options.maxRequestAgeMs ?? MAX_REQUEST_AGE_MS, 1, MAX_REQUEST_AGE_MS, "request age");
  const allowedClockSkewMs = boundedLimit(options.allowedClockSkewMs ?? 5_000, 0, 60_000, "clock skew");
  const now = options.now ?? Date.now;
  const timestampMs = now();
  if (!Number.isSafeInteger(timestampMs) || timestampMs < 0) throw new BrokerError("PRECONDITION_FAILED", "Edge status client clock is invalid");
  const request: UnsignedEdgeStatusRequest = {
    protocolVersion: PROTOCOL_VERSION,
    contractVersion: CONTRACT_VERSION,
    requestId: `request:edge-status-${randomBytes(16).toString("hex")}`,
    nonce: `edge-status-nonce-${randomBytes(16).toString("hex")}`,
    timestampMs,
    expiresAtMs: timestampMs + Math.min(timeoutMs, maxRequestAgeMs),
    kind: "edge_status"
  };
  const key = Buffer.from(options.authenticationKey);
  const signed = signEdgeStatusRequest(request, key);
  const before = await validateEdgeStatusSocketTarget(options.socketPath);
  try {
    const response = await exchangeStatusSocket(options.socketPath, `${JSON.stringify(signed)}\n`, timeoutMs, maxResponseBytes);
    const after = await validateEdgeStatusSocketTarget(options.socketPath);
    if (before.device !== after.device || before.inode !== after.inode) throw new BrokerError("CONFLICT", "Edge status socket identity changed during readback");
    const verified = authenticateEdgeStatusResponse(response, request, key);
    if (!verified.ok) throw new BrokerError(verified.resultClass, verified.error.message, verified.error.retryable);
    return verified.status;
  } finally {
    key.fill(0);
  }
}

export function signEdgeStatusRequest(request: UnsignedEdgeStatusRequest, authenticationKey: Buffer): SignedEdgeStatusRequest {
  validateUnsignedEdgeStatusRequest(request);
  return { ...request, authenticationProof: statusRequestProof(request, authenticationKey) };
}

export function authenticateEdgeStatusRequest(
  raw: unknown,
  authenticationKey: Buffer,
  nowMs: number,
  maxRequestAgeMs = MAX_REQUEST_AGE_MS,
  allowedClockSkewMs = 5_000
): UnsignedEdgeStatusRequest {
  const parsed = parseSignedEdgeStatusRequest(raw);
  const request = parsed.unsigned;
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || request.timestampMs > nowMs + allowedClockSkewMs ||
      nowMs - request.timestampMs > maxRequestAgeMs || request.expiresAtMs <= nowMs ||
      request.expiresAtMs <= request.timestampMs || request.expiresAtMs > request.timestampMs + maxRequestAgeMs + allowedClockSkewMs) {
    throw new BrokerError("AUTH_EXPIRED", "Edge status timestamp is outside the accepted window");
  }
  if (!safeEqualHex(parsed.authenticationProof, statusRequestProof(request, authenticationKey))) {
    throw new BrokerError("AUTH_INVALID", "Edge status authentication failed");
  }
  return request;
}

export function validateUnsignedEdgeStatusRequest(request: UnsignedEdgeStatusRequest): void {
  const allowed = ["protocolVersion", "contractVersion", "requestId", "nonce", "timestampMs", "expiresAtMs", "kind"];
  if (!isPlainDataRecord(request)) throw new BrokerError("PRECONDITION_FAILED", "Edge status request fields are malformed");
  const keys = Object.keys(request);
  if (keys.length !== allowed.length || allowed.some((key) => !keys.includes(key)) ||
      request.protocolVersion !== PROTOCOL_VERSION || request.contractVersion !== CONTRACT_VERSION ||
      !STATUS_REQUEST_ID_PATTERN.test(request.requestId) || !STATUS_NONCE_PATTERN.test(request.nonce) ||
      !Number.isSafeInteger(request.timestampMs) || request.timestampMs < 0 ||
      !Number.isSafeInteger(request.expiresAtMs) || request.expiresAtMs <= request.timestampMs || request.kind !== "edge_status") {
    throw new BrokerError("PRECONDITION_FAILED", "Edge status request fields are malformed");
  }
}

export function validateEdgeStatusReadback(status: EdgeServiceReadback): EdgeServiceReadback {
  if (!isPlainDataRecord(status) || status.component !== "mac-operator-edge" ||
      !["stopped", "starting", "running", "stopping", "failed"].includes(status.state) ||
      !/^[0-9a-f]{7,64}$/u.test(status.sourceRevision) ||
      !/^v?\d+\.\d+(?:\.\d+)?(?:[-+].*)?$/u.test(status.contractVersion) ||
      !/^(?:policy-[1-9][0-9]*|\d+\.\d+(?:\.\d+)?(?:[-+].*)?)$/u.test(status.policyVersion) ||
      typeof status.bindHost !== "string" || status.bindHost.length === 0 || status.bindHost.length > 255 ||
      /[\u0000-\u001F\u007F]/u.test(status.bindHost) || !Number.isSafeInteger(status.bindPort) ||
      status.bindPort < 1 || status.bindPort > 65_535 || typeof status.listening !== "boolean") {
    throw new BrokerError("EXECUTION_FAILED", "Edge status readback is malformed");
  }
  return { ...status };
}

export function authenticateEdgeStatusResponse(
  raw: unknown,
  request: UnsignedEdgeStatusRequest,
  authenticationKey: Buffer
): EdgeStatusResponse {
  validateUnsignedEdgeStatusRequest(request);
  if (authenticationKey.byteLength < 32 || !isPlainDataRecord(raw)) throw new BrokerError("AUTH_INVALID", "Edge status response is invalid");
  const response = raw as Record<string, unknown>;
  if (response.kind !== "edge_status" || response.requestId !== request.requestId || typeof response.responseProof !== "string") {
    throw new BrokerError("AUTH_INVALID", "Edge status response identity is invalid");
  }
  const body = { ...response };
  delete body.responseProof;
  if (!safeEqualHex(response.responseProof as string, statusResponseProof(request, body, authenticationKey))) {
    throw new BrokerError("AUTH_INVALID", "Edge status response authentication failed");
  }
  if (response.ok === true) {
    const expected = ["ok", "kind", "requestId", "status", "responseProof"];
    if (!sameKeys(response, expected)) throw new BrokerError("EXECUTION_FAILED", "Edge status response fields are malformed");
    return { ...(response as unknown as EdgeStatusSuccessResponse), status: validateEdgeStatusReadback(response.status as EdgeServiceReadback) };
  }
  const expected = ["ok", "kind", "requestId", "resultClass", "error", "responseProof"];
  if (response.ok !== false || !sameKeys(response, expected) || typeof response.resultClass !== "string" ||
      !isPlainDataRecord(response.error) || !sameKeys(response.error as Record<string, unknown>, ["message", "retryable"]) ||
      typeof (response.error as Record<string, unknown>).message !== "string" ||
      typeof (response.error as Record<string, unknown>).retryable !== "boolean") {
    throw new BrokerError("EXECUTION_FAILED", "Edge status failure is malformed");
  }
  return response as unknown as EdgeStatusFailureResponse;
}

export async function validateEdgeStatusSocketTarget(socketPath: string): Promise<SocketIdentity> {
  if (!canonicalStatusPath(socketPath)) throw new BrokerError("AUTH_INVALID", "Edge status socket path is not canonical");
  const parentPath = dirname(socketPath);
  const parent = await lstat(parentPath);
  const uid = process.getuid?.();
  if (!parent.isDirectory() || parent.isSymbolicLink() || uid === undefined || parent.uid !== uid || (parent.mode & 0o077) !== 0) {
    throw new BrokerError("AUTH_INVALID", "Edge status socket directory failed ownership or permission checks");
  }
  const canonicalParent = await realpath(parentPath).catch(() => { throw new BrokerError("AUTH_INVALID", "Edge status socket directory could not be canonicalized"); });
  const canonicalParentStat = await lstat(canonicalParent);
  if (!canonicalParentStat.isDirectory() || canonicalParentStat.dev !== parent.dev || canonicalParentStat.ino !== parent.ino) {
    throw new BrokerError("AUTH_INVALID", "Edge status socket directory target changed while canonicalizing");
  }
  const socket = await lstat(socketPath);
  if (!socket.isSocket() || socket.isSymbolicLink() || socket.uid !== uid || (socket.mode & 0o177) !== 0) {
    throw new BrokerError("AUTH_INVALID", "Edge status socket target failed ownership or permission checks");
  }
  return { device: socket.dev, inode: socket.ino };
}

export interface SocketIdentity {
  device: number;
  inode: number;
}

function parseSignedEdgeStatusRequest(raw: unknown): { unsigned: UnsignedEdgeStatusRequest; authenticationProof: string } {
  if (!isPlainDataRecord(raw)) throw new BrokerError("PRECONDITION_FAILED", "Edge status request is malformed");
  const value = raw as Record<string, unknown>;
  const allowed = ["protocolVersion", "contractVersion", "requestId", "nonce", "timestampMs", "expiresAtMs", "kind", "authenticationProof"];
  if (!sameKeys(value, allowed) || typeof value.authenticationProof !== "string" || !/^[a-f0-9]{64}$/u.test(value.authenticationProof)) {
    throw new BrokerError("PRECONDITION_FAILED", "Edge status request authentication envelope is malformed");
  }
  const unsigned = { ...value } as unknown as UnsignedEdgeStatusRequest & { authenticationProof?: string };
  delete unsigned.authenticationProof;
  validateUnsignedEdgeStatusRequest(unsigned);
  return { unsigned, authenticationProof: value.authenticationProof };
}

function unsignedEdgeStatusCandidate(raw: unknown): UnsignedEdgeStatusRequest | undefined {
  if (!isPlainDataRecord(raw)) return undefined;
  const record = raw as Record<string, unknown>;
  const allowed = ["protocolVersion", "contractVersion", "requestId", "nonce", "timestampMs", "expiresAtMs", "kind", "authenticationProof"];
  if (!sameKeys(record, allowed) || typeof record.authenticationProof !== "string") return undefined;
  const candidate = { ...record } as unknown as UnsignedEdgeStatusRequest & { authenticationProof?: string };
  delete candidate.authenticationProof;
  try { validateUnsignedEdgeStatusRequest(candidate); return candidate; } catch { return undefined; }
}

function fallbackRequest(): UnsignedEdgeStatusRequest {
  const now = Date.now();
  return { protocolVersion: PROTOCOL_VERSION, contractVersion: CONTRACT_VERSION, requestId: "request:edge-status-invalid", nonce: `edge-status-nonce-${"0".repeat(16)}`, timestampMs: now, expiresAtMs: now + 1, kind: "edge_status" };
}

function statusSuccess(request: UnsignedEdgeStatusRequest, status: EdgeServiceReadback, key: Buffer): EdgeStatusSuccessResponse {
  const body = { ok: true as const, kind: "edge_status" as const, requestId: request.requestId, status };
  return { ...body, responseProof: statusResponseProof(request, body, key) };
}

function statusFailure(errorClass: ErrorClass, message: string, requestId: string, retryable: boolean, request: UnsignedEdgeStatusRequest | undefined, key: Buffer): EdgeStatusFailureResponse {
  const body = { ok: false as const, kind: "edge_status" as const, requestId, resultClass: errorClass, error: { message: boundedStatusMessage(message), retryable } };
  return { ...body, responseProof: statusResponseProof(request, body, key) };
}

function statusRequestProof(request: UnsignedEdgeStatusRequest, key: Buffer): string {
  if (key.byteLength < 32) throw new BrokerError("AUTH_INVALID", "Edge status key is invalid");
  return createHmac("sha256", key).update(STATUS_REQUEST_DOMAIN, "utf8").update(sha256(canonicalJson(request)), "utf8").digest("hex");
}

function statusResponseProof(request: UnsignedEdgeStatusRequest | undefined, body: object, key: Buffer): string {
  if (key.byteLength < 32) throw new BrokerError("AUTH_INVALID", "Edge status key is invalid");
  return createHmac("sha256", key).update(STATUS_RESPONSE_DOMAIN, "utf8").update(request ? sha256(canonicalJson(request)) : "invalid-edge-status-request", "utf8").update(canonicalJson(body), "utf8").digest("hex");
}

function safeEqualHex(left: string, right: string): boolean {
  if (!/^[a-f0-9]{64}$/u.test(left) || !/^[a-f0-9]{64}$/u.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function boundedStatusMessage(value: string): string {
  return typeof value === "string" && value.length <= 512 && !value.includes("\0") && !/[\r\n]/u.test(value) ? value : "Edge status request failed";
}

function sameKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function canonicalStatusPath(path: string): boolean {
  return typeof path === "string" && isAbsolute(path) && resolve(path) === path && path.endsWith(".sock") && !path.includes("\0") && !path.includes("\n") && !path.includes("\r");
}

function isAsciiWhitespace(byte: number): boolean {
  return byte === 0x09 || byte === 0x0a || byte === 0x0c || byte === 0x0d || byte === 0x20;
}

function boundedLimit(value: number, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error(`Edge status ${label} limit is invalid`);
  return value;
}

function writeStatusResponse(socket: Socket, response: EdgeStatusResponse, maxResponseBytes: number): void {
  if (socket.destroyed) return;
  const serialized = `${JSON.stringify(response)}\n`;
  if (Buffer.byteLength(serialized, "utf8") <= maxResponseBytes) socket.end(serialized);
  else socket.destroy();
}

function exchangeStatusSocket(socketPath: string, body: string, timeoutMs: number, maxResponseBytes: number): Promise<unknown> {
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
    socket.setTimeout(timeoutMs, () => finish(new BrokerError("TIMEOUT", "Edge status readback timed out", true)));
    socket.once("error", () => finish(new BrokerError("EXECUTION_FAILED", "Edge status transport failed", true)));
    socket.on("data", (chunk: Buffer) => {
      if (settled) return;
      total += chunk.byteLength;
      if (total > maxResponseBytes) { finish(new BrokerError("OUTPUT_LIMIT", "Edge status response exceeded the byte limit")); return; }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      if (combined.subarray(newline + 1).some((byte) => !isAsciiWhitespace(byte))) { finish(new BrokerError("AUTH_INVALID", "Edge status response contained trailing data")); return; }
      try { finish(undefined, parseJsonUtf8Strict(combined.subarray(0, newline))); }
      catch { finish(new BrokerError("AUTH_INVALID", "Edge status response is not valid JSON")); }
    });
    socket.once("connect", () => {
      void lstat(socketPath).then((after) => {
        if (!after.isSocket() || after.isSymbolicLink()) { finish(new BrokerError("AUTH_INVALID", "Edge status socket target changed while connecting")); return; }
        socket.write(body);
      }).catch(() => finish(new BrokerError("AUTH_INVALID", "Edge status socket target could not be revalidated")));
    });
  });
}

async function validateStatusSocketParent(socketPath: string): Promise<void> {
  const parentPath = dirname(socketPath);
  const parent = await lstat(parentPath);
  const uid = process.getuid?.();
  if (!parent.isDirectory() || parent.isSymbolicLink() || uid === undefined || parent.uid !== uid || (parent.mode & 0o077) !== 0) {
    throw new Error("Edge status socket directory failed ownership or permission checks");
  }
  const canonicalParent = await realpath(parentPath);
  const canonicalParentStat = await lstat(canonicalParent);
  if (canonicalParent !== parentPath || !canonicalParentStat.isDirectory() || canonicalParentStat.dev !== parent.dev || canonicalParentStat.ino !== parent.ino) {
    throw new Error("Edge status socket directory is not canonical");
  }
}

async function removeStaleStatusSocket(socketPath: string): Promise<void> {
  try {
    const value = await lstat(socketPath);
    const uid = process.getuid?.();
    if (!value.isSocket() || value.isSymbolicLink() || uid === undefined || value.uid !== uid || (value.mode & 0o177) !== 0) {
      throw new Error("existing Edge status socket is unsafe");
    }
    await unlink(socketPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

async function removeOwnedStatusSocket(socketPath: string, identity: SocketIdentity): Promise<void> {
  try {
    const value = await lstat(socketPath);
    if (value.isSocket() && !value.isSymbolicLink() && value.dev === identity.device && value.ino === identity.inode) await unlink(socketPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolveClose, rejectClose) => {
    server.close((error) => error && (error as NodeJS.ErrnoException).code !== "ERR_SERVER_NOT_RUNNING" ? rejectClose(error) : resolveClose());
  });
}
