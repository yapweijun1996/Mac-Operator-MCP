import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { connect, type Socket } from "node:net";
import { parseJsonUtf8Strict, canonicalJson, CONTRACT_VERSION, PROTOCOL_VERSION, BrokerError, type ErrorClass } from "@mac-operator/contracts";
import type { RootHelperSnapshotCapability } from "./root-helper-snapshot.js";
import { parseRootHelperSnapshotCapability } from "./root-helper-snapshot.js";
import { MacOsNativePeerIpcServer, assertNativeSocketPath, type NativePeerPolicy } from "./native-peer-ipc-server.js";
import { MacOsPeerCredentialVerifier } from "./peer-credentials.js";
import type { SocketPathIdentity } from "./ipc-server.js";
import { readPrivilegedHelperSocketReadback } from "./privileged-helper-package.js";
import { isPlainDataRecord } from "./plain-record.js";

const STATUS_REQUEST_DOMAIN = "mac-operator-root-helper-status-request-v0.1\0";
const STATUS_RESPONSE_DOMAIN = "mac-operator-root-helper-status-response-v0.1\0";
const STATUS_REQUEST_ID_PATTERN = /^request:root-helper-status-[A-Za-z0-9._:-]{16,128}$/u;
const STATUS_NONCE_PATTERN = /^root-helper-status-nonce-[A-Za-z0-9._:-]{16,128}$/u;
const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 128 * 1024;
const MAX_REQUEST_AGE_MS = 60_000;

export type RootHelperSnapshotStatusState = "stopped" | "starting" | "running" | "stopping" | "failed";

export interface RootHelperSnapshotStatusReadback {
  component: "mac-operator-root-helper-snapshot";
  sourceRevision: string;
  contractVersion: string;
  evidenceRef?: string;
  state: RootHelperSnapshotStatusState;
  runtimeState: RootHelperSnapshotStatusState;
  nativeTransportRequired: true;
  available: boolean;
  capability: RootHelperSnapshotCapability;
}

export interface UnsignedRootHelperSnapshotStatusRequest {
  protocolVersion: typeof PROTOCOL_VERSION;
  contractVersion: typeof CONTRACT_VERSION;
  requestId: string;
  nonce: string;
  timestampMs: number;
  expiresAtMs: number;
  kind: "root_helper_snapshot_status";
}

export interface SignedRootHelperSnapshotStatusRequest extends UnsignedRootHelperSnapshotStatusRequest {
  authenticationProof: string;
}

export type RootHelperSnapshotStatusSuccessResponse = {
  ok: true;
  kind: "root_helper_snapshot_status";
  requestId: string;
  status: RootHelperSnapshotStatusReadback;
  responseProof: string;
};

export type RootHelperSnapshotStatusFailureResponse = {
  ok: false;
  kind: "root_helper_snapshot_status";
  requestId: string;
  resultClass: ErrorClass;
  error: { message: string; retryable: boolean };
  responseProof: string;
};

export type RootHelperSnapshotStatusResponse = RootHelperSnapshotStatusSuccessResponse | RootHelperSnapshotStatusFailureResponse;

export interface RootHelperSnapshotStatusReplayGuard {
  admit(input: Pick<UnsignedRootHelperSnapshotStatusRequest, "requestId" | "nonce" | "timestampMs" | "expiresAtMs">): void;
}

/** In-memory replay fence for the short-lived root-helper status endpoint. */
export class MemoryRootHelperSnapshotStatusReplayGuard implements RootHelperSnapshotStatusReplayGuard {
  private readonly accepted = new Map<string, number>();

  admit(input: Pick<UnsignedRootHelperSnapshotStatusRequest, "requestId" | "nonce" | "timestampMs" | "expiresAtMs">): void {
    validateReplayInput(input);
    const now = Date.now();
    for (const [key, expiresAtMs] of this.accepted) if (expiresAtMs <= now) this.accepted.delete(key);
    if (this.accepted.has(input.requestId) || [...this.accepted.keys()].some((key) => key === input.nonce)) {
      throw new BrokerError("REPLAY_DENIED", "Root-helper snapshot status request was already accepted");
    }
    this.accepted.set(input.requestId, input.expiresAtMs);
    this.accepted.set(input.nonce, input.expiresAtMs);
  }
}

export interface RootHelperSnapshotStatusIpcServerOptions {
  socketPath: string;
  authenticationKey: Buffer;
  replayGuard: RootHelperSnapshotStatusReplayGuard;
  peerPolicy: NativePeerPolicy;
  readStatus: () => RootHelperSnapshotStatusReadback;
  authorizeStatus: () => void;
  maxRequestBytes?: number;
  maxRequestAgeMs?: number;
  allowedClockSkewMs?: number;
  now?: () => number;
  onError?: (error: unknown) => void;
}

/** Native-peer and HMAC protected read-only root-helper status endpoint. */
export class RootHelperSnapshotStatusIpcServer {
  private readonly nativeTransport: MacOsNativePeerIpcServer;
  private readonly authenticationKey: Buffer;
  private readonly maxRequestBytes: number;
  private readonly maxRequestAgeMs: number;
  private readonly allowedClockSkewMs: number;
  private readonly now: () => number;
  private closed = false;

  constructor(private readonly options: RootHelperSnapshotStatusIpcServerOptions) {
    assertNativeSocketPath(options.socketPath);
    if (!Buffer.isBuffer(options.authenticationKey) || options.authenticationKey.byteLength < 32) {
      throw new Error("Root-helper snapshot status key must contain at least 32 bytes");
    }
    if (!options.replayGuard || typeof options.replayGuard.admit !== "function" ||
        typeof options.readStatus !== "function" || typeof options.authorizeStatus !== "function") {
      throw new Error("Root-helper snapshot status IPC authority callbacks are required");
    }
    const maxRequestBytes = options.maxRequestBytes ?? MAX_REQUEST_BYTES;
    const maxRequestAgeMs = options.maxRequestAgeMs ?? MAX_REQUEST_AGE_MS;
    const allowedClockSkewMs = options.allowedClockSkewMs ?? 5_000;
    if (!Number.isSafeInteger(maxRequestBytes) || maxRequestBytes < 256 || maxRequestBytes > MAX_REQUEST_BYTES * 4 ||
        !Number.isSafeInteger(maxRequestAgeMs) || maxRequestAgeMs < 1 || maxRequestAgeMs > MAX_REQUEST_AGE_MS ||
        !Number.isSafeInteger(allowedClockSkewMs) || allowedClockSkewMs < 0 || allowedClockSkewMs > 60_000) {
      throw new Error("Root-helper snapshot status IPC limits are invalid");
    }
    this.authenticationKey = Buffer.from(options.authenticationKey);
    this.maxRequestBytes = maxRequestBytes;
    this.maxRequestAgeMs = maxRequestAgeMs;
    this.allowedClockSkewMs = allowedClockSkewMs;
    this.now = options.now ?? Date.now;
    this.nativeTransport = new MacOsNativePeerIpcServer({
      socketPath: options.socketPath,
      peerPolicy: options.peerPolicy,
      onSocket: (socket) => this.handleSocket(socket),
      ...(options.onError === undefined ? {} : { onError: options.onError })
    });
  }

  async listen(): Promise<void> {
    if (this.closed) throw new BrokerError("CANCELLED", "Root-helper snapshot status IPC server is closed");
    await this.nativeTransport.listen();
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    try { await this.nativeTransport.close(); }
    finally { this.authenticationKey.fill(0); }
  }

  private handleSocket(socket: Socket): void {
    socket.setTimeout(Math.min(this.maxRequestAgeMs + this.allowedClockSkewMs, MAX_REQUEST_AGE_MS + 60_000), () => socket.destroy());
    let chunks: Buffer[] = [];
    let total = 0;
    let handled = false;
    socket.on("data", (chunk: Buffer) => {
      if (handled) return;
      total += chunk.byteLength;
      if (total > this.maxRequestBytes) {
        handled = true;
        writeStatusResponse(socket, statusFailure("OUTPUT_LIMIT", "Root-helper snapshot status request exceeded the byte limit", "invalid-request", false, undefined, this.authenticationKey));
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      handled = true;
      socket.pause();
      let request: UnsignedRootHelperSnapshotStatusRequest | undefined;
      let response: RootHelperSnapshotStatusResponse;
      try {
        const raw = parseJsonUtf8Strict(combined.subarray(0, newline));
        request = unsignedStatusCandidate(raw);
        request = authenticateRootHelperSnapshotStatusRequest(raw, this.authenticationKey, this.now(), this.maxRequestAgeMs, this.allowedClockSkewMs);
        if (combined.subarray(newline + 1).some((byte) => !isAsciiWhitespace(byte))) {
          throw new BrokerError("PRECONDITION_FAILED", "Root-helper snapshot status request contained trailing data");
        }
        this.options.replayGuard.admit(request);
        this.options.authorizeStatus();
        response = statusSuccess(request, validateRootHelperSnapshotStatusReadback(this.options.readStatus()), this.authenticationKey);
      } catch (error) {
        const brokerError = error instanceof BrokerError ? error : new BrokerError("PRECONDITION_FAILED", "Root-helper snapshot status request is invalid");
        const fallback = request ?? fallbackStatusRequest();
        response = statusFailure(brokerError.errorClass, brokerError.message, fallback.requestId, brokerError.retryable, request, this.authenticationKey);
      }
      writeStatusResponse(socket, response);
    });
  }
}

export interface RootHelperSnapshotStatusClientOptions {
  socketPath: string;
  authenticationKey: Buffer;
  /** The Broker must bind the status response to the expected root process identity. */
  peerPolicy: NativePeerPolicy;
  timeoutMs?: number;
  now?: () => number;
}

export async function readRootHelperSnapshotStatus(options: RootHelperSnapshotStatusClientOptions): Promise<RootHelperSnapshotStatusReadback> {
  if (options === null || typeof options !== "object" || !Buffer.isBuffer(options.authenticationKey) || options.authenticationKey.byteLength < 32) {
    throw new BrokerError("PRECONDITION_FAILED", "Root-helper snapshot status client options are invalid");
  }
  assertNativeSocketPath(options.socketPath);
  const timeoutMs = options.timeoutMs ?? 5_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 15_000) {
    throw new BrokerError("PRECONDITION_FAILED", "Root-helper snapshot status timeout is invalid");
  }
  const now = options.now ?? Date.now;
  const timestampMs = now();
  if (!Number.isSafeInteger(timestampMs) || timestampMs < 0) throw new BrokerError("PRECONDITION_FAILED", "Root-helper snapshot status clock is invalid");
  const request: UnsignedRootHelperSnapshotStatusRequest = {
    protocolVersion: PROTOCOL_VERSION,
    contractVersion: CONTRACT_VERSION,
    requestId: `request:root-helper-status-${randomBytes(16).toString("hex")}`,
    nonce: `root-helper-status-nonce-${randomBytes(16).toString("hex")}`,
    timestampMs,
    expiresAtMs: timestampMs + Math.min(timeoutMs, MAX_REQUEST_AGE_MS),
    kind: "root_helper_snapshot_status"
  };
  const key = Buffer.from(options.authenticationKey);
  const verifier = new MacOsPeerCredentialVerifier(options.peerPolicy);
  const before = await readStatusSocketTarget(options.socketPath);
  try {
    const response = await exchangeStatusSocket(options.socketPath, `${JSON.stringify(signRootHelperSnapshotStatusRequest(request, key))}\n`, timeoutMs, verifier);
    const after = await readStatusSocketTarget(options.socketPath);
    if (before.device !== after.device || before.inode !== after.inode) throw new BrokerError("CONFLICT", "Root-helper snapshot status socket identity changed during readback");
    const verified = authenticateRootHelperSnapshotStatusResponse(response, request, key);
    if (!verified.ok) throw new BrokerError(verified.resultClass, verified.error.message, verified.error.retryable);
    return verified.status;
  } finally {
    key.fill(0);
  }
}

export function signRootHelperSnapshotStatusRequest(request: UnsignedRootHelperSnapshotStatusRequest, authenticationKey: Buffer): SignedRootHelperSnapshotStatusRequest {
  validateUnsignedRootHelperSnapshotStatusRequest(request);
  if (authenticationKey.byteLength < 32) throw new BrokerError("AUTH_INVALID", "Root-helper snapshot status key is invalid");
  return { ...request, authenticationProof: requestProof(request, authenticationKey) };
}

export function authenticateRootHelperSnapshotStatusRequest(
  raw: unknown,
  authenticationKey: Buffer,
  nowMs: number,
  maxRequestAgeMs = MAX_REQUEST_AGE_MS,
  allowedClockSkewMs = 5_000
): UnsignedRootHelperSnapshotStatusRequest {
  if (authenticationKey.byteLength < 32) throw new BrokerError("AUTH_INVALID", "Root-helper snapshot status key is invalid");
  const parsed = parseSignedStatusRequest(raw);
  const request = parsed.unsigned;
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || request.timestampMs > nowMs + allowedClockSkewMs ||
      nowMs - request.timestampMs > maxRequestAgeMs || request.expiresAtMs <= nowMs ||
      request.expiresAtMs <= request.timestampMs || request.expiresAtMs > request.timestampMs + maxRequestAgeMs + allowedClockSkewMs ||
      !safeEqualHex(parsed.authenticationProof, requestProof(request, authenticationKey))) {
    throw new BrokerError("AUTH_INVALID", "Root-helper snapshot status authentication failed or expired");
  }
  return request;
}

export function validateUnsignedRootHelperSnapshotStatusRequest(request: UnsignedRootHelperSnapshotStatusRequest): void {
  if (!isPlainDataRecord(request) || !sameKeys(request, ["contractVersion", "expiresAtMs", "kind", "nonce", "protocolVersion", "requestId", "timestampMs"]) ||
      request.protocolVersion !== PROTOCOL_VERSION || request.contractVersion !== CONTRACT_VERSION ||
      !STATUS_REQUEST_ID_PATTERN.test(request.requestId) || !STATUS_NONCE_PATTERN.test(request.nonce) ||
      !Number.isSafeInteger(request.timestampMs) || request.timestampMs < 0 || !Number.isSafeInteger(request.expiresAtMs) ||
      request.expiresAtMs <= request.timestampMs || request.kind !== "root_helper_snapshot_status") {
    throw new BrokerError("PRECONDITION_FAILED", "Root-helper snapshot status request fields are malformed");
  }
}

export function validateRootHelperSnapshotStatusReadback(status: RootHelperSnapshotStatusReadback): RootHelperSnapshotStatusReadback {
  if (!isPlainDataRecord(status) || status.component !== "mac-operator-root-helper-snapshot" ||
      !/^[0-9a-f]{7,64}$/u.test(status.sourceRevision) ||
      !/^v?\d+\.\d+(?:\.\d+)?(?:[-+].*)?$/u.test(status.contractVersion) ||
      !["stopped", "starting", "running", "stopping", "failed"].includes(status.state) ||
      !["stopped", "starting", "running", "stopping", "failed"].includes(status.runtimeState) ||
      status.nativeTransportRequired !== true || typeof status.available !== "boolean" ||
      (status.evidenceRef !== undefined && !/^[A-Za-z0-9._:/-]{1,256}$/u.test(status.evidenceRef))) {
    throw new BrokerError("EXECUTION_FAILED", "Root-helper snapshot status readback is malformed");
  }
  let capability: RootHelperSnapshotCapability;
  try { capability = parseRootHelperSnapshotCapability(status.capability); }
  catch { throw new BrokerError("EXECUTION_FAILED", "Root-helper snapshot status capability is malformed"); }
  if (capability.available !== status.available) {
    throw new BrokerError("EXECUTION_FAILED", "Root-helper snapshot status capability disagrees with availability");
  }
  return { ...status, capability };
}

export function authenticateRootHelperSnapshotStatusResponse(
  raw: unknown,
  request: UnsignedRootHelperSnapshotStatusRequest,
  authenticationKey: Buffer
): RootHelperSnapshotStatusResponse {
  validateUnsignedRootHelperSnapshotStatusRequest(request);
  if (authenticationKey.byteLength < 32 || !isPlainDataRecord(raw)) throw new BrokerError("AUTH_INVALID", "Root-helper snapshot status response is invalid");
  const response = raw as Record<string, unknown>;
  if (response.kind !== "root_helper_snapshot_status" || response.requestId !== request.requestId || typeof response.responseProof !== "string") {
    throw new BrokerError("AUTH_INVALID", "Root-helper snapshot status response identity is invalid");
  }
  const body = { ...response };
  delete body.responseProof;
  if (!safeEqualHex(response.responseProof as string, responseProof(request, body, authenticationKey))) {
    throw new BrokerError("AUTH_INVALID", "Root-helper snapshot status response authentication failed");
  }
  if (response.ok === true) {
    if (!sameKeys(response, ["kind", "ok", "requestId", "responseProof", "status"])) throw new BrokerError("EXECUTION_FAILED", "Root-helper snapshot status response fields are malformed");
    return { ...(response as unknown as RootHelperSnapshotStatusSuccessResponse), status: validateRootHelperSnapshotStatusReadback(response.status as RootHelperSnapshotStatusReadback) };
  }
  if (response.ok !== false || !sameKeys(response, ["error", "kind", "ok", "requestId", "responseProof", "resultClass"]) ||
      typeof response.resultClass !== "string" || !isErrorClass(response.resultClass) || !isPlainDataRecord(response.error) ||
      !sameKeys(response.error as Record<string, unknown>, ["message", "retryable"]) || typeof (response.error as Record<string, unknown>).message !== "string" ||
      typeof (response.error as Record<string, unknown>).retryable !== "boolean" || !isBoundedMessage((response.error as Record<string, unknown>).message as string)) {
    throw new BrokerError("EXECUTION_FAILED", "Root-helper snapshot status failure is malformed");
  }
  return response as unknown as RootHelperSnapshotStatusFailureResponse;
}

async function readStatusSocketTarget(socketPath: string): Promise<SocketPathIdentity> {
  try {
    const readback = await readPrivilegedHelperSocketReadback(socketPath, 0, 0, "root-helper snapshot status");
    return { device: readback.device, inode: readback.inode };
  } catch {
    throw new BrokerError("TARGET_NOT_FOUND", "Root-helper snapshot status socket is unavailable");
  }
}

async function exchangeStatusSocket(socketPath: string, serialized: string, timeoutMs: number, verifier: { verify(socket: Socket): unknown }): Promise<unknown> {
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
    socket.setTimeout(timeoutMs, () => fail(new BrokerError("TIMEOUT", "Root-helper snapshot status readback timed out", true)));
    socket.once("error", () => fail(new BrokerError("UNKNOWN_OUTCOME", "Root-helper snapshot status transport failed", true)));
    socket.on("data", (chunk: Buffer) => {
      if (settled) return;
      total += chunk.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        fail(new BrokerError("OUTPUT_LIMIT", "Root-helper snapshot status response exceeded the byte limit"));
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      if (combined.subarray(newline + 1).some((byte) => !isAsciiWhitespace(byte))) {
        fail(new BrokerError("AUTH_INVALID", "Root-helper snapshot status response contained trailing data"));
        return;
      }
      settled = true;
      socket.destroy();
      try { resolvePromise(parseJsonUtf8Strict(combined.subarray(0, newline))); }
      catch { reject(new BrokerError("EXECUTION_FAILED", "Root-helper snapshot status response is not valid JSON")); }
    });
    socket.on("close", () => {
      if (!settled) fail(new BrokerError("UNKNOWN_OUTCOME", "Root-helper snapshot status channel closed without a response", true));
    });
    socket.once("connect", () => {
      try {
        verifier.verify(socket);
        socket.write(serialized);
      } catch {
        fail(new BrokerError("AUTH_INVALID", "Root-helper snapshot status root peer authentication failed"));
      }
    });
  });
}

function parseSignedStatusRequest(raw: unknown): { unsigned: UnsignedRootHelperSnapshotStatusRequest; authenticationProof: string } {
  if (!isPlainDataRecord(raw)) throw new BrokerError("PRECONDITION_FAILED", "Root-helper snapshot status request is malformed");
  const record = raw as Record<string, unknown>;
  if (!sameKeys(record, ["authenticationProof", "contractVersion", "expiresAtMs", "kind", "nonce", "protocolVersion", "requestId", "timestampMs"]) ||
      typeof record.authenticationProof !== "string" || !/^[a-f0-9]{64}$/u.test(record.authenticationProof)) {
    throw new BrokerError("PRECONDITION_FAILED", "Root-helper snapshot status request authentication envelope is malformed");
  }
  const unsigned = { ...record } as unknown as UnsignedRootHelperSnapshotStatusRequest & { authenticationProof?: string };
  delete unsigned.authenticationProof;
  validateUnsignedRootHelperSnapshotStatusRequest(unsigned);
  return { unsigned, authenticationProof: record.authenticationProof };
}

function unsignedStatusCandidate(raw: unknown): UnsignedRootHelperSnapshotStatusRequest | undefined {
  if (!isPlainDataRecord(raw)) return undefined;
  const record = raw as Record<string, unknown>;
  if (typeof record.authenticationProof !== "string") return undefined;
  const candidate = { ...record } as unknown as UnsignedRootHelperSnapshotStatusRequest & { authenticationProof?: string };
  delete candidate.authenticationProof;
  try { validateUnsignedRootHelperSnapshotStatusRequest(candidate); return candidate; } catch { return undefined; }
}

function fallbackStatusRequest(): UnsignedRootHelperSnapshotStatusRequest {
  const now = Date.now();
  return { protocolVersion: PROTOCOL_VERSION, contractVersion: CONTRACT_VERSION, requestId: "request:root-helper-status-invalid", nonce: `root-helper-status-nonce-${"0".repeat(16)}`, timestampMs: now, expiresAtMs: now + 1, kind: "root_helper_snapshot_status" };
}

function validateReplayInput(input: Pick<UnsignedRootHelperSnapshotStatusRequest, "requestId" | "nonce" | "timestampMs" | "expiresAtMs">): void {
  if (!STATUS_REQUEST_ID_PATTERN.test(input.requestId) || !STATUS_NONCE_PATTERN.test(input.nonce) || !Number.isSafeInteger(input.timestampMs) ||
      input.timestampMs < 0 || !Number.isSafeInteger(input.expiresAtMs) || input.expiresAtMs <= input.timestampMs) {
    throw new BrokerError("PRECONDITION_FAILED", "Root-helper snapshot status replay input is malformed");
  }
}

function statusSuccess(request: UnsignedRootHelperSnapshotStatusRequest, status: RootHelperSnapshotStatusReadback, key: Buffer): RootHelperSnapshotStatusSuccessResponse {
  const body = { ok: true as const, kind: "root_helper_snapshot_status" as const, requestId: request.requestId, status };
  return { ...body, responseProof: responseProof(request, body, key) };
}

function statusFailure(errorClass: ErrorClass, message: string, requestId: string, retryable: boolean, request: UnsignedRootHelperSnapshotStatusRequest | undefined, key: Buffer): RootHelperSnapshotStatusFailureResponse {
  const body = { ok: false as const, kind: "root_helper_snapshot_status" as const, requestId, resultClass: errorClass, error: { message: boundedMessage(message), retryable } };
  return { ...body, responseProof: responseProof(request ?? fallbackStatusRequest(), body, key) };
}

function requestProof(request: UnsignedRootHelperSnapshotStatusRequest, key: Buffer): string {
  return createHmac("sha256", key).update(STATUS_REQUEST_DOMAIN).update(canonicalJson(request)).digest("hex");
}

function responseProof(request: UnsignedRootHelperSnapshotStatusRequest, body: object, key: Buffer): string {
  return createHmac("sha256", key).update(STATUS_RESPONSE_DOMAIN).update(canonicalJson(request)).update(canonicalJson(body)).digest("hex");
}

function safeEqualHex(left: string, right: string): boolean {
  if (!/^[a-f0-9]{64}$/u.test(left) || !/^[a-f0-9]{64}$/u.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function boundedMessage(value: string): string {
  return isBoundedMessage(value) ? value : "Root-helper snapshot status request failed";
}

function isBoundedMessage(value: string): boolean {
  return value.length <= 512 && !value.includes("\0") && !/[\r\n]/u.test(value);
}

function isErrorClass(value: string): value is ErrorClass {
  return (Object.values([
    "AUTH_REQUIRED", "AUTH_INVALID", "AUTH_EXPIRED", "REPLAY_DENIED", "REVOKED", "SCOPE_DENIED", "SECRET_BOUNDARY_DENIED",
    "PATH_DENIED", "NETWORK_DENIED", "PRIVILEGE_DENIED", "POLICY_DENIED", "TARGET_NOT_FOUND", "PRECONDITION_FAILED", "CONFLICT",
    "TIMEOUT", "OUTPUT_LIMIT", "CANCELLED", "EXECUTION_FAILED", "VERIFICATION_FAILED", "AUDIT_UNAVAILABLE", "UNKNOWN_OUTCOME", "UNSUPPORTED_CAPABILITY"
  ] as const) as readonly string[]).includes(value);
}

function sameKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
}

function isAsciiWhitespace(byte: number): boolean {
  return byte === 0x09 || byte === 0x0a || byte === 0x0d || byte === 0x20;
}

function writeStatusResponse(socket: Socket, response: RootHelperSnapshotStatusResponse): void {
  const serialized = `${JSON.stringify(response)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > MAX_RESPONSE_BYTES) {
    socket.destroy();
    return;
  }
  socket.end(serialized);
}
