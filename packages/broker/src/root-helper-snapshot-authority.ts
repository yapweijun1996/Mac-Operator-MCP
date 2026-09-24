import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { connect, type Socket } from "node:net";
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
import { captureSocketPathIdentity, type SocketPathIdentity } from "./ipc-server.js";
import { MacOsNativePeerIpcServer, type NativePeerPolicy } from "./native-peer-ipc-server.js";
import { MacOsPeerCredentialVerifier } from "./peer-credentials.js";
import { isPlainDataRecord } from "./plain-record.js";
import type { BrokerStore } from "./persistence.js";
import type { RootHelperSnapshotRequestAdmission } from "./root-helper-snapshot.js";

const REQUEST_DOMAIN = "mac-operator-root-helper-snapshot-authority-request-v0.1\0";
const RESPONSE_DOMAIN = "mac-operator-root-helper-snapshot-authority-response-v0.1\0";
const REQUEST_ID_PATTERN = /^request:root-helper-authority-[A-Za-z0-9._:-]{16,128}$/u;
const NONCE_PATTERN = /^root-helper-authority-nonce-[A-Za-z0-9._:-]{16,128}$/u;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const MAX_REQUEST_BYTES = 32 * 1024;
const MAX_RESPONSE_BYTES = 16 * 1024;
const MAX_REQUEST_AGE_MS = 60_000;

export interface UnsignedRootHelperSnapshotAuthorityRequest {
  protocolVersion: typeof PROTOCOL_VERSION;
  contractVersion: typeof CONTRACT_VERSION;
  requestId: string;
  nonce: string;
  nonceExpiresAtMs: number;
  timestampMs: number;
  expiresAtMs: number;
  kind: "snapshot_authority_check";
  requestDigest: string;
}

export interface SignedRootHelperSnapshotAuthorityRequest extends UnsignedRootHelperSnapshotAuthorityRequest {
  authenticationProof: string;
}

export type RootHelperSnapshotAuthorityResponse =
  | {
      ok: true;
      kind: "snapshot_authority_check";
      requestId: string;
      requestDigest: string;
      authorized: true;
      responseProof: string;
    }
  | {
      ok: false;
      kind: "snapshot_authority_check";
      requestId: string;
      requestDigest: string;
      resultClass: ErrorClass;
      error: { message: string; retryable: boolean };
      responseProof: string;
    };

export interface RootHelperSnapshotAuthorityReplayGuard {
  admit(input: Pick<UnsignedRootHelperSnapshotAuthorityRequest, "requestId" | "nonce" | "timestampMs" | "nonceExpiresAtMs">): void;
}

/**
 * Broker-owned active-request registry shared by the transport and authority
 * listener. A valid HMAC poll is still denied unless its digest was admitted
 * by the Broker for a currently executing task.
 */
export interface RootHelperSnapshotRequestAuthority extends RootHelperSnapshotRequestAdmission {
  admit(requestDigest: string, expiresAtMs: number): void;
  assertAuthorized(requestDigest: string): void;
  release(requestDigest: string): void;
  revoke(requestDigest?: string): void;
}

export class InMemoryRootHelperSnapshotRequestAuthority implements RootHelperSnapshotRequestAuthority {
  private readonly active = new Map<string, number>();

  constructor(private readonly maxEntries = 256, private readonly now: () => number = Date.now) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > 4_096 || typeof now !== "function") {
      throw new Error("Root-helper snapshot request authority limits are invalid");
    }
  }

  admit(requestDigest: string, expiresAtMs: number): void {
    validateRequestAuthorityDigest(requestDigest);
    const nowMs = this.now();
    if (!Number.isSafeInteger(nowMs) || nowMs < 0 || !Number.isSafeInteger(expiresAtMs) || expiresAtMs <= nowMs) {
      throw new BrokerError("AUTH_EXPIRED", "Root-helper snapshot request authority window is invalid");
    }
    this.prune(nowMs);
    if (this.active.size >= this.maxEntries) throw new BrokerError("OUTPUT_LIMIT", "Root-helper snapshot active-request registry is full");
    if (this.active.has(requestDigest)) throw new BrokerError("CONFLICT", "Root-helper snapshot request digest is already active");
    this.active.set(requestDigest, expiresAtMs);
  }

  assertAuthorized(requestDigest: string): void {
    validateRequestAuthorityDigest(requestDigest);
    const nowMs = this.now();
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new BrokerError("PRECONDITION_FAILED", "Root-helper snapshot authority clock is invalid");
    const expiresAtMs = this.active.get(requestDigest);
    if (expiresAtMs === undefined) throw new BrokerError("REVOKED", "Root-helper snapshot request is not active");
    if (nowMs >= expiresAtMs) {
      this.active.delete(requestDigest);
      throw new BrokerError("AUTH_EXPIRED", "Root-helper snapshot request authority has expired");
    }
  }

  release(requestDigest: string): void {
    validateRequestAuthorityDigest(requestDigest);
    this.active.delete(requestDigest);
  }

  revoke(requestDigest?: string): void {
    if (requestDigest === undefined) {
      this.active.clear();
      return;
    }
    validateRequestAuthorityDigest(requestDigest);
    this.active.delete(requestDigest);
  }

  private prune(nowMs: number): void {
    for (const [digest, expiresAtMs] of this.active) if (expiresAtMs <= nowMs) this.active.delete(digest);
  }
}

/** Durable replay adapter using the Broker's existing helper nonce ledger. */
export class BrokerStoreRootHelperSnapshotAuthorityReplayGuard implements RootHelperSnapshotAuthorityReplayGuard {
  constructor(private readonly store: Pick<BrokerStore, "admitPrivilegedHelperCommand">) {}

  admit(input: Pick<UnsignedRootHelperSnapshotAuthorityRequest, "requestId" | "nonce" | "timestampMs" | "nonceExpiresAtMs">): void {
    validateReplayInput(input);
    this.store.admitPrivilegedHelperCommand({
      requestId: input.requestId,
      nonce: input.nonce,
      acceptedAtMs: input.timestampMs,
      expiresAtMs: input.nonceExpiresAtMs
    });
  }
}

export class InMemoryRootHelperSnapshotAuthorityReplayGuard implements RootHelperSnapshotAuthorityReplayGuard {
  private readonly accepted = new Map<string, number>();

  constructor(private readonly maxEntries = 4096) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > 65_536) {
      throw new Error("Root-helper snapshot authority replay capacity is invalid");
    }
  }

  admit(input: Pick<UnsignedRootHelperSnapshotAuthorityRequest, "requestId" | "nonce" | "timestampMs" | "nonceExpiresAtMs">): void {
    validateReplayInput(input);
    for (const [key, expiry] of this.accepted) if (expiry <= input.timestampMs) this.accepted.delete(key);
    if (this.accepted.size >= this.maxEntries) throw new BrokerError("OUTPUT_LIMIT", "Root-helper snapshot authority replay ledger is full");
    const requestKey = `request:${input.requestId}|nonce:${input.nonce}`;
    if (this.accepted.has(requestKey)) throw new BrokerError("REPLAY_DENIED", "Root-helper snapshot authority poll was already accepted");
    this.accepted.set(requestKey, input.nonceExpiresAtMs);
  }
}

export interface RootHelperSnapshotAuthorityIpcServerOptions {
  socketPath: string;
  authenticationKey: Buffer;
  replayGuard: RootHelperSnapshotAuthorityReplayGuard;
  authorizeRequest: (requestDigest: string) => void;
  /** The expected peer is the root-owned helper process identity. */
  peerPolicy: NativePeerPolicy;
  now?: () => number;
  maxRequestAgeMs?: number;
}

function validateRequestAuthorityDigest(value: string): void {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) {
    throw new BrokerError("PRECONDITION_FAILED", "Root-helper snapshot request digest is invalid");
  }
}

/** Broker-owned authority endpoint used only by the root-helper poller. */
export class RootHelperSnapshotAuthorityIpcServer {
  private readonly authenticationKey: Buffer;
  private readonly now: () => number;
  private readonly maxRequestAgeMs: number;
  private nativeTransport: MacOsNativePeerIpcServer | undefined;

  constructor(private readonly options: RootHelperSnapshotAuthorityIpcServerOptions) {
    if (!canonicalSocketPath(options.socketPath) || Buffer.byteLength(options.socketPath, "utf8") >= 104 ||
        !Buffer.isBuffer(options.authenticationKey) || options.authenticationKey.byteLength < 32 ||
        !options.replayGuard || typeof options.authorizeRequest !== "function" ||
        !options.peerPolicy || !Number.isSafeInteger(options.peerPolicy.expectedUid) || options.peerPolicy.expectedUid < 1) {
      throw new Error("Root-helper snapshot authority server options are invalid");
    }
    this.authenticationKey = Buffer.from(options.authenticationKey);
    this.now = options.now ?? Date.now;
    this.maxRequestAgeMs = options.maxRequestAgeMs ?? MAX_REQUEST_AGE_MS;
    if (!Number.isSafeInteger(this.maxRequestAgeMs) || this.maxRequestAgeMs < 1 || this.maxRequestAgeMs > MAX_REQUEST_AGE_MS) {
      this.authenticationKey.fill(0);
      throw new Error("Root-helper snapshot authority server request age is invalid");
    }
  }

  async listen(): Promise<void> {
    if (this.nativeTransport) throw new Error("Root-helper snapshot authority server is already running");
    this.nativeTransport = new MacOsNativePeerIpcServer({
      socketPath: this.options.socketPath,
      peerPolicy: this.options.peerPolicy,
      onSocket: (socket) => this.handleSocket(socket)
    });
    try {
      await this.nativeTransport.listen();
    } catch (error) {
      this.nativeTransport = undefined;
      throw error;
    }
  }

  async close(): Promise<void> {
    const transport = this.nativeTransport;
    this.nativeTransport = undefined;
    try {
      await transport?.close();
    } finally {
      this.authenticationKey.fill(0);
    }
  }

  private handleSocket(socket: Socket): void {
    const chunks: Buffer[] = [];
    let total = 0;
    let handled = false;
    socket.setTimeout(this.maxRequestAgeMs + 5_000, () => socket.destroy());
    socket.on("data", (chunk: Buffer) => {
      if (handled) return;
      total += chunk.byteLength;
      if (total > MAX_REQUEST_BYTES) {
        handled = true;
        socket.destroy();
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      handled = true;
      socket.pause();
      let request: UnsignedRootHelperSnapshotAuthorityRequest | undefined;
      let response: RootHelperSnapshotAuthorityResponse;
      try {
        const raw = parseJsonUtf8Strict(combined.subarray(0, newline));
        request = authenticateRootHelperSnapshotAuthorityRequest(raw, this.authenticationKey, this.now(), this.maxRequestAgeMs);
        if (combined.subarray(newline + 1).some((byte) => !isAsciiWhitespace(byte))) {
          throw new BrokerError("PRECONDITION_FAILED", "Root-helper snapshot authority request contained trailing data");
        }
        this.options.replayGuard.admit(request);
        this.options.authorizeRequest(request.requestDigest);
        response = authoritySuccess(request, this.authenticationKey);
      } catch (error) {
        const brokerError = error instanceof BrokerError ? error : new BrokerError("PRECONDITION_FAILED", "Root-helper snapshot authority request is invalid");
        const fallback = request ?? fallbackRequest();
        response = authorityFailure(brokerError.errorClass, brokerError.message, fallback, brokerError.retryable, this.authenticationKey);
      }
      const serialized = `${JSON.stringify(response)}\n`;
      if (Buffer.byteLength(serialized, "utf8") > MAX_RESPONSE_BYTES) socket.destroy();
      else socket.end(serialized);
    });
  }
}

export interface RootHelperSnapshotAuthorityPoller {
  assertAuthorized(requestDigest: string, expiresAtMs: number): Promise<void>;
  dispose?: () => void;
}

export interface RootHelperSnapshotAuthorityClientOptions {
  socketPath: string;
  authenticationKey: Buffer;
  /** Broker peer authentication is mandatory for the root-helper client. */
  peerPolicy: NativePeerPolicy;
  timeoutMs?: number;
  maxRequestAgeMs?: number;
  now?: () => number;
}

/** Root-helper-side client for pre/during/post execution Broker authority polls. */
export class RootHelperSnapshotAuthorityClient implements RootHelperSnapshotAuthorityPoller {
  private readonly authenticationKey: Buffer;
  private readonly now: () => number;
  private readonly timeoutMs: number;
  private readonly maxRequestAgeMs: number;
  private readonly peerCredentialVerifier: MacOsPeerCredentialVerifier;
  private disposed = false;

  constructor(private readonly options: RootHelperSnapshotAuthorityClientOptions) {
    if (!canonicalSocketPath(options.socketPath) || Buffer.byteLength(options.socketPath, "utf8") >= 104 ||
        !Buffer.isBuffer(options.authenticationKey) || options.authenticationKey.byteLength < 32 ||
        !options.peerPolicy || !Number.isSafeInteger(options.peerPolicy.expectedUid) || options.peerPolicy.expectedUid < 1) {
      throw new Error("Root-helper snapshot authority client options are invalid");
    }
    this.authenticationKey = Buffer.from(options.authenticationKey);
    this.now = options.now ?? Date.now;
    this.timeoutMs = options.timeoutMs ?? 5_000;
    this.maxRequestAgeMs = options.maxRequestAgeMs ?? MAX_REQUEST_AGE_MS;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > 15_000 ||
        !Number.isSafeInteger(this.maxRequestAgeMs) || this.maxRequestAgeMs < 1 || this.maxRequestAgeMs > MAX_REQUEST_AGE_MS) {
      this.authenticationKey.fill(0);
      throw new Error("Root-helper snapshot authority client limits are invalid");
    }
    this.peerCredentialVerifier = new MacOsPeerCredentialVerifier(options.peerPolicy);
  }

  async assertAuthorized(requestDigest: string, expiresAtMs: number): Promise<void> {
    if (this.disposed) throw new BrokerError("CANCELLED", "Root-helper snapshot authority client is disposed");
    if (!DIGEST_PATTERN.test(requestDigest)) throw new BrokerError("PRECONDITION_FAILED", "Root-helper snapshot request digest is invalid");
    const timestampMs = this.now();
    if (!Number.isSafeInteger(timestampMs) || timestampMs < 0 || !Number.isSafeInteger(expiresAtMs) || expiresAtMs <= timestampMs) {
      throw new BrokerError("AUTH_EXPIRED", "Root-helper snapshot authority poll is expired");
    }
    const effectiveExpiresAtMs = Math.min(expiresAtMs, timestampMs + this.timeoutMs, timestampMs + this.maxRequestAgeMs);
    if (effectiveExpiresAtMs <= timestampMs) throw new BrokerError("AUTH_EXPIRED", "Root-helper snapshot authority poll is expired");
    const request: UnsignedRootHelperSnapshotAuthorityRequest = {
      protocolVersion: PROTOCOL_VERSION,
      contractVersion: CONTRACT_VERSION,
      requestId: `request:root-helper-authority-${randomBytes(16).toString("hex")}`,
      nonce: `root-helper-authority-nonce-${randomBytes(16).toString("hex")}`,
      nonceExpiresAtMs: effectiveExpiresAtMs,
      timestampMs,
      expiresAtMs: effectiveExpiresAtMs,
      kind: "snapshot_authority_check",
      requestDigest
    };
    const signed = signRootHelperSnapshotAuthorityRequest(request, this.authenticationKey);
    const before = await this.captureSocket();
    const response = await exchangeAuthoritySocket(
        this.options.socketPath,
        `${JSON.stringify(signed)}\n`,
        this.timeoutMs,
        this.peerCredentialVerifier
      );
    const after = await this.captureSocket();
    if (before.device !== after.device || before.inode !== after.inode) {
      throw new BrokerError("CONFLICT", "Root-helper snapshot authority socket identity changed during polling", true);
    }
    const verified = authenticateRootHelperSnapshotAuthorityResponse(response, request, this.authenticationKey);
    if (!verified.ok) throw new BrokerError(verified.resultClass, verified.error.message, verified.error.retryable);
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.authenticationKey.fill(0);
  }

  private async captureSocket(): Promise<SocketPathIdentity> {
    try { return await captureSocketPathIdentity(this.options.socketPath); }
    catch { throw new BrokerError("TARGET_NOT_FOUND", "Root-helper snapshot authority socket is unavailable"); }
  }
}

export function signRootHelperSnapshotAuthorityRequest(
  request: UnsignedRootHelperSnapshotAuthorityRequest,
  authenticationKey: Buffer
): SignedRootHelperSnapshotAuthorityRequest {
  validateUnsignedRootHelperSnapshotAuthorityRequest(request);
  if (authenticationKey.byteLength < 32) throw new BrokerError("AUTH_INVALID", "Root-helper snapshot authority key is invalid");
  return { ...request, authenticationProof: requestProof(request, authenticationKey) };
}

export function authenticateRootHelperSnapshotAuthorityRequest(
  raw: unknown,
  authenticationKey: Buffer,
  nowMs: number,
  maxRequestAgeMs = MAX_REQUEST_AGE_MS
): UnsignedRootHelperSnapshotAuthorityRequest {
  if (authenticationKey.byteLength < 32) throw new BrokerError("AUTH_INVALID", "Root-helper snapshot authority key is invalid");
  if (!isPlainDataRecord(raw)) throw new BrokerError("PRECONDITION_FAILED", "Root-helper snapshot authority envelope is malformed");
  const record = raw as Record<string, unknown>;
  const allowed = ["authenticationProof", "contractVersion", "expiresAtMs", "kind", "nonce", "nonceExpiresAtMs", "protocolVersion", "requestDigest", "requestId", "timestampMs"];
  if (Object.keys(record).length !== allowed.length || allowed.some((key) => !Object.hasOwn(record, key)) ||
      typeof record.authenticationProof !== "string" || !/^[a-f0-9]{64}$/u.test(record.authenticationProof)) {
    throw new BrokerError("PRECONDITION_FAILED", "Root-helper snapshot authority envelope is malformed");
  }
  const request = {
    protocolVersion: record.protocolVersion as typeof PROTOCOL_VERSION,
    contractVersion: record.contractVersion as typeof CONTRACT_VERSION,
    requestId: record.requestId as string,
    nonce: record.nonce as string,
    nonceExpiresAtMs: record.nonceExpiresAtMs as number,
    timestampMs: record.timestampMs as number,
    expiresAtMs: record.expiresAtMs as number,
    kind: record.kind as "snapshot_authority_check",
    requestDigest: record.requestDigest as string
  } satisfies UnsignedRootHelperSnapshotAuthorityRequest;
  validateUnsignedRootHelperSnapshotAuthorityRequest(request);
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || request.timestampMs > nowMs + 5_000 ||
      nowMs - request.timestampMs > maxRequestAgeMs || request.expiresAtMs <= nowMs ||
      request.expiresAtMs > request.timestampMs + maxRequestAgeMs + 5_000 || request.nonceExpiresAtMs <= nowMs ||
      request.nonceExpiresAtMs > request.timestampMs + maxRequestAgeMs + 5_000 ||
      !safeEqualHex(record.authenticationProof as string, requestProof(request, authenticationKey))) {
    throw new BrokerError("AUTH_INVALID", "Root-helper snapshot authority authentication failed or expired");
  }
  return request;
}

export function authenticateRootHelperSnapshotAuthorityResponse(
  raw: unknown,
  request: UnsignedRootHelperSnapshotAuthorityRequest,
  authenticationKey: Buffer
): RootHelperSnapshotAuthorityResponse {
  validateUnsignedRootHelperSnapshotAuthorityRequest(request);
  if (authenticationKey.byteLength < 32 || !isPlainDataRecord(raw)) throw new BrokerError("AUTH_INVALID", "Root-helper snapshot authority response is invalid");
  const response = raw as Record<string, unknown>;
  if (response.kind !== "snapshot_authority_check" || response.requestId !== request.requestId || response.requestDigest !== request.requestDigest ||
      typeof response.responseProof !== "string") throw new BrokerError("AUTH_INVALID", "Root-helper snapshot authority response identity is invalid");
  const body = { ...response };
  delete body.responseProof;
  if (!safeEqualHex(response.responseProof as string, responseProof(request, body, authenticationKey))) {
    throw new BrokerError("AUTH_INVALID", "Root-helper snapshot authority response authentication failed");
  }
  if (response.ok === true) {
    const expectedKeys = ["authorized", "kind", "ok", "requestDigest", "requestId", "responseProof"];
    const keys = Object.keys(response).sort();
    if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index]) || response.authorized !== true) {
      throw new BrokerError("EXECUTION_FAILED", "Root-helper snapshot authority success is malformed");
    }
    return response as unknown as RootHelperSnapshotAuthorityResponse;
  }
  const expectedKeys = ["error", "kind", "ok", "requestDigest", "requestId", "responseProof", "resultClass"];
  const keys = Object.keys(response).sort();
  if (response.ok !== false || keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index]) ||
      typeof response.resultClass !== "string" || !isErrorClass(response.resultClass) || !isPlainDataRecord(response.error) ||
      Object.keys(response.error).length !== 2 || typeof (response.error as Record<string, unknown>).message !== "string" ||
      typeof (response.error as Record<string, unknown>).retryable !== "boolean" ||
      boundedMessage((response.error as Record<string, unknown>).message as string) !== (response.error as Record<string, unknown>).message) {
    throw new BrokerError("EXECUTION_FAILED", "Root-helper snapshot authority failure is malformed");
  }
  return response as unknown as RootHelperSnapshotAuthorityResponse;
}

function validateUnsignedRootHelperSnapshotAuthorityRequest(request: UnsignedRootHelperSnapshotAuthorityRequest): void {
  if (!isPlainDataRecord(request) || request.protocolVersion !== PROTOCOL_VERSION || request.contractVersion !== CONTRACT_VERSION ||
      !REQUEST_ID_PATTERN.test(request.requestId) || !NONCE_PATTERN.test(request.nonce) || request.kind !== "snapshot_authority_check" ||
      !DIGEST_PATTERN.test(request.requestDigest) || !Number.isSafeInteger(request.timestampMs) || request.timestampMs < 0 ||
      !Number.isSafeInteger(request.expiresAtMs) || request.expiresAtMs <= request.timestampMs ||
      !Number.isSafeInteger(request.nonceExpiresAtMs) || request.nonceExpiresAtMs <= request.timestampMs) {
    throw new BrokerError("PRECONDITION_FAILED", "Root-helper snapshot authority request is malformed");
  }
}

function validateReplayInput(input: Pick<UnsignedRootHelperSnapshotAuthorityRequest, "requestId" | "nonce" | "timestampMs" | "nonceExpiresAtMs">): void {
  if (!REQUEST_ID_PATTERN.test(input.requestId) || !NONCE_PATTERN.test(input.nonce) || !Number.isSafeInteger(input.timestampMs) ||
      input.timestampMs < 0 || !Number.isSafeInteger(input.nonceExpiresAtMs) || input.nonceExpiresAtMs <= input.timestampMs) {
    throw new BrokerError("PRECONDITION_FAILED", "Root-helper snapshot authority replay admission is malformed");
  }
}

function authoritySuccess(request: UnsignedRootHelperSnapshotAuthorityRequest, key: Buffer): Extract<RootHelperSnapshotAuthorityResponse, { ok: true }> {
  const body = { ok: true as const, kind: "snapshot_authority_check" as const, requestId: request.requestId, requestDigest: request.requestDigest, authorized: true as const };
  return { ...body, responseProof: responseProof(request, body, key) };
}

function authorityFailure(
  resultClass: ErrorClass,
  message: string,
  request: UnsignedRootHelperSnapshotAuthorityRequest,
  retryable: boolean,
  key: Buffer
): Extract<RootHelperSnapshotAuthorityResponse, { ok: false }> {
  const body = { ok: false as const, kind: "snapshot_authority_check" as const, requestId: request.requestId, requestDigest: request.requestDigest, resultClass, error: { message: boundedMessage(message), retryable } };
  return { ...body, responseProof: responseProof(request, body, key) };
}

function requestProof(request: UnsignedRootHelperSnapshotAuthorityRequest, key: Buffer): string {
  return createHmac("sha256", key).update(REQUEST_DOMAIN, "utf8").update(sha256(canonicalJson(request)), "utf8").digest("hex");
}

function responseProof(request: UnsignedRootHelperSnapshotAuthorityRequest, body: object, key: Buffer): string {
  return createHmac("sha256", key).update(RESPONSE_DOMAIN, "utf8").update(sha256(canonicalJson(request)), "utf8").update(canonicalJson(body), "utf8").digest("hex");
}

function fallbackRequest(): UnsignedRootHelperSnapshotAuthorityRequest {
  return {
    protocolVersion: PROTOCOL_VERSION,
    contractVersion: CONTRACT_VERSION,
    requestId: "request:root-helper-authority-invalid",
    nonce: "root-helper-authority-nonce-invalid-invalid",
    nonceExpiresAtMs: 2,
    timestampMs: 0,
    expiresAtMs: 2,
    kind: "snapshot_authority_check",
    requestDigest: "0".repeat(64)
  };
}

function canonicalSocketPath(value: unknown): value is string {
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
  return value.length <= 512 && !value.includes("\0") && !/[\r\n]/u.test(value) ? value : "Root-helper snapshot authority request failed";
}

function isErrorClass(value: string): value is ErrorClass {
  return (Object.values([
    "AUTH_REQUIRED", "AUTH_INVALID", "AUTH_EXPIRED", "REPLAY_DENIED", "REVOKED", "SCOPE_DENIED", "SECRET_BOUNDARY_DENIED",
    "PATH_DENIED", "NETWORK_DENIED", "PRIVILEGE_DENIED", "POLICY_DENIED", "TARGET_NOT_FOUND", "PRECONDITION_FAILED", "CONFLICT",
    "TIMEOUT", "OUTPUT_LIMIT", "CANCELLED", "EXECUTION_FAILED", "VERIFICATION_FAILED", "AUDIT_UNAVAILABLE", "UNKNOWN_OUTCOME", "UNSUPPORTED_CAPABILITY"
  ] as const) as readonly string[]).includes(value);
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
    socket.setTimeout(timeoutMs, () => fail(new BrokerError("TIMEOUT", "Root-helper snapshot authority poll timed out", true)));
    socket.once("error", () => fail(new BrokerError("UNKNOWN_OUTCOME", "Root-helper snapshot authority transport failed", true)));
    socket.on("data", (chunk: Buffer) => {
      if (settled) return;
      total += chunk.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        fail(new BrokerError("OUTPUT_LIMIT", "Root-helper snapshot authority response exceeded the byte limit"));
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      if (combined.subarray(newline + 1).some((byte) => !isAsciiWhitespace(byte))) {
        fail(new BrokerError("AUTH_INVALID", "Root-helper snapshot authority response contained trailing data"));
        return;
      }
      settled = true;
      socket.destroy();
      try { resolvePromise(parseJsonUtf8Strict(combined.subarray(0, newline))); }
      catch { reject(new BrokerError("EXECUTION_FAILED", "Root-helper snapshot authority response is not valid JSON")); }
    });
    socket.on("close", () => {
      if (!settled) fail(new BrokerError("UNKNOWN_OUTCOME", "Root-helper snapshot authority channel closed without a response", true));
    });
    socket.once("connect", () => {
      try {
        peerCredentialVerifier.verify(socket);
        socket.write(serialized);
      } catch {
        fail(new BrokerError("AUTH_INVALID", "Root-helper snapshot authority Broker peer authentication failed"));
      }
    });
  });
}
