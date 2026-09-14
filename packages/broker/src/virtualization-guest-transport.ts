import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { BrokerError, canonicalJson, CONTRACT_VERSION, decodeUtf8Strict, PROTOCOL_VERSION, sha256 } from "@mac-operator/contracts";
import type { BrokerStore } from "./persistence.js";
import type { VirtualizationGuestIdentity } from "./task-runner.js";

const REQUEST_DOMAIN = "mac-operator-virtualization-guest-request-v0.1\0";
const RESPONSE_DOMAIN = "mac-operator-virtualization-guest-response-v0.1\0";
const STATUS_REQUEST_DOMAIN = "mac-operator-virtualization-guest-status-request-v0.1\0";
const STATUS_RESPONSE_DOMAIN = "mac-operator-virtualization-guest-status-response-v0.1\0";
const REQUEST_ID_PATTERN = /^request:guest-[A-Za-z0-9._:-]{16,128}$/u;
const NONCE_PATTERN = /^guest-nonce-[A-Za-z0-9._:-]{16,128}$/u;
const STATUS_REQUEST_ID_PATTERN = /^request:guest-status-[A-Za-z0-9._:-]{16,128}$/u;
const STATUS_NONCE_PATTERN = /^guest-status-nonce-[A-Za-z0-9._:-]{16,128}$/u;
const PROFILE_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const RUNTIME_VERSION_PATTERN = /^[A-Za-z0-9._:+/-]{1,128}$/u;
const MAX_REQUEST_AGE_MS = 60_000;
const MAX_CLOCK_SKEW_MS = 5_000;
const MAX_TIMEOUT_MS = 15 * 60_000;
const MAX_OUTPUT_CAP_BYTES = 4 * 1024 * 1024;
const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = MAX_OUTPUT_CAP_BYTES + 64 * 1024;
const MAX_SUMMARY_BYTES = 512;
const MAX_REPLAY_ENTRIES = 4096;

export type VirtualizationGuestProcessTreePolicy = "single_process" | "owned_group";
export type VirtualizationGuestTaskState = "completed" | "failed" | "cancelled" | "timed_out" | "unknown";
export type VirtualizationGuestResultClass =
  | "SUCCEEDED"
  | "EXECUTION_FAILED"
  | "CANCELLED"
  | "TIMEOUT"
  | "OUTPUT_LIMIT"
  | "VERIFICATION_FAILED"
  | "UNKNOWN_OUTCOME";
export type VirtualizationGuestVerificationStatus = "verified" | "failed" | "unknown" | "not_run";

export interface UnsignedVirtualizationGuestRequest {
  schemaVersion: "0.1";
  protocolVersion: typeof PROTOCOL_VERSION;
  contractVersion: typeof CONTRACT_VERSION;
  kind: "virtualization_guest_task";
  requestId: string;
  nonce: string;
  timestampMs: number;
  expiresAtMs: number;
  guestIdentity: VirtualizationGuestIdentity;
  sandboxProfile: string;
  profileDigest: string;
  taskDigest: string;
  processTreePolicy: VirtualizationGuestProcessTreePolicy;
  timeoutMs: number;
  outputCapBytes: number;
  operation: "task_run";
}

export interface SignedVirtualizationGuestRequest extends UnsignedVirtualizationGuestRequest {
  authenticationProof: string;
}

export interface UnsignedVirtualizationGuestResponse {
  schemaVersion: "0.1";
  protocolVersion: typeof PROTOCOL_VERSION;
  contractVersion: typeof CONTRACT_VERSION;
  kind: "virtualization_guest_task_result";
  requestId: string;
  nonce: string;
  guestIdentity: VirtualizationGuestIdentity;
  requestDigest: string;
  state: VirtualizationGuestTaskState;
  resultClass: VirtualizationGuestResultClass;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  durationMs: number;
  outputPolicy: "broker-redacted-v1";
  verification: {
    status: VirtualizationGuestVerificationStatus;
    summary?: string;
  };
}

export interface SignedVirtualizationGuestResponse extends UnsignedVirtualizationGuestResponse {
  responseProof: string;
}

/** A fresh, replay-protected request used to recover one prior task outcome. */
export interface UnsignedVirtualizationGuestStatusRequest {
  schemaVersion: "0.1";
  protocolVersion: typeof PROTOCOL_VERSION;
  contractVersion: typeof CONTRACT_VERSION;
  kind: "virtualization_guest_task_status";
  requestId: string;
  nonce: string;
  timestampMs: number;
  expiresAtMs: number;
  guestIdentity: VirtualizationGuestIdentity;
  originalRequestId: string;
  originalNonce: string;
  originalRequestDigest: string;
  timeoutMs: number;
  outputCapBytes: number;
  operation: "task_status";
}

export interface SignedVirtualizationGuestStatusRequest extends UnsignedVirtualizationGuestStatusRequest {
  authenticationProof: string;
}

export interface UnsignedVirtualizationGuestStatusResponse {
  schemaVersion: "0.1";
  protocolVersion: typeof PROTOCOL_VERSION;
  contractVersion: typeof CONTRACT_VERSION;
  kind: "virtualization_guest_task_status_result";
  requestId: string;
  nonce: string;
  guestIdentity: VirtualizationGuestIdentity;
  originalRequestId: string;
  originalNonce: string;
  originalRequestDigest: string;
  statusRequestDigest: string;
  state: VirtualizationGuestTaskState;
  resultClass: VirtualizationGuestResultClass;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  durationMs: number;
  outputPolicy: "broker-redacted-v1";
  verification: {
    status: VirtualizationGuestVerificationStatus;
    summary?: string;
  };
}

export interface SignedVirtualizationGuestStatusResponse extends UnsignedVirtualizationGuestStatusResponse {
  responseProof: string;
}

export interface VirtualizationGuestRequestInput {
  guestIdentity: VirtualizationGuestIdentity;
  sandboxProfile: string;
  profileDigest: string;
  taskDigest: string;
  processTreePolicy: VirtualizationGuestProcessTreePolicy;
  timeoutMs: number;
  outputCapBytes: number;
  requestId?: string;
  nonce?: string;
  timestampMs?: number;
  expiresAtMs?: number;
}

export interface VirtualizationGuestStatusLookupInput {
  guestIdentity: VirtualizationGuestIdentity;
  originalRequestId: string;
  originalNonce: string;
  originalRequestDigest: string;
  timeoutMs: number;
  outputCapBytes: number;
  requestId?: string;
  nonce?: string;
  timestampMs?: number;
  expiresAtMs?: number;
}

export interface VirtualizationGuestReplayGuard {
  admit(input: Pick<UnsignedVirtualizationGuestRequest, "requestId" | "nonce" | "expiresAtMs">): void;
}

/**
 * Process-local replay guard for tests and a single Broker lifetime. Production
 * callers should use a BrokerStore-backed implementation so accepted nonces
 * survive a restart before enabling the guest bridge.
 */
export class InMemoryVirtualizationGuestReplayGuard implements VirtualizationGuestReplayGuard {
  private readonly accepted = new Map<string, number>();
  private readonly maxEntries: number;
  private readonly now: () => number;

  constructor(options: { maxEntries?: number; now?: () => number } = {}) {
    this.maxEntries = options.maxEntries ?? MAX_REPLAY_ENTRIES;
    this.now = options.now ?? Date.now;
    if (!Number.isSafeInteger(this.maxEntries) || this.maxEntries < 1 || this.maxEntries > MAX_REPLAY_ENTRIES) {
      throw new Error("Virtualization guest replay guard capacity is invalid");
    }
  }

  admit(input: Pick<UnsignedVirtualizationGuestRequest, "requestId" | "nonce" | "expiresAtMs">): void {
    const now = this.now();
    for (const [key, expiresAtMs] of this.accepted) {
      if (expiresAtMs < now) this.accepted.delete(key);
    }
    const requestKey = `request:${input.requestId}`;
    const nonceKey = `nonce:${input.nonce}`;
    if (this.accepted.has(requestKey) || this.accepted.has(nonceKey)) {
      throw new BrokerError("REPLAY_DENIED", "Virtualization guest request nonce or request ID was already accepted");
    }
    if (this.accepted.size + 2 > this.maxEntries) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Virtualization guest replay guard is at capacity");
    }
    this.accepted.set(requestKey, input.expiresAtMs);
    this.accepted.set(nonceKey, input.expiresAtMs);
  }
}

/** Durable replay admission owned by the Broker persistence boundary. */
export class BrokerStoreVirtualizationGuestReplayGuard implements VirtualizationGuestReplayGuard {
  private readonly now: () => number;

  constructor(
    private readonly store: Pick<BrokerStore, "admitVirtualizationGuestRequest">,
    options: { now?: () => number } = {}
  ) {
    this.now = options.now ?? Date.now;
  }

  admit(input: Pick<UnsignedVirtualizationGuestRequest, "requestId" | "nonce" | "expiresAtMs">): void {
    this.store.admitVirtualizationGuestRequest({
      requestId: input.requestId,
      nonce: input.nonce,
      acceptedAtMs: this.now(),
      expiresAtMs: input.expiresAtMs
    });
  }
}

export interface VerifyVirtualizationGuestRequestOptions {
  replayGuard: VirtualizationGuestReplayGuard;
  now?: number;
  maxRequestAgeMs?: number;
  allowedClockSkewMs?: number;
  expectedGuestIdentity?: VirtualizationGuestIdentity;
  expectedSandboxProfile?: string;
  expectedProfileDigest?: string;
}

export interface VerifyVirtualizationGuestResponseOptions {
  expectedGuestIdentity?: VirtualizationGuestIdentity;
  expectedOutputCapBytes?: number;
}

/**
 * The native side owns the actual VM/virtio channel. The Broker supplies a
 * bounded signed frame and an abort signal; it never sends a host path, raw
 * executable, credential, or arbitrary command to this channel.
 */
export interface VirtualizationGuestChannel {
  exchange(frame: Uint8Array, signal: AbortSignal): Promise<Uint8Array>;
}

export interface VirtualizationGuestTransportClientOptions {
  authenticationKey: Buffer;
  replayGuard: VirtualizationGuestReplayGuard;
  channel: VirtualizationGuestChannel;
  now?: () => number;
  expectedGuestIdentity?: VirtualizationGuestIdentity;
  expectedSandboxProfile?: string;
  expectedProfileDigest?: string;
  maxResponseBytes?: number;
  cancellationPollMs?: number;
  /** Broker-owned Job/authority check required before any status lookup. */
  authorizeStatusLookup?: (input: VirtualizationGuestStatusLookupInput) => void;
}

export interface VirtualizationGuestExchangeOptions {
  shouldCancel?: () => boolean;
  /** Called only after request authentication and replay admission. */
  onRequestAdmitted?: (request: UnsignedVirtualizationGuestRequest) => void;
  /** Optional per-call Broker authority for a status lookup. */
  authorizeStatusLookup?: (input: VirtualizationGuestStatusLookupInput) => void;
}

export function createVirtualizationGuestRequest(
  input: VirtualizationGuestRequestInput,
  authenticationKey: Buffer,
  options: { now?: number; requestId?: string; nonce?: string } = {}
): SignedVirtualizationGuestRequest {
  const now = options.now ?? Date.now();
  const request: UnsignedVirtualizationGuestRequest = {
    schemaVersion: "0.1",
    protocolVersion: PROTOCOL_VERSION,
    contractVersion: CONTRACT_VERSION,
    kind: "virtualization_guest_task",
    requestId: input.requestId ?? options.requestId ?? `request:guest-${randomBytes(16).toString("hex")}`,
    nonce: input.nonce ?? options.nonce ?? `guest-nonce-${randomBytes(16).toString("hex")}`,
    timestampMs: input.timestampMs ?? now,
    expiresAtMs: input.expiresAtMs ?? now + MAX_REQUEST_AGE_MS,
    guestIdentity: input.guestIdentity,
    sandboxProfile: input.sandboxProfile,
    profileDigest: input.profileDigest,
    taskDigest: input.taskDigest,
    processTreePolicy: input.processTreePolicy,
    timeoutMs: input.timeoutMs,
    outputCapBytes: input.outputCapBytes,
    operation: "task_run"
  };
  validateUnsignedVirtualizationGuestRequest(request);
  return { ...request, authenticationProof: requestProof(request, authenticationKey) };
}

export function signVirtualizationGuestRequest(
  request: UnsignedVirtualizationGuestRequest,
  authenticationKey: Buffer
): SignedVirtualizationGuestRequest {
  validateUnsignedVirtualizationGuestRequest(request);
  return { ...request, authenticationProof: requestProof(request, authenticationKey) };
}

export function createVirtualizationGuestStatusRequest(
  input: VirtualizationGuestStatusLookupInput,
  authenticationKey: Buffer,
  options: { now?: number; requestId?: string; nonce?: string } = {}
): SignedVirtualizationGuestStatusRequest {
  const now = options.now ?? Date.now();
  const request: UnsignedVirtualizationGuestStatusRequest = {
    schemaVersion: "0.1",
    protocolVersion: PROTOCOL_VERSION,
    contractVersion: CONTRACT_VERSION,
    kind: "virtualization_guest_task_status",
    requestId: input.requestId ?? options.requestId ?? `request:guest-status-${randomBytes(16).toString("hex")}`,
    nonce: input.nonce ?? options.nonce ?? `guest-status-nonce-${randomBytes(16).toString("hex")}`,
    timestampMs: input.timestampMs ?? now,
    expiresAtMs: input.expiresAtMs ?? now + MAX_REQUEST_AGE_MS,
    guestIdentity: input.guestIdentity,
    originalRequestId: input.originalRequestId,
    originalNonce: input.originalNonce,
    originalRequestDigest: input.originalRequestDigest,
    timeoutMs: input.timeoutMs,
    outputCapBytes: input.outputCapBytes,
    operation: "task_status"
  };
  validateUnsignedVirtualizationGuestStatusRequest(request);
  return { ...request, authenticationProof: statusRequestProof(request, authenticationKey) };
}

export function signVirtualizationGuestStatusRequest(
  request: UnsignedVirtualizationGuestStatusRequest,
  authenticationKey: Buffer
): SignedVirtualizationGuestStatusRequest {
  validateUnsignedVirtualizationGuestStatusRequest(request);
  return { ...request, authenticationProof: statusRequestProof(request, authenticationKey) };
}

export function verifyVirtualizationGuestRequest(
  raw: unknown,
  authenticationKey: Buffer,
  options: VerifyVirtualizationGuestRequestOptions
): UnsignedVirtualizationGuestRequest {
  if (!options?.replayGuard) throw new Error("Virtualization guest request replay guard is required");
  const parsed = parseSignedRequest(raw);
  try {
    validateAuthenticationKey(authenticationKey);
    const expected = requestProof(parsed.request, authenticationKey);
    if (!constantTimeEqualHex(parsed.authenticationProof, expected)) {
      throw new BrokerError("AUTH_INVALID", "Virtualization guest request authentication failed");
    }
    validateRequestFreshness(parsed.request, options.now ?? Date.now(), options.maxRequestAgeMs ?? MAX_REQUEST_AGE_MS, options.allowedClockSkewMs ?? MAX_CLOCK_SKEW_MS);
    if (options.expectedGuestIdentity && !sameGuestIdentity(parsed.request.guestIdentity, options.expectedGuestIdentity)) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest identity does not match the Broker policy");
    }
    if (options.expectedSandboxProfile !== undefined && parsed.request.sandboxProfile !== options.expectedSandboxProfile) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest sandbox profile does not match the Broker policy");
    }
    if (options.expectedProfileDigest !== undefined && parsed.request.profileDigest !== options.expectedProfileDigest) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest profile digest does not match the Broker policy");
    }
    options.replayGuard.admit(parsed.request);
    return parsed.request;
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("AUTH_INVALID", "Virtualization guest request authentication failed");
  }
}

export function verifyVirtualizationGuestStatusRequest(
  raw: unknown,
  authenticationKey: Buffer,
  options: VerifyVirtualizationGuestRequestOptions
): UnsignedVirtualizationGuestStatusRequest {
  if (!options?.replayGuard) throw new Error("Virtualization guest status replay guard is required");
  const parsed = parseSignedStatusRequest(raw);
  try {
    validateAuthenticationKey(authenticationKey);
    const expected = statusRequestProof(parsed.request, authenticationKey);
    if (!constantTimeEqualHex(parsed.authenticationProof, expected)) {
      throw new BrokerError("AUTH_INVALID", "Virtualization guest status authentication failed");
    }
    validateRequestFreshness(parsed.request, options.now ?? Date.now(), options.maxRequestAgeMs ?? MAX_REQUEST_AGE_MS, options.allowedClockSkewMs ?? MAX_CLOCK_SKEW_MS);
    if (options.expectedGuestIdentity && !sameGuestIdentity(parsed.request.guestIdentity, options.expectedGuestIdentity)) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest status identity does not match the Broker policy");
    }
    options.replayGuard.admit(parsed.request);
    return parsed.request;
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("AUTH_INVALID", "Virtualization guest status authentication failed");
  }
}

export function virtualizationGuestRequestDigest(request: UnsignedVirtualizationGuestRequest): string {
  validateUnsignedVirtualizationGuestRequest(request);
  return sha256(canonicalJson(request));
}

export function virtualizationGuestStatusRequestDigest(request: UnsignedVirtualizationGuestStatusRequest): string {
  validateUnsignedVirtualizationGuestStatusRequest(request);
  return sha256(canonicalJson(request));
}

export function signVirtualizationGuestResponse(
  response: UnsignedVirtualizationGuestResponse,
  authenticationKey: Buffer
): SignedVirtualizationGuestResponse {
  validateUnsignedVirtualizationGuestResponse(response);
  return { ...response, responseProof: responseProof(response, authenticationKey) };
}

export function signVirtualizationGuestStatusResponse(
  response: UnsignedVirtualizationGuestStatusResponse,
  authenticationKey: Buffer
): SignedVirtualizationGuestStatusResponse {
  validateUnsignedVirtualizationGuestStatusResponse(response);
  return { ...response, responseProof: statusResponseProof(response, authenticationKey) };
}

export function verifyVirtualizationGuestResponse(
  raw: unknown,
  authenticationKey: Buffer,
  request: UnsignedVirtualizationGuestRequest,
  options: VerifyVirtualizationGuestResponseOptions = {}
): UnsignedVirtualizationGuestResponse {
  validateUnsignedVirtualizationGuestRequest(request);
  const parsed = parseSignedResponse(raw);
  try {
    validateAuthenticationKey(authenticationKey);
    validateUnsignedVirtualizationGuestResponse(parsed.response);
    if (parsed.response.requestDigest !== virtualizationGuestRequestDigest(request) ||
        parsed.response.requestId !== request.requestId ||
        parsed.response.nonce !== request.nonce ||
        !sameGuestIdentity(parsed.response.guestIdentity, request.guestIdentity)) {
      throw new BrokerError("CONFLICT", "Virtualization guest response is not bound to the request");
    }
    if (options.expectedGuestIdentity && !sameGuestIdentity(parsed.response.guestIdentity, options.expectedGuestIdentity)) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest response identity does not match the Broker policy");
    }
    if (options.expectedOutputCapBytes !== undefined &&
        Buffer.byteLength(parsed.response.stdout, "utf8") + Buffer.byteLength(parsed.response.stderr, "utf8") > options.expectedOutputCapBytes) {
      throw new BrokerError("OUTPUT_LIMIT", "Virtualization guest response exceeded the output byte limit");
    }
    const expected = responseProof(parsed.response, authenticationKey);
    if (!constantTimeEqualHex(parsed.responseProof, expected)) {
      throw new BrokerError("AUTH_INVALID", "Virtualization guest response authentication failed");
    }
    return parsed.response;
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("AUTH_INVALID", "Virtualization guest response authentication failed");
  }
}

export function verifyVirtualizationGuestStatusResponse(
  raw: unknown,
  authenticationKey: Buffer,
  request: UnsignedVirtualizationGuestStatusRequest,
  options: VerifyVirtualizationGuestResponseOptions = {}
): UnsignedVirtualizationGuestStatusResponse {
  validateUnsignedVirtualizationGuestStatusRequest(request);
  const parsed = parseSignedStatusResponse(raw);
  try {
    validateAuthenticationKey(authenticationKey);
    validateUnsignedVirtualizationGuestStatusResponse(parsed.response);
    if (parsed.response.statusRequestDigest !== virtualizationGuestStatusRequestDigest(request) ||
        parsed.response.requestId !== request.requestId ||
        parsed.response.nonce !== request.nonce ||
        parsed.response.originalRequestId !== request.originalRequestId ||
        parsed.response.originalNonce !== request.originalNonce ||
        parsed.response.originalRequestDigest !== request.originalRequestDigest ||
        !sameGuestIdentity(parsed.response.guestIdentity, request.guestIdentity)) {
      throw new BrokerError("CONFLICT", "Virtualization guest status response is not bound to the request");
    }
    if (options.expectedGuestIdentity && !sameGuestIdentity(parsed.response.guestIdentity, options.expectedGuestIdentity)) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest status response identity does not match the Broker policy");
    }
    if (options.expectedOutputCapBytes !== undefined &&
        Buffer.byteLength(parsed.response.stdout, "utf8") + Buffer.byteLength(parsed.response.stderr, "utf8") > options.expectedOutputCapBytes) {
      throw new BrokerError("OUTPUT_LIMIT", "Virtualization guest status response exceeded the output byte limit");
    }
    const expected = statusResponseProof(parsed.response, authenticationKey);
    if (!constantTimeEqualHex(parsed.responseProof, expected)) {
      throw new BrokerError("AUTH_INVALID", "Virtualization guest status response authentication failed");
    }
    return parsed.response;
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("AUTH_INVALID", "Virtualization guest status response authentication failed");
  }
}

/**
 * Bounded Broker-owned exchange boundary for a future native guest adapter.
 * Replay admission occurs before the frame leaves the Broker. Once admitted,
 * transport loss is reported as UNKNOWN_OUTCOME because the guest may have
 * started work and the Broker cannot infer a result from a closed channel.
 */
export class VirtualizationGuestTransportClient {
  private readonly authenticationKey: Buffer;
  private readonly replayGuard: VirtualizationGuestReplayGuard;
  private readonly channel: VirtualizationGuestChannel;
  private readonly now: () => number;
  private readonly expectedGuestIdentity: VirtualizationGuestIdentity | undefined;
  private readonly expectedSandboxProfile: string | undefined;
  private readonly expectedProfileDigest: string | undefined;
  private readonly maxResponseBytes: number;
  private readonly cancellationPollMs: number;
  private readonly authorizeStatusLookup: ((input: VirtualizationGuestStatusLookupInput) => void) | undefined;
  private readonly activeExchanges = new Set<{
    controller: AbortController;
    reject: (reason: BrokerError) => void;
  }>();
  private closed = false;

  constructor(options: VirtualizationGuestTransportClientOptions) {
    validateAuthenticationKey(options.authenticationKey);
    if (!options.replayGuard || !options.channel || typeof options.channel.exchange !== "function") {
      throw new Error("Virtualization guest transport requires a replay guard and channel");
    }
    this.authenticationKey = Buffer.from(options.authenticationKey);
    this.replayGuard = options.replayGuard;
    this.channel = options.channel;
    this.now = options.now ?? Date.now;
    this.expectedGuestIdentity = options.expectedGuestIdentity;
    this.expectedSandboxProfile = options.expectedSandboxProfile;
    this.expectedProfileDigest = options.expectedProfileDigest;
    this.maxResponseBytes = options.maxResponseBytes ?? MAX_RESPONSE_BYTES;
    this.cancellationPollMs = options.cancellationPollMs ?? 25;
    this.authorizeStatusLookup = options.authorizeStatusLookup;
    if (!Number.isSafeInteger(this.maxResponseBytes) || this.maxResponseBytes < 256 || this.maxResponseBytes > MAX_RESPONSE_BYTES ||
        !Number.isSafeInteger(this.cancellationPollMs) || this.cancellationPollMs < 10 || this.cancellationPollMs > 1_000) {
      throw new Error("Virtualization guest transport limits are invalid");
    }
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    for (const exchange of this.activeExchanges) {
      exchange.controller.abort();
      exchange.reject(new BrokerError("CANCELLED", "Virtualization guest transport was closed while a request was active"));
    }
    this.activeExchanges.clear();
    this.authenticationKey.fill(0);
  }

  async execute(input: VirtualizationGuestRequestInput, options: VirtualizationGuestExchangeOptions = {}): Promise<UnsignedVirtualizationGuestResponse> {
    if (this.closed) throw new BrokerError("POLICY_DENIED", "Virtualization guest transport is closed");
    const now = this.now();
    const signedRequest = createVirtualizationGuestRequest(input, this.authenticationKey, { now });
    const request = verifyVirtualizationGuestRequest(signedRequest, this.authenticationKey, {
      replayGuard: this.replayGuard,
      now,
      ...(this.expectedGuestIdentity === undefined ? {} : { expectedGuestIdentity: this.expectedGuestIdentity }),
      ...(this.expectedSandboxProfile === undefined ? {} : { expectedSandboxProfile: this.expectedSandboxProfile }),
      ...(this.expectedProfileDigest === undefined ? {} : { expectedProfileDigest: this.expectedProfileDigest })
    });
    try {
      options.onRequestAdmitted?.(request);
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Virtualization guest request admission could not be persisted");
    }
    const frame = Buffer.from(JSON.stringify(signedRequest), "utf8");
    if (frame.byteLength > MAX_REQUEST_BYTES) {
      throw new BrokerError("OUTPUT_LIMIT", "Virtualization guest request exceeded the byte limit");
    }
    const responseFrame = await this.exchangeFrame(frame, request.timeoutMs, options, "task");
    if (this.closed) throw new BrokerError("CANCELLED", "Virtualization guest transport was closed while a request was active");
    let raw: unknown;
    try {
      raw = JSON.parse(decodeUtf8Strict(Buffer.from(responseFrame))) as unknown;
    } catch {
      throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest response frame is not valid JSON");
    }
    return verifyVirtualizationGuestResponse(raw, this.authenticationKey, request, {
      ...(this.expectedGuestIdentity === undefined ? {} : { expectedGuestIdentity: this.expectedGuestIdentity }),
      expectedOutputCapBytes: request.outputCapBytes
    });
  }

  /**
   * Recover a previously admitted task without replaying its execution
   * request. Each lookup has a fresh request ID/nonce but remains bound to the
   * original request identity and digest inside the signed response.
   */
  async lookup(
    input: VirtualizationGuestStatusLookupInput,
    options: VirtualizationGuestExchangeOptions = {}
  ): Promise<UnsignedVirtualizationGuestStatusResponse> {
    if (this.closed) throw new BrokerError("POLICY_DENIED", "Virtualization guest transport is closed");
    const authorizers = [this.authorizeStatusLookup, options.authorizeStatusLookup].filter(
      (value): value is (input: VirtualizationGuestStatusLookupInput) => void => value !== undefined
    );
    if (authorizers.length === 0) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest status lookup authority is unavailable");
    }
    const authorizedInput: VirtualizationGuestStatusLookupInput = {
      ...input,
      guestIdentity: { ...input.guestIdentity }
    };
    try {
      for (const authorizeStatusLookup of authorizers) {
        authorizeStatusLookup({ ...authorizedInput, guestIdentity: { ...authorizedInput.guestIdentity } });
      }
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("POLICY_DENIED", "Virtualization guest status lookup is not authorized");
    }
    const now = this.now();
    const signedRequest = createVirtualizationGuestStatusRequest(authorizedInput, this.authenticationKey, { now });
    const request = verifyVirtualizationGuestStatusRequest(signedRequest, this.authenticationKey, {
      replayGuard: this.replayGuard,
      now,
      ...(this.expectedGuestIdentity === undefined ? {} : { expectedGuestIdentity: this.expectedGuestIdentity })
    });
    const frame = Buffer.from(JSON.stringify(signedRequest), "utf8");
    if (frame.byteLength > MAX_REQUEST_BYTES) {
      throw new BrokerError("OUTPUT_LIMIT", "Virtualization guest status request exceeded the byte limit");
    }
    const responseFrame = await this.exchangeFrame(frame, request.timeoutMs, options, "status");
    if (this.closed) throw new BrokerError("CANCELLED", "Virtualization guest transport was closed while a request was active");
    let raw: unknown;
    try {
      raw = JSON.parse(decodeUtf8Strict(Buffer.from(responseFrame))) as unknown;
    } catch {
      throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest status response frame is not valid JSON");
    }
    return verifyVirtualizationGuestStatusResponse(raw, this.authenticationKey, request, {
      ...(this.expectedGuestIdentity === undefined ? {} : { expectedGuestIdentity: this.expectedGuestIdentity }),
      expectedOutputCapBytes: request.outputCapBytes
    });
  }

  private async exchangeFrame(
    frame: Uint8Array,
    timeoutMs: number,
    options: VirtualizationGuestExchangeOptions,
    operation: "task" | "status"
  ): Promise<Uint8Array> {
    if (this.closed) throw new BrokerError("POLICY_DENIED", "Virtualization guest transport is closed");
    const controller = new AbortController();
    let timeoutExpired = false;
    let cancelled = false;
    let rejectAbort: ((reason: BrokerError) => void) | undefined;
    const abortOutcome = new Promise<Uint8Array>((_resolve, reject) => {
      rejectAbort = reject;
    });
    const activeExchange = { controller, reject: (reason: BrokerError): void => rejectAbort?.(reason) };
    this.activeExchanges.add(activeExchange);
    const timeout = setTimeout(() => {
      timeoutExpired = true;
      controller.abort();
      rejectAbort?.(new BrokerError("TIMEOUT", `Virtualization guest ${operation} request exceeded its execution budget`));
    }, timeoutMs);
    const poller = options.shouldCancel === undefined
      ? undefined
      : setInterval(() => {
        try {
          if (options.shouldCancel?.()) {
            cancelled = true;
            controller.abort();
            rejectAbort?.(new BrokerError("CANCELLED", `Virtualization guest ${operation} request was cancelled under active authority`));
          }
        } catch {
          cancelled = true;
          controller.abort();
          rejectAbort?.(new BrokerError("CANCELLED", `Virtualization guest ${operation} request was cancelled under active authority`));
        }
      }, this.cancellationPollMs);
    try {
      const responseFrame = await Promise.race([
        this.channel.exchange(frame, controller.signal),
        abortOutcome
      ]);
      if (this.closed) throw new BrokerError("CANCELLED", "Virtualization guest transport was closed while a request was active");
      if (timeoutExpired) throw new BrokerError("TIMEOUT", `Virtualization guest ${operation} request exceeded its execution budget`);
      if (cancelled) throw new BrokerError("CANCELLED", `Virtualization guest ${operation} request was cancelled under active authority`);
      if (!Buffer.isBuffer(responseFrame) && !(responseFrame instanceof Uint8Array)) {
        throw new BrokerError("PRECONDITION_FAILED", `Virtualization guest ${operation} response frame is invalid`);
      }
      if (responseFrame.byteLength > this.maxResponseBytes) {
        throw new BrokerError("OUTPUT_LIMIT", `Virtualization guest ${operation} response exceeded the byte limit`);
      }
      return responseFrame;
    } catch (error) {
      if (timeoutExpired) throw new BrokerError("TIMEOUT", `Virtualization guest ${operation} request exceeded its execution budget`);
      if (cancelled) throw new BrokerError("CANCELLED", `Virtualization guest ${operation} request was cancelled under active authority`);
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("UNKNOWN_OUTCOME", `Virtualization guest ${operation} transport outcome could not be established`, true);
    } finally {
      clearTimeout(timeout);
      if (poller !== undefined) clearInterval(poller);
      this.activeExchanges.delete(activeExchange);
    }
  }
}

export function validateUnsignedVirtualizationGuestRequest(request: UnsignedVirtualizationGuestRequest): void {
  assertExactKeys(request, [
    "schemaVersion", "protocolVersion", "contractVersion", "kind", "requestId", "nonce", "timestampMs", "expiresAtMs",
    "guestIdentity", "sandboxProfile", "profileDigest", "taskDigest", "processTreePolicy", "timeoutMs", "outputCapBytes", "operation"
  ], "Virtualization guest request");
  if (request.schemaVersion !== "0.1" || request.protocolVersion !== PROTOCOL_VERSION || request.contractVersion !== CONTRACT_VERSION ||
      request.kind !== "virtualization_guest_task" || request.operation !== "task_run") {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest request version or kind is invalid");
  }
  validateRequestIdentifiers(request);
  validateGuestIdentity(request.guestIdentity);
  if (!PROFILE_PATTERN.test(request.sandboxProfile) || !SHA256_PATTERN.test(request.profileDigest) || !SHA256_PATTERN.test(request.taskDigest)) {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest request profile binding is invalid");
  }
  if (request.processTreePolicy !== "single_process" && request.processTreePolicy !== "owned_group") {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest process policy is invalid");
  }
  if (!Number.isSafeInteger(request.timeoutMs) || request.timeoutMs < 1 || request.timeoutMs > MAX_TIMEOUT_MS ||
      !Number.isSafeInteger(request.outputCapBytes) || request.outputCapBytes < 1 || request.outputCapBytes > MAX_OUTPUT_CAP_BYTES) {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest request limits are invalid");
  }
}

export function validateUnsignedVirtualizationGuestStatusRequest(request: UnsignedVirtualizationGuestStatusRequest): void {
  assertExactKeys(request, [
    "schemaVersion", "protocolVersion", "contractVersion", "kind", "requestId", "nonce", "timestampMs", "expiresAtMs",
    "guestIdentity", "originalRequestId", "originalNonce", "originalRequestDigest", "timeoutMs", "outputCapBytes", "operation"
  ], "Virtualization guest status request");
  if (request.schemaVersion !== "0.1" || request.protocolVersion !== PROTOCOL_VERSION || request.contractVersion !== CONTRACT_VERSION ||
      request.kind !== "virtualization_guest_task_status" || request.operation !== "task_status") {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest status request version or kind is invalid");
  }
  if (!STATUS_REQUEST_ID_PATTERN.test(request.requestId) || !STATUS_NONCE_PATTERN.test(request.nonce) ||
      !Number.isSafeInteger(request.timestampMs) || request.timestampMs < 0 ||
      !Number.isSafeInteger(request.expiresAtMs) || request.expiresAtMs <= request.timestampMs ||
      !REQUEST_ID_PATTERN.test(request.originalRequestId) || !NONCE_PATTERN.test(request.originalNonce) ||
      !SHA256_PATTERN.test(request.originalRequestDigest)) {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest status request identifiers are invalid");
  }
  validateGuestIdentity(request.guestIdentity);
  if (!Number.isSafeInteger(request.timeoutMs) || request.timeoutMs < 1 || request.timeoutMs > MAX_TIMEOUT_MS ||
      !Number.isSafeInteger(request.outputCapBytes) || request.outputCapBytes < 1 || request.outputCapBytes > MAX_OUTPUT_CAP_BYTES) {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest status request limits are invalid");
  }
}

export function validateUnsignedVirtualizationGuestResponse(response: UnsignedVirtualizationGuestResponse): void {
  assertExactKeys(response, [
    "schemaVersion", "protocolVersion", "contractVersion", "kind", "requestId", "nonce", "guestIdentity", "requestDigest",
    "state", "resultClass", "exitCode", "stdout", "stderr", "truncated", "durationMs", "outputPolicy", "verification"
  ], "Virtualization guest response");
  if (response.schemaVersion !== "0.1" || response.protocolVersion !== PROTOCOL_VERSION || response.contractVersion !== CONTRACT_VERSION ||
      response.kind !== "virtualization_guest_task_result") {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest response version or kind is invalid");
  }
  if (!REQUEST_ID_PATTERN.test(response.requestId) || !NONCE_PATTERN.test(response.nonce) || !SHA256_PATTERN.test(response.requestDigest)) {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest response identifiers are invalid");
  }
  validateGuestIdentity(response.guestIdentity);
  if (!["completed", "failed", "cancelled", "timed_out", "unknown"].includes(response.state) ||
      !["SUCCEEDED", "EXECUTION_FAILED", "CANCELLED", "TIMEOUT", "OUTPUT_LIMIT", "VERIFICATION_FAILED", "UNKNOWN_OUTCOME"].includes(response.resultClass)) {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest response result is invalid");
  }
  if (response.exitCode !== null && (!Number.isSafeInteger(response.exitCode) || response.exitCode < -1 || response.exitCode > 255)) {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest response exit code is invalid");
  }
  if (typeof response.stdout !== "string" || typeof response.stderr !== "string" ||
      Buffer.byteLength(response.stdout, "utf8") > MAX_OUTPUT_CAP_BYTES || Buffer.byteLength(response.stderr, "utf8") > MAX_OUTPUT_CAP_BYTES ||
      Buffer.byteLength(response.stdout, "utf8") + Buffer.byteLength(response.stderr, "utf8") > MAX_OUTPUT_CAP_BYTES ||
      typeof response.truncated !== "boolean" || !Number.isSafeInteger(response.durationMs) || response.durationMs < 0 || response.durationMs > MAX_TIMEOUT_MS * 2 ||
      response.outputPolicy !== "broker-redacted-v1") {
    throw new BrokerError("OUTPUT_LIMIT", "Virtualization guest response output is invalid or exceeds the byte limit");
  }
  assertAllowedKeys(response.verification, ["status", "summary"], "Virtualization guest response verification");
  if (!["verified", "failed", "unknown", "not_run"].includes(response.verification.status) ||
      (response.verification.summary !== undefined && (typeof response.verification.summary !== "string" || Buffer.byteLength(response.verification.summary, "utf8") > MAX_SUMMARY_BYTES))) {
    throw new BrokerError("VERIFICATION_FAILED", "Virtualization guest response verification is invalid");
  }
}

export function validateUnsignedVirtualizationGuestStatusResponse(response: UnsignedVirtualizationGuestStatusResponse): void {
  assertExactKeys(response, [
    "schemaVersion", "protocolVersion", "contractVersion", "kind", "requestId", "nonce", "guestIdentity",
    "originalRequestId", "originalNonce", "originalRequestDigest", "statusRequestDigest", "state", "resultClass",
    "exitCode", "stdout", "stderr", "truncated", "durationMs", "outputPolicy", "verification"
  ], "Virtualization guest status response");
  if (response.schemaVersion !== "0.1" || response.protocolVersion !== PROTOCOL_VERSION || response.contractVersion !== CONTRACT_VERSION ||
      response.kind !== "virtualization_guest_task_status_result") {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest status response version or kind is invalid");
  }
  if (!STATUS_REQUEST_ID_PATTERN.test(response.requestId) || !STATUS_NONCE_PATTERN.test(response.nonce) ||
      !REQUEST_ID_PATTERN.test(response.originalRequestId) || !NONCE_PATTERN.test(response.originalNonce) ||
      !SHA256_PATTERN.test(response.originalRequestDigest) || !SHA256_PATTERN.test(response.statusRequestDigest)) {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest status response identifiers are invalid");
  }
  validateGuestIdentity(response.guestIdentity);
  if (![
    "completed", "failed", "cancelled", "timed_out", "unknown"
  ].includes(response.state) || ![
    "SUCCEEDED", "EXECUTION_FAILED", "CANCELLED", "TIMEOUT", "OUTPUT_LIMIT", "VERIFICATION_FAILED", "UNKNOWN_OUTCOME"
  ].includes(response.resultClass)) {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest status response result is invalid");
  }
  if (response.exitCode !== null && (!Number.isSafeInteger(response.exitCode) || response.exitCode < -1 || response.exitCode > 255)) {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest status response exit code is invalid");
  }
  if (typeof response.stdout !== "string" || typeof response.stderr !== "string" ||
      Buffer.byteLength(response.stdout, "utf8") > MAX_OUTPUT_CAP_BYTES || Buffer.byteLength(response.stderr, "utf8") > MAX_OUTPUT_CAP_BYTES ||
      Buffer.byteLength(response.stdout, "utf8") + Buffer.byteLength(response.stderr, "utf8") > MAX_OUTPUT_CAP_BYTES ||
      typeof response.truncated !== "boolean" || !Number.isSafeInteger(response.durationMs) || response.durationMs < 0 ||
      response.durationMs > MAX_TIMEOUT_MS * 2 || response.outputPolicy !== "broker-redacted-v1") {
    throw new BrokerError("OUTPUT_LIMIT", "Virtualization guest status response output is invalid or exceeds the byte limit");
  }
  assertAllowedKeys(response.verification, ["status", "summary"], "Virtualization guest status response verification");
  if (!["verified", "failed", "unknown", "not_run"].includes(response.verification.status) ||
      (response.verification.summary !== undefined &&
       (typeof response.verification.summary !== "string" || Buffer.byteLength(response.verification.summary, "utf8") > MAX_SUMMARY_BYTES))) {
    throw new BrokerError("VERIFICATION_FAILED", "Virtualization guest status response verification is invalid");
  }
}

function parseSignedRequest(raw: unknown): { request: UnsignedVirtualizationGuestRequest; authenticationProof: string } {
  if (!isRecord(raw)) throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest request envelope is invalid");
  assertExactKeys(raw, [
    "schemaVersion", "protocolVersion", "contractVersion", "kind", "requestId", "nonce", "timestampMs", "expiresAtMs",
    "guestIdentity", "sandboxProfile", "profileDigest", "taskDigest", "processTreePolicy", "timeoutMs", "outputCapBytes", "operation", "authenticationProof"
  ], "Virtualization guest request envelope");
  if (typeof raw.authenticationProof !== "string" || !SHA256_PATTERN.test(raw.authenticationProof)) {
    throw new BrokerError("AUTH_INVALID", "Virtualization guest request authentication proof is invalid");
  }
  const request = { ...raw } as unknown as UnsignedVirtualizationGuestRequest;
  delete (request as unknown as Record<string, unknown>).authenticationProof;
  validateUnsignedVirtualizationGuestRequest(request);
  return { request, authenticationProof: raw.authenticationProof };
}

function parseSignedResponse(raw: unknown): { response: UnsignedVirtualizationGuestResponse; responseProof: string } {
  if (!isRecord(raw)) throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest response envelope is invalid");
  assertExactKeys(raw, [
    "schemaVersion", "protocolVersion", "contractVersion", "kind", "requestId", "nonce", "guestIdentity", "requestDigest",
    "state", "resultClass", "exitCode", "stdout", "stderr", "truncated", "durationMs", "outputPolicy", "verification", "responseProof"
  ], "Virtualization guest response envelope");
  if (typeof raw.responseProof !== "string" || !SHA256_PATTERN.test(raw.responseProof)) {
    throw new BrokerError("AUTH_INVALID", "Virtualization guest response authentication proof is invalid");
  }
  const response = { ...raw } as unknown as UnsignedVirtualizationGuestResponse;
  delete (response as unknown as Record<string, unknown>).responseProof;
  return { response, responseProof: raw.responseProof };
}

function parseSignedStatusRequest(raw: unknown): { request: UnsignedVirtualizationGuestStatusRequest; authenticationProof: string } {
  if (!isRecord(raw)) throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest status request envelope is invalid");
  assertExactKeys(raw, [
    "schemaVersion", "protocolVersion", "contractVersion", "kind", "requestId", "nonce", "timestampMs", "expiresAtMs",
    "guestIdentity", "originalRequestId", "originalNonce", "originalRequestDigest", "timeoutMs", "outputCapBytes", "operation", "authenticationProof"
  ], "Virtualization guest status request envelope");
  if (typeof raw.authenticationProof !== "string" || !SHA256_PATTERN.test(raw.authenticationProof)) {
    throw new BrokerError("AUTH_INVALID", "Virtualization guest status authentication proof is invalid");
  }
  const request = { ...raw } as unknown as UnsignedVirtualizationGuestStatusRequest;
  delete (request as unknown as Record<string, unknown>).authenticationProof;
  validateUnsignedVirtualizationGuestStatusRequest(request);
  return { request, authenticationProof: raw.authenticationProof };
}

function parseSignedStatusResponse(raw: unknown): { response: UnsignedVirtualizationGuestStatusResponse; responseProof: string } {
  if (!isRecord(raw)) throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest status response envelope is invalid");
  assertExactKeys(raw, [
    "schemaVersion", "protocolVersion", "contractVersion", "kind", "requestId", "nonce", "guestIdentity",
    "originalRequestId", "originalNonce", "originalRequestDigest", "statusRequestDigest", "state", "resultClass",
    "exitCode", "stdout", "stderr", "truncated", "durationMs", "outputPolicy", "verification", "responseProof"
  ], "Virtualization guest status response envelope");
  if (typeof raw.responseProof !== "string" || !SHA256_PATTERN.test(raw.responseProof)) {
    throw new BrokerError("AUTH_INVALID", "Virtualization guest status response authentication proof is invalid");
  }
  const response = { ...raw } as unknown as UnsignedVirtualizationGuestStatusResponse;
  delete (response as unknown as Record<string, unknown>).responseProof;
  return { response, responseProof: raw.responseProof };
}

function requestProof(request: UnsignedVirtualizationGuestRequest, key: Buffer): string {
  validateAuthenticationKey(key);
  return createHmac("sha256", key).update(REQUEST_DOMAIN, "utf8").update(sha256(canonicalJson(request)), "utf8").digest("hex");
}

function statusRequestProof(request: UnsignedVirtualizationGuestStatusRequest, key: Buffer): string {
  validateAuthenticationKey(key);
  return createHmac("sha256", key).update(STATUS_REQUEST_DOMAIN, "utf8").update(sha256(canonicalJson(request)), "utf8").digest("hex");
}

function responseProof(response: UnsignedVirtualizationGuestResponse, key: Buffer): string {
  validateAuthenticationKey(key);
  return createHmac("sha256", key).update(RESPONSE_DOMAIN, "utf8").update(response.requestDigest, "utf8").update(canonicalJson(response), "utf8").digest("hex");
}

function statusResponseProof(response: UnsignedVirtualizationGuestStatusResponse, key: Buffer): string {
  validateAuthenticationKey(key);
  return createHmac("sha256", key).update(STATUS_RESPONSE_DOMAIN, "utf8").update(response.statusRequestDigest, "utf8").update(canonicalJson(response), "utf8").digest("hex");
}

function validateRequestFreshness(
  request: Pick<UnsignedVirtualizationGuestRequest, "timestampMs" | "expiresAtMs">,
  now: number,
  maxRequestAgeMs: number,
  allowedClockSkewMs: number
): void {
  if (!Number.isSafeInteger(now) || !Number.isSafeInteger(maxRequestAgeMs) || maxRequestAgeMs < 1 || maxRequestAgeMs > MAX_REQUEST_AGE_MS ||
      !Number.isSafeInteger(allowedClockSkewMs) || allowedClockSkewMs < 0 || allowedClockSkewMs > MAX_CLOCK_SKEW_MS) {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest request freshness limits are invalid");
  }
  if (request.timestampMs > now + allowedClockSkewMs || request.expiresAtMs <= now - allowedClockSkewMs ||
      request.expiresAtMs <= request.timestampMs || request.expiresAtMs > request.timestampMs + maxRequestAgeMs + allowedClockSkewMs) {
    throw new BrokerError("AUTH_EXPIRED", "Virtualization guest request is expired or outside the accepted clock window");
  }
}

function validateRequestIdentifiers(request: Pick<UnsignedVirtualizationGuestRequest, "requestId" | "nonce" | "timestampMs" | "expiresAtMs">): void {
  if (!REQUEST_ID_PATTERN.test(request.requestId) || !NONCE_PATTERN.test(request.nonce) ||
      !Number.isSafeInteger(request.timestampMs) || request.timestampMs < 0 || !Number.isSafeInteger(request.expiresAtMs) || request.expiresAtMs <= request.timestampMs) {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest request identifiers are invalid");
  }
}

function validateGuestIdentity(identity: VirtualizationGuestIdentity): void {
  assertExactKeys(identity, ["imageSha256", "runtimeVersion"], "Virtualization guest identity");
  if (!SHA256_PATTERN.test(identity.imageSha256) || !RUNTIME_VERSION_PATTERN.test(identity.runtimeVersion)) {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest identity is invalid");
  }
}

function sameGuestIdentity(left: VirtualizationGuestIdentity, right: VirtualizationGuestIdentity): boolean {
  return left.imageSha256 === right.imageSha256 && left.runtimeVersion === right.runtimeVersion;
}

function validateAuthenticationKey(key: Buffer): void {
  if (!Buffer.isBuffer(key) || key.byteLength < 32) throw new BrokerError("AUTH_INVALID", "Virtualization guest authentication key is invalid");
}

function constantTimeEqualHex(left: string, right: string): boolean {
  if (!SHA256_PATTERN.test(left) || !SHA256_PATTERN.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function assertExactKeys(value: unknown, allowed: readonly string[], label: string): void {
  if (!isRecord(value)) throw new BrokerError("PRECONDITION_FAILED", `${label} is invalid`);
  const keys = Object.keys(value).sort();
  const expected = [...allowed].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new BrokerError("PRECONDITION_FAILED", `${label} contains unsupported fields`);
  }
}

function assertAllowedKeys(value: unknown, allowed: readonly string[], label: string): void {
  if (!isRecord(value)) throw new BrokerError("PRECONDITION_FAILED", `${label} is invalid`);
  const allowedSet = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedSet.has(key))) {
    throw new BrokerError("PRECONDITION_FAILED", `${label} contains unsupported fields`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
