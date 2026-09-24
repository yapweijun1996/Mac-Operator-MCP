import { createConnection, type Socket } from "node:net";
import { BrokerError, canonicalJson, parseJsonUtf8Strict, sha256 } from "@mac-operator/contracts";
import { assertContentDoesNotContainSecrets } from "./secret-policy.js";
import { isPlainDataRecord } from "./plain-record.js";
import { parseTaskNetworkDestination } from "./task-profile.js";

const NETWORK_PROXY_SCHEMA_VERSION = "0.1" as const;
const POLICY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const REQUEST_ID_PATTERN = /^(?:network-request|child-network):[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/u;
const MAX_DESTINATIONS = 32;
const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_TIMEOUT_MS = 60_000;
const NETWORK_CHANNEL_SCHEMA_VERSION = "0.1" as const;
const NETWORK_CHANNEL_MAX_FRAME_BYTES = 512 * 1024;
const NETWORK_CHANNEL_MAX_REQUESTS = 32;
const NETWORK_CHANNEL_TOKEN_PATTERN = /^[a-f0-9]{64}$/u;
const NETWORK_CHANNEL_REQUEST_ID_PATTERN = /^child-network:[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/u;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;

export interface BrokerNetworkProxyPolicyInput {
  policyId: string;
  destinations: readonly string[];
  maxRequestBytes?: number;
  maxResponseBytes?: number;
  timeoutMs?: number;
}

export interface BrokerNetworkProxyPolicy {
  schemaVersion: typeof NETWORK_PROXY_SCHEMA_VERSION;
  policyId: string;
  destinations: readonly string[];
  maxRequestBytes: number;
  maxResponseBytes: number;
  timeoutMs: number;
  digest: string;
}

export interface BrokerNetworkProxyOptions {
  enabled?: boolean;
  policy: BrokerNetworkProxyPolicy;
}

export interface BrokerNetworkProxyExchangeRequest {
  requestId: string;
  target: string;
  payload: Buffer;
}

export interface BrokerNetworkProxyExchangeControl {
  shouldCancel?: () => boolean;
}

export interface BrokerNetworkProxyExchangeResult {
  requestId: string;
  target: string;
  response: Buffer;
  requestBytes: number;
  responseBytes: number;
  responseSha256: string;
  durationMs: number;
}

export interface BrokerNetworkProxyChannelOptions {
  socket: Socket;
  proxy: BrokerNetworkProxy;
  capabilityToken: string;
  shouldCancel?: () => boolean;
  maxRequests?: number;
}

/**
 * Build the only policy shape accepted by the Broker-owned network proxy.
 * Destinations are normalized to loopback TCP endpoints and the digest binds
 * every limit, so a caller cannot widen the policy by changing a target.
 */
export function createBrokerNetworkProxyPolicy(input: BrokerNetworkProxyPolicyInput): BrokerNetworkProxyPolicy {
  if (input === null || typeof input !== "object" || Array.isArray(input) ||
      typeof input.policyId !== "string" || !POLICY_ID_PATTERN.test(input.policyId) ||
      !Array.isArray(input.destinations) || input.destinations.length < 1 || input.destinations.length > MAX_DESTINATIONS) {
    throw new BrokerError("POLICY_DENIED", "Network proxy policy is malformed");
  }
  const destinations = [...new Set(input.destinations.map(normalizeDestination))].sort();
  if (destinations.length !== input.destinations.length) {
    throw new BrokerError("POLICY_DENIED", "Network proxy policy contains duplicate destinations");
  }
  const maxRequestBytes = input.maxRequestBytes ?? 8 * 1024;
  const maxResponseBytes = input.maxResponseBytes ?? 64 * 1024;
  const timeoutMs = input.timeoutMs ?? 5_000;
  if (!Number.isSafeInteger(maxRequestBytes) || maxRequestBytes < 1 || maxRequestBytes > MAX_REQUEST_BYTES ||
      !Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1 || maxResponseBytes > MAX_RESPONSE_BYTES ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 25 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new BrokerError("POLICY_DENIED", "Network proxy policy limits are invalid");
  }
  const unsigned = {
    schemaVersion: NETWORK_PROXY_SCHEMA_VERSION,
    policyId: input.policyId,
    destinations,
    maxRequestBytes,
    maxResponseBytes,
    timeoutMs
  } as const;
  return Object.freeze({ ...unsigned, digest: sha256(canonicalJson(unsigned)) });
}

/**
 * Disabled-by-default Broker-owned loopback proxy candidate. It never accepts
 * a remote hostname, DNS result, caller-supplied policy, or raw credential
 * payload, and it is not exported as an MCP tool.
 */
export class BrokerNetworkProxy {
  readonly available: boolean;
  readonly policy: BrokerNetworkProxyPolicy;
  private readonly consumedRequestIds = new Set<string>();

  constructor(options: BrokerNetworkProxyOptions) {
    validatePolicy(options?.policy);
    this.policy = options.policy;
    this.available = options.enabled === true;
  }

  async exchange(
    request: BrokerNetworkProxyExchangeRequest,
    control: BrokerNetworkProxyExchangeControl = {}
  ): Promise<BrokerNetworkProxyExchangeResult> {
    if (!this.available) throw new BrokerError("POLICY_DENIED", "Network proxy is disabled");
    if (request === null || typeof request !== "object" || Array.isArray(request) ||
        typeof request.requestId !== "string" || !REQUEST_ID_PATTERN.test(request.requestId) ||
        typeof request.target !== "string" || !Buffer.isBuffer(request.payload)) {
      throw new BrokerError("PRECONDITION_FAILED", "Network proxy request is malformed");
    }
    if (this.consumedRequestIds.has(request.requestId)) {
      throw new BrokerError("REPLAY_DENIED", "Network proxy request was already consumed");
    }
    this.consumedRequestIds.add(request.requestId);
    if (this.consumedRequestIds.size > NETWORK_CHANNEL_MAX_REQUESTS * 2) {
      const oldest = this.consumedRequestIds.values().next().value;
      if (typeof oldest === "string") this.consumedRequestIds.delete(oldest);
    }
    const target = normalizeDestination(request.target);
    if (!this.policy.destinations.includes(target)) {
      throw new BrokerError("NETWORK_DENIED", "Network proxy target is not allowlisted");
    }
    if (request.payload.byteLength > this.policy.maxRequestBytes) {
      throw new BrokerError("OUTPUT_LIMIT", "Network proxy request exceeds its byte budget");
    }
    if (control.shouldCancel?.() === true) {
      throw new BrokerError("CANCELLED", "Network proxy exchange was cancelled");
    }
    assertContentDoesNotContainSecrets(request.payload);
    const started = Date.now();
    const response = await connectAndExchange(target, request.payload, this.policy, control);
    assertContentDoesNotContainSecrets(response);
    return {
      requestId: request.requestId,
      target,
      response,
      requestBytes: request.payload.byteLength,
      responseBytes: response.byteLength,
      responseSha256: sha256(response),
      durationMs: Math.max(0, Date.now() - started)
    };
  }
}

/**
 * Broker endpoint for a single App Sandbox task's inherited network FD.
 * The child receives only a capability token and this framed channel; every
 * actual socket still originates in the Broker-owned proxy above.
 */
export class BrokerNetworkProxyChannel {
  private readonly socket: Socket;
  private readonly proxy: BrokerNetworkProxy;
  private readonly capabilityToken: string;
  private readonly shouldCancel: () => boolean;
  private readonly maxRequests: number;
  private pending = Buffer.alloc(0);
  private processing = Promise.resolve();
  private requestCount = 0;
  private started = false;
  private closed = false;

  constructor(options: BrokerNetworkProxyChannelOptions) {
    if (options === null || typeof options !== "object" ||
        !(options.socket instanceof Object) || !(options.proxy instanceof BrokerNetworkProxy) ||
        typeof options.capabilityToken !== "string" || !NETWORK_CHANNEL_TOKEN_PATTERN.test(options.capabilityToken) ||
        (options.shouldCancel !== undefined && typeof options.shouldCancel !== "function") ||
        (options.maxRequests !== undefined &&
          (!Number.isSafeInteger(options.maxRequests) || options.maxRequests < 1 || options.maxRequests > NETWORK_CHANNEL_MAX_REQUESTS))) {
      throw new BrokerError("POLICY_DENIED", "Network proxy channel options are invalid");
    }
    this.socket = options.socket;
    this.proxy = options.proxy;
    this.capabilityToken = options.capabilityToken;
    this.shouldCancel = options.shouldCancel ?? (() => false);
    this.maxRequests = options.maxRequests ?? NETWORK_CHANNEL_MAX_REQUESTS;
  }

  start(): void {
    if (this.started || this.closed) throw new BrokerError("CONFLICT", "Network proxy channel is not reusable");
    this.started = true;
    this.socket.setNoDelay(true);
    this.socket.on("data", (chunk: Buffer) => this.receive(chunk));
    this.socket.once("error", () => this.close());
    this.socket.once("close", () => { this.closed = true; });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.socket.destroy();
  }

  private receive(chunk: Buffer): void {
    if (this.closed) return;
    if (!Buffer.isBuffer(chunk) || chunk.byteLength > NETWORK_CHANNEL_MAX_FRAME_BYTES ||
        this.pending.byteLength + chunk.byteLength > NETWORK_CHANNEL_MAX_FRAME_BYTES) {
      this.close();
      return;
    }
    this.pending = Buffer.concat([this.pending, chunk]);
    for (;;) {
      const newline = this.pending.indexOf(0x0a);
      if (newline < 0) return;
      const frame = this.pending.subarray(0, newline);
      this.pending = this.pending.subarray(newline + 1);
      if (frame.byteLength === 0 || frame.byteLength > NETWORK_CHANNEL_MAX_FRAME_BYTES) {
        this.close();
        return;
      }
      const current = Buffer.from(frame);
      this.processing = this.processing.then(() => this.process(current)).catch(() => this.close());
    }
  }

  private async process(frame: Buffer): Promise<void> {
    if (this.closed) return;
    const parsed = parseNetworkChannelRequest(frame);
    if (parsed.capabilityToken !== this.capabilityToken) {
      await this.sendError(parsed.requestId, parsed.target, new BrokerError("AUTH_INVALID", "Network proxy channel authentication failed"));
      this.close();
      return;
    }
    if (this.requestCount >= this.maxRequests) {
      await this.sendError(parsed.requestId, parsed.target, new BrokerError("OUTPUT_LIMIT", "Network proxy channel request budget is exhausted"));
      this.close();
      return;
    }
    this.requestCount += 1;
    if (this.shouldCancel()) {
      await this.sendError(parsed.requestId, parsed.target, new BrokerError("CANCELLED", "Network proxy channel was cancelled"));
      this.close();
      return;
    }
    try {
      const result = await this.proxy.exchange({
        requestId: parsed.requestId,
        target: parsed.target,
        payload: parsed.payload
      }, { shouldCancel: this.shouldCancel });
      await this.send({
        schemaVersion: NETWORK_CHANNEL_SCHEMA_VERSION,
        kind: "network_response",
        ok: true,
        requestId: result.requestId,
        target: result.target,
        responseBase64: result.response.toString("base64"),
        responseBytes: result.responseBytes,
        responseSha256: result.responseSha256
      });
    } catch (error) {
      const brokerError = error instanceof BrokerError
        ? error
        : new BrokerError("EXECUTION_FAILED", "Network proxy exchange failed");
      await this.sendError(parsed.requestId, parsed.target, brokerError);
      if (brokerError.errorClass === "CANCELLED" || brokerError.errorClass === "UNKNOWN_OUTCOME") this.close();
    }
  }

  private async sendError(requestId: string, target: string, error: BrokerError): Promise<void> {
    await this.send({
      schemaVersion: NETWORK_CHANNEL_SCHEMA_VERSION,
      kind: "network_response",
      ok: false,
      requestId,
      target,
      errorClass: error.errorClass,
      message: error.message.slice(0, 256),
      retryable: error.retryable
    });
  }

  private async send(value: Record<string, unknown>): Promise<void> {
    if (this.closed) return;
    const frame = Buffer.from(`${canonicalJson(value)}\n`, "utf8");
    if (frame.byteLength > NETWORK_CHANNEL_MAX_FRAME_BYTES) {
      this.close();
      return;
    }
    await new Promise<void>((resolve, reject) => {
      this.socket.write(frame, (error?: Error | null) => error === undefined || error === null ? resolve() : reject(error));
    });
  }
}

interface ParsedNetworkChannelRequest {
  requestId: string;
  capabilityToken: string;
  target: string;
  payload: Buffer;
}

function parseNetworkChannelRequest(frame: Buffer): ParsedNetworkChannelRequest {
  let raw: unknown;
  try {
    raw = parseJsonUtf8Strict(frame);
  } catch {
    throw new BrokerError("AUTH_INVALID", "Network proxy channel frame is not strict JSON");
  }
  if (!isPlainDataRecord(raw) || Object.keys(raw).sort().join(",") !==
      "capabilityToken,kind,payloadBase64,requestId,schemaVersion,target" ||
      raw.schemaVersion !== NETWORK_CHANNEL_SCHEMA_VERSION || raw.kind !== "network_request" ||
      typeof raw.requestId !== "string" || !NETWORK_CHANNEL_REQUEST_ID_PATTERN.test(raw.requestId) ||
      typeof raw.capabilityToken !== "string" || !NETWORK_CHANNEL_TOKEN_PATTERN.test(raw.capabilityToken) ||
      typeof raw.target !== "string" || typeof raw.payloadBase64 !== "string") {
    throw new BrokerError("AUTH_INVALID", "Network proxy channel request is malformed");
  }
  const payload = decodeBase64(raw.payloadBase64);
  if (payload.byteLength > MAX_REQUEST_BYTES) {
    throw new BrokerError("OUTPUT_LIMIT", "Network proxy channel request exceeds the byte budget");
  }
  return {
    requestId: raw.requestId,
    capabilityToken: raw.capabilityToken,
    target: raw.target,
    payload
  };
}

function decodeBase64(value: string): Buffer {
  if (value.length > Math.ceil(MAX_REQUEST_BYTES / 3) * 4 || !BASE64_PATTERN.test(value)) {
    throw new BrokerError("PRECONDITION_FAILED", "Network proxy channel payload encoding is invalid");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) {
    throw new BrokerError("PRECONDITION_FAILED", "Network proxy channel payload encoding is non-canonical");
  }
  return decoded;
}

function normalizeDestination(value: unknown): string {
  const parsed = parseTaskNetworkDestination(value);
  if (parsed === null || parsed.protocol !== "tcp" || parsed.address !== "localhost") {
    throw new BrokerError("NETWORK_DENIED", "Network proxy supports only loopback TCP destinations");
  }
  return `tcp://localhost:${parsed.port}`;
}

function validatePolicy(policy: unknown): asserts policy is BrokerNetworkProxyPolicy {
  if (policy === null || typeof policy !== "object" || Array.isArray(policy)) {
    throw new BrokerError("POLICY_DENIED", "Network proxy policy is malformed");
  }
  const value = policy as Partial<BrokerNetworkProxyPolicy>;
  if (value.schemaVersion !== NETWORK_PROXY_SCHEMA_VERSION ||
      typeof value.policyId !== "string" || !POLICY_ID_PATTERN.test(value.policyId) ||
      !Array.isArray(value.destinations) || value.destinations.length < 1 || value.destinations.length > MAX_DESTINATIONS ||
      value.destinations.some((destination) => typeof destination !== "string") ||
      !Number.isSafeInteger(value.maxRequestBytes) || (value.maxRequestBytes as number) < 1 || (value.maxRequestBytes as number) > MAX_REQUEST_BYTES ||
      !Number.isSafeInteger(value.maxResponseBytes) || (value.maxResponseBytes as number) < 1 || (value.maxResponseBytes as number) > MAX_RESPONSE_BYTES ||
      !Number.isSafeInteger(value.timeoutMs) || (value.timeoutMs as number) < 25 || (value.timeoutMs as number) > MAX_TIMEOUT_MS ||
      typeof value.digest !== "string" || !/^[a-f0-9]{64}$/u.test(value.digest)) {
    throw new BrokerError("POLICY_DENIED", "Network proxy policy is malformed");
  }
  const rebuilt = createBrokerNetworkProxyPolicy({
    policyId: value.policyId as string,
    destinations: value.destinations as readonly string[],
    maxRequestBytes: value.maxRequestBytes as number,
    maxResponseBytes: value.maxResponseBytes as number,
    timeoutMs: value.timeoutMs as number
  });
  if (rebuilt.digest !== value.digest) throw new BrokerError("POLICY_DENIED", "Network proxy policy digest is invalid");
}

async function connectAndExchange(
  target: string,
  payload: Buffer,
  policy: BrokerNetworkProxyPolicy,
  control: BrokerNetworkProxyExchangeControl
): Promise<Buffer> {
  const parsed = parseTaskNetworkDestination(target);
  if (parsed === null) throw new BrokerError("NETWORK_DENIED", "Network proxy target is malformed");
  return await new Promise<Buffer>((resolve, reject) => {
    let socket: Socket | undefined;
    let settled = false;
    let response = Buffer.alloc(0);
    const timeout = setTimeout(() => finish(new BrokerError("TIMEOUT", "Network proxy exchange timed out", true)), policy.timeoutMs);
    const cancellation = setInterval(() => {
      if (control.shouldCancel?.() === true) finish(new BrokerError("CANCELLED", "Network proxy exchange was cancelled"));
    }, 25);
    const finish = (error: BrokerError | undefined): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      clearInterval(cancellation);
      socket?.destroy();
      if (error === undefined) resolve(response);
      else reject(error);
    };
    socket = createConnection({ host: "127.0.0.1", port: parsed.port });
    socket.setNoDelay(true);
    socket.setTimeout(policy.timeoutMs, () => finish(new BrokerError("TIMEOUT", "Network proxy exchange timed out", true)));
    socket.once("connect", () => socket?.end(payload));
    socket.on("data", (chunk: Buffer) => {
      if (response.byteLength + chunk.byteLength > policy.maxResponseBytes) {
        finish(new BrokerError("OUTPUT_LIMIT", "Network proxy response exceeds its byte budget"));
        return;
      }
      response = Buffer.concat([response, chunk]);
    });
    socket.once("end", () => finish(undefined));
    socket.once("error", (error: NodeJS.ErrnoException) => {
      if (error.code === "ETIMEDOUT") finish(new BrokerError("TIMEOUT", "Network proxy connection timed out", true));
      else finish(new BrokerError("EXECUTION_FAILED", "Network proxy connection failed"));
    });
  });
}
