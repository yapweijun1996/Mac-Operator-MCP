import { BrokerError, canonicalJson, parseJsonUtf8Strict } from "@mac-operator/contracts";
import {
  signVirtualizationGuestResponse,
  signVirtualizationGuestStatusResponse,
  validateUnsignedVirtualizationGuestResponse,
  validateUnsignedVirtualizationGuestStatusResponse,
  verifyVirtualizationGuestRequest,
  verifyVirtualizationGuestStatusRequest,
  virtualizationGuestRequestDigest,
  virtualizationGuestStatusRequestDigest,
  type SignedVirtualizationGuestResponse,
  type SignedVirtualizationGuestStatusResponse,
  type UnsignedVirtualizationGuestRequest,
  type UnsignedVirtualizationGuestResponse,
  type UnsignedVirtualizationGuestStatusRequest,
  type UnsignedVirtualizationGuestStatusResponse,
  type VirtualizationGuestReplayGuard
} from "./virtualization-guest-transport.js";
import {
  parseVirtualizationGuestIdentity,
  sameVirtualizationGuestIdentity,
  type VirtualizationGuestIdentity
} from "./virtualization-guest-attestation.js";
import {
  VirtualizationGuestProfileExecutor,
  VirtualizationGuestTaskProfileRegistry,
  type VirtualizationGuestProcessAdapter,
  type VirtualizationGuestTaskProfile
} from "./virtualization-guest-executor.js";

const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024 + 64 * 1024;

export interface VirtualizationGuestAgentOptions {
  /** Guest-only secret; the host Broker must never load or persist this key. */
  authenticationKey: Buffer;
  replayGuard: VirtualizationGuestReplayGuard;
  expectedGuestIdentity: VirtualizationGuestIdentity;
  expectedSandboxProfile: string;
  expectedProfileDigest: string;
  execute(request: UnsignedVirtualizationGuestRequest, signal?: AbortSignal): Promise<UnsignedVirtualizationGuestResponse>;
  lookup?(request: UnsignedVirtualizationGuestStatusRequest, signal?: AbortSignal): Promise<UnsignedVirtualizationGuestStatusResponse>;
  now?: () => number;
  maxRequestBytes?: number;
  maxResponseBytes?: number;
}

/** Startup-owned composition for the concrete profile-bound guest service. */
export interface VirtualizationGuestProfileAgentOptions extends Omit<VirtualizationGuestAgentOptions, "execute" | "lookup"> {
  profiles: readonly VirtualizationGuestTaskProfile[];
  processAdapter: VirtualizationGuestProcessAdapter;
  maxConcurrent?: number;
}

/**
 * Creates the guest protocol service with a digest-bound manifest registry and
 * a bounded execution adapter. The returned executor must be closed by the
 * guest process after the bootstrap source has drained its active streams.
 */
export function createVirtualizationGuestProfileAgent(options: VirtualizationGuestProfileAgentOptions): {
  agent: VirtualizationGuestAgent;
  executor: VirtualizationGuestProfileExecutor;
} {
  const registry = new VirtualizationGuestTaskProfileRegistry(options.profiles);
  const executor = new VirtualizationGuestProfileExecutor(registry, options.processAdapter, {
    ...(options.maxConcurrent === undefined ? {} : { maxConcurrent: options.maxConcurrent })
  });
  const agent = new VirtualizationGuestAgent({
    authenticationKey: options.authenticationKey,
    replayGuard: options.replayGuard,
    expectedGuestIdentity: options.expectedGuestIdentity,
    expectedSandboxProfile: options.expectedSandboxProfile,
    expectedProfileDigest: options.expectedProfileDigest,
    execute: (request, signal) => executor.execute(request, signal),
    lookup: (request) => executor.lookup(request),
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.maxRequestBytes === undefined ? {} : { maxRequestBytes: options.maxRequestBytes }),
    ...(options.maxResponseBytes === undefined ? {} : { maxResponseBytes: options.maxResponseBytes })
  });
  return { agent, executor };
}

/**
 * Guest-side protocol service for a future Virtualization.framework adapter.
 * It owns request verification, replay admission, response binding, and key
 * disposal, while the VM/channel implementation remains outside this module.
 * No host path, executable, credential, or arbitrary command crosses this
 * boundary: the executor receives only the validated digest-bound envelope.
 */
export class VirtualizationGuestAgent {
  private readonly authenticationKey: Buffer;
  private readonly replayGuard: VirtualizationGuestReplayGuard;
  private readonly expectedGuestIdentity: VirtualizationGuestIdentity;
  private readonly expectedSandboxProfile: string;
  private readonly expectedProfileDigest: string;
  private readonly executeRequest: VirtualizationGuestAgentOptions["execute"];
  private readonly lookupRequest: VirtualizationGuestAgentOptions["lookup"];
  private readonly maxRequestBytes: number;
  private readonly maxResponseBytes: number;
  private readonly now: () => number;
  private readonly activeControllers = new Set<AbortController>();
  private closed = false;

  constructor(options: VirtualizationGuestAgentOptions) {
    if (!Buffer.isBuffer(options?.authenticationKey) || options.authenticationKey.byteLength !== 32 ||
        options.replayGuard === undefined || typeof options.replayGuard.admit !== "function" ||
        options.expectedGuestIdentity === null || typeof options.expectedGuestIdentity !== "object" ||
        typeof options.expectedSandboxProfile !== "string" || typeof options.expectedProfileDigest !== "string" ||
        typeof options.execute !== "function" ||
        (options.lookup !== undefined && typeof options.lookup !== "function") ||
        (options.now !== undefined && typeof options.now !== "function")) {
      throw new Error("Virtualization guest agent options are invalid");
    }
    const maxRequestBytes = options.maxRequestBytes ?? MAX_REQUEST_BYTES;
    const maxResponseBytes = options.maxResponseBytes ?? MAX_RESPONSE_BYTES;
    if (!Number.isSafeInteger(maxRequestBytes) || maxRequestBytes < 256 || maxRequestBytes > MAX_REQUEST_BYTES ||
        !Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 256 || maxResponseBytes > MAX_RESPONSE_BYTES) {
      throw new Error("Virtualization guest agent frame limits are invalid");
    }
    this.authenticationKey = Buffer.from(options.authenticationKey);
    this.replayGuard = options.replayGuard;
    this.expectedGuestIdentity = parseVirtualizationGuestIdentity(options.expectedGuestIdentity);
    this.expectedSandboxProfile = options.expectedSandboxProfile;
    this.expectedProfileDigest = options.expectedProfileDigest;
    this.executeRequest = options.execute;
    this.lookupRequest = options.lookup;
    this.maxRequestBytes = maxRequestBytes;
    this.maxResponseBytes = maxResponseBytes;
    this.now = options.now ?? Date.now;
  }

  /**
   * Handles exactly one JSON request frame and returns exactly one signed JSON
   * response frame. A transport may wrap this method in a virtio-socket loop.
   */
  async exchange(frame: Uint8Array, signal?: AbortSignal): Promise<Uint8Array> {
    if (this.closed) throw new BrokerError("POLICY_DENIED", "Virtualization guest agent is closed");
    if (signal?.aborted) throw new BrokerError("CANCELLED", "Virtualization guest request was cancelled");
    if (!(frame instanceof Uint8Array) || frame.byteLength < 1 || frame.byteLength > this.maxRequestBytes) {
      throw new BrokerError("OUTPUT_LIMIT", "Virtualization guest request frame exceeded the byte limit");
    }
    let raw: unknown;
    try {
      raw = parseJsonUtf8Strict(Buffer.from(frame));
    } catch {
      throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest request frame is not valid JSON");
    }
    if (raw !== null && typeof raw === "object" && (raw as { kind?: unknown }).kind === "virtualization_guest_task") {
      return this.handleTask(raw, signal);
    }
    if (raw !== null && typeof raw === "object" && (raw as { kind?: unknown }).kind === "virtualization_guest_task_status") {
      return this.handleStatus(raw, signal);
    }
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest request kind is invalid");
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    for (const controller of this.activeControllers) controller.abort();
    this.activeControllers.clear();
    this.authenticationKey.fill(0);
  }

  private async handleTask(raw: unknown, signal?: AbortSignal): Promise<Uint8Array> {
    const request = verifyVirtualizationGuestRequest(raw, this.authenticationKey, {
      replayGuard: this.replayGuard,
      now: this.now(),
      expectedGuestIdentity: this.expectedGuestIdentity,
      expectedSandboxProfile: this.expectedSandboxProfile,
      expectedProfileDigest: this.expectedProfileDigest
    });
    const control = this.beginRequest(signal);
    try {
      const response = await this.executeRequest({ ...request, guestIdentity: { ...request.guestIdentity } }, control.controller.signal);
      if (control.controller.signal.aborted || this.closed) throw new BrokerError("CANCELLED", "Virtualization guest task was cancelled");
      const signed = bindAndSignTaskResponse(response, request, this.authenticationKey, this.expectedGuestIdentity);
      return encodeResponse(signed, this.maxResponseBytes, "Virtualization guest response");
    } finally {
      control.dispose();
    }
  }

  private async handleStatus(raw: unknown, signal?: AbortSignal): Promise<Uint8Array> {
    const request = verifyVirtualizationGuestStatusRequest(raw, this.authenticationKey, {
      replayGuard: this.replayGuard,
      now: this.now(),
      expectedGuestIdentity: this.expectedGuestIdentity
    });
    if (this.lookupRequest === undefined) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest status service is not enabled");
    }
    const control = this.beginRequest(signal);
    try {
      const response = await this.lookupRequest({ ...request, guestIdentity: { ...request.guestIdentity } }, control.controller.signal);
      if (control.controller.signal.aborted || this.closed) throw new BrokerError("CANCELLED", "Virtualization guest status was cancelled");
      const signed = bindAndSignStatusResponse(response, request, this.authenticationKey, this.expectedGuestIdentity);
      return encodeResponse(signed, this.maxResponseBytes, "Virtualization guest status response");
    } finally {
      control.dispose();
    }
  }

  private beginRequest(signal?: AbortSignal): { controller: AbortController; dispose: () => void } {
    if (this.closed) throw new BrokerError("POLICY_DENIED", "Virtualization guest agent is closed");
    if (signal?.aborted) throw new BrokerError("CANCELLED", "Virtualization guest request was cancelled");
    const controller = new AbortController();
    const abortFromCaller = (): void => controller.abort();
    signal?.addEventListener("abort", abortFromCaller, { once: true });
    this.activeControllers.add(controller);
    return {
      controller,
      dispose: () => {
        signal?.removeEventListener("abort", abortFromCaller);
        this.activeControllers.delete(controller);
      }
    };
  }
}

function bindAndSignTaskResponse(
  response: UnsignedVirtualizationGuestResponse,
  request: UnsignedVirtualizationGuestRequest,
  authenticationKey: Buffer,
  expectedGuestIdentity: VirtualizationGuestIdentity
): SignedVirtualizationGuestResponse {
  try {
    validateUnsignedVirtualizationGuestResponse(response);
  } catch {
    throw new BrokerError("EXECUTION_FAILED", "Virtualization guest executor returned a malformed response");
  }
  if (response.requestId !== request.requestId || response.nonce !== request.nonce ||
      response.requestDigest !== virtualizationGuestRequestDigest(request) ||
      !sameVirtualizationGuestIdentity(response.guestIdentity, expectedGuestIdentity)) {
    throw new BrokerError("CONFLICT", "Virtualization guest response is not bound to the admitted request");
  }
  return signVirtualizationGuestResponse(response, authenticationKey);
}

function bindAndSignStatusResponse(
  response: UnsignedVirtualizationGuestStatusResponse,
  request: UnsignedVirtualizationGuestStatusRequest,
  authenticationKey: Buffer,
  expectedGuestIdentity: VirtualizationGuestIdentity
): SignedVirtualizationGuestStatusResponse {
  try {
    validateUnsignedVirtualizationGuestStatusResponse(response);
  } catch {
    throw new BrokerError("EXECUTION_FAILED", "Virtualization guest status executor returned a malformed response");
  }
  if (response.requestId !== request.requestId || response.nonce !== request.nonce ||
      response.originalRequestId !== request.originalRequestId || response.originalNonce !== request.originalNonce ||
      response.originalRequestDigest !== request.originalRequestDigest ||
      response.statusRequestDigest !== virtualizationGuestStatusRequestDigest(request) ||
      !sameVirtualizationGuestIdentity(response.guestIdentity, expectedGuestIdentity)) {
    throw new BrokerError("CONFLICT", "Virtualization guest status response is not bound to the admitted request");
  }
  return signVirtualizationGuestStatusResponse(response, authenticationKey);
}

function encodeResponse(value: unknown, maxBytes: number, label: string): Uint8Array {
  const encoded = Buffer.from(canonicalJson(value), "utf8");
  if (encoded.byteLength > maxBytes) throw new BrokerError("OUTPUT_LIMIT", `${label} exceeded the byte limit`);
  return encoded;
}
