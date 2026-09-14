import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { BrokerError } from "@mac-operator/contracts";
import { validateNativeAdapterPath } from "./peer-credentials.js";
import { verifyVirtualizationGuestImage, type LoadedVirtualizationGuestImage } from "./virtualization-guest-image.js";
import {
  parseVirtualizationGuestIdentity,
  sameVirtualizationGuestIdentity,
  type VirtualizationGuestIdentity
} from "./virtualization-guest-attestation.js";
import type {
  VirtualizationGuestVmAdapter,
  VirtualizationGuestVmStartResult,
  VirtualizationGuestVmStatusResult,
  VirtualizationGuestVmStopResult
} from "./virtualization-guest-lifecycle.js";
import type { VirtualizationGuestChannel } from "./virtualization-guest-transport.js";

const require = createRequire(import.meta.url);
const MAX_NATIVE_ADAPTER_BYTES = 16 * 1024 * 1024;
const MIN_SUPPORTED_NAPI_VERSION = 8;
const BOOT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const RUNTIME_VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}$/u;

export interface NativeVirtualizationGuestVmBinding {
  nativeNapiVersion: number;
  createGuestVm(
    imagePath: string,
    device: string,
    inode: string,
    sha256: string,
    runtimeVersion: string
  ): unknown;
  startGuestVm(handle: unknown): Promise<unknown>;
  stopGuestVm(handle: unknown, bootId: string): Promise<unknown>;
  statusGuestVm(handle: unknown): Promise<unknown>;
  closeGuestVm(handle: unknown): void;
  exchangeGuestFrame(
    handle: unknown,
    port: number,
    frame: Buffer,
    maxResponseBytes: number,
    timeoutMs: number
  ): Promise<unknown>;
}

export interface NativeVirtualizationGuestChannelOptions {
  /** Guest-owned virtio-socket port; the Broker startup config owns it. */
  port: number;
  maxFrameBytes?: number;
  timeoutMs?: number;
}

export interface NativeVirtualizationGuestVmAdapter extends VirtualizationGuestVmAdapter {
  createChannel(options: NativeVirtualizationGuestChannelOptions): VirtualizationGuestChannel;
}

interface NativeAdapterArtifact {
  device: number;
  inode: number;
  size: number;
  digest: string;
}

let loadedArtifact: NativeAdapterArtifact | undefined;

/**
 * Loads the protected native Virtualization.framework lifecycle artifact.
 * This is startup-only; MCP arguments never select the module or image.
 */
export function loadNativeVirtualizationGuestVmBinding(): NativeVirtualizationGuestVmBinding {
  if (process.platform !== "darwin") throw new Error("Virtualization guest VM adapter requires macOS");
  try {
    const nativePath = require.resolve("./virtualization_guest_lifecycle.node");
    const before = readArtifact(nativePath);
    if (loadedArtifact !== undefined && !sameArtifact(loadedArtifact, before)) {
      throw new Error("Virtualization guest VM adapter changed after initial load");
    }
    const native = require(nativePath) as Partial<NativeVirtualizationGuestVmBinding>;
    const after = readArtifact(nativePath);
    if (!sameArtifact(before, after)) throw new Error("Virtualization guest VM adapter changed while loading");
    const runtimeNapiVersion = Number.parseInt(process.versions.napi ?? "", 10);
    if (typeof native.nativeNapiVersion !== "number" || !Number.isSafeInteger(native.nativeNapiVersion) ||
        native.nativeNapiVersion < MIN_SUPPORTED_NAPI_VERSION ||
        !Number.isSafeInteger(runtimeNapiVersion) || runtimeNapiVersion < MIN_SUPPORTED_NAPI_VERSION ||
        native.nativeNapiVersion > runtimeNapiVersion ||
        typeof native.createGuestVm !== "function" || typeof native.startGuestVm !== "function" ||
        typeof native.stopGuestVm !== "function" || typeof native.statusGuestVm !== "function" ||
        typeof native.closeGuestVm !== "function" || typeof native.exchangeGuestFrame !== "function") {
      throw new Error("Virtualization guest VM adapter exports are incompatible");
    }
    loadedArtifact = after;
    return native as NativeVirtualizationGuestVmBinding;
  } catch {
    throw new Error("Virtualization guest VM native adapter is unavailable");
  }
}

export interface NativeVirtualizationGuestVmOptions {
  image: LoadedVirtualizationGuestImage;
  /** Independent host startup gate; MCP requests cannot set this value. */
  enabled: boolean;
  /** External reviewed evidence gate; this is never request-controlled. */
  hostEvidenceAccepted: boolean;
}

/**
 * Creates a Broker-owned native VM adapter after re-reading the startup image.
 * The native handle retains only the immutable image identity and no caller
 * path is accepted by start, stop, or status operations.
 */
export async function createNativeVirtualizationGuestVm(
  options: NativeVirtualizationGuestVmOptions
): Promise<NativeVirtualizationGuestVmAdapter> {
  if (options === null || typeof options !== "object" || options.enabled !== true ||
      options.hostEvidenceAccepted !== true) {
    return unavailableAdapter();
  }
  const image = await verifyVirtualizationGuestImage(options.image);
  const guestIdentity = parseVirtualizationGuestIdentity(image.guestIdentity);
  const native = loadNativeVirtualizationGuestVmBinding();
  let handle: unknown;
  try {
    handle = native.createGuestVm(
      image.path,
      image.device,
      image.inode,
      guestIdentity.imageSha256,
      guestIdentity.runtimeVersion
    );
  } catch {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest VM configuration is unavailable");
  }
  if (handle === null || handle === undefined) {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest VM handle is unavailable");
  }
  return new NativeVirtualizationGuestVmAdapterImpl(native, handle, guestIdentity, image);
}

class NativeVirtualizationGuestVmAdapterImpl implements NativeVirtualizationGuestVmAdapter {
  readonly available = true;
  readonly guestIdentity: VirtualizationGuestIdentity;
  private closed = false;

  constructor(
    private readonly native: NativeVirtualizationGuestVmBinding,
    private readonly handle: unknown,
    guestIdentity: VirtualizationGuestIdentity,
    private readonly image: LoadedVirtualizationGuestImage
  ) {
    this.guestIdentity = parseVirtualizationGuestIdentity(guestIdentity);
  }

  async start(input: { guestIdentity: VirtualizationGuestIdentity; signal: AbortSignal }): Promise<VirtualizationGuestVmStartResult> {
    this.assertOpen();
    this.assertIdentity(input.guestIdentity);
    await this.assertImageStable();
    const result = await raceAbort(
      this.native.startGuestVm(this.handle),
      input.signal,
      "Virtualization guest VM start was cancelled"
    );
    return parseTransitionResult(result, "running", this.guestIdentity);
  }

  async stop(input: { guestIdentity: VirtualizationGuestIdentity; bootId: string; signal: AbortSignal }): Promise<VirtualizationGuestVmStopResult> {
    this.assertOpen();
    this.assertIdentity(input.guestIdentity);
    if (typeof input.bootId !== "string" || !BOOT_ID_PATTERN.test(input.bootId)) {
      throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest VM boot ID is malformed");
    }
    await this.assertImageStable();
    const result = await raceAbort(
      this.native.stopGuestVm(this.handle, input.bootId),
      input.signal,
      "Virtualization guest VM stop was cancelled"
    );
    return parseTransitionResult(result, "stopped", this.guestIdentity, input.bootId);
  }

  async status(input: { guestIdentity: VirtualizationGuestIdentity; signal: AbortSignal }): Promise<VirtualizationGuestVmStatusResult> {
    this.assertOpen();
    this.assertIdentity(input.guestIdentity);
    if (input.signal.aborted) throw new BrokerError("CANCELLED", "Virtualization guest VM status was cancelled");
    await this.assertImageStable();
    let result: unknown;
    try {
      result = await raceAbort(
        this.native.statusGuestVm(this.handle),
        input.signal,
        "Virtualization guest VM status was cancelled"
      );
    } catch (error) {
      if (error instanceof BrokerError && error.errorClass === "CANCELLED") throw error;
      throw new BrokerError("UNKNOWN_OUTCOME", "Virtualization guest VM status is unavailable", true);
    }
    return parseStatusResult(result, this.guestIdentity);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    try {
      this.native.closeGuestVm(this.handle);
    } catch {
      throw new BrokerError("UNKNOWN_OUTCOME", "Virtualization guest VM close outcome is unknown", true);
    }
    this.closed = true;
  }

  createChannel(options: NativeVirtualizationGuestChannelOptions): VirtualizationGuestChannel {
    this.assertOpen();
    validateChannelOptions(options);
    return new NativeVirtualizationGuestChannel(this.native, this.handle, options);
  }

  private assertOpen(): void {
    if (this.closed) throw new BrokerError("POLICY_DENIED", "Virtualization guest VM adapter is closed");
  }

  private assertIdentity(identity: VirtualizationGuestIdentity): void {
    if (!sameVirtualizationGuestIdentity(this.guestIdentity, identity)) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest VM identity does not match the adapter");
    }
  }

  private async assertImageStable(): Promise<void> {
    try {
      await verifyVirtualizationGuestImage(this.image);
    } catch {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest VM image identity changed");
    }
  }
}

export class NativeVirtualizationGuestChannel implements VirtualizationGuestChannel {
  private readonly port: number;
  private readonly maxFrameBytes: number;
  private readonly timeoutMs: number;

  constructor(
    private readonly native: NativeVirtualizationGuestVmBinding,
    private readonly handle: unknown,
    options: NativeVirtualizationGuestChannelOptions
  ) {
    validateChannelOptions(options);
    this.port = options.port;
    this.maxFrameBytes = options.maxFrameBytes ?? 4 * 1024 * 1024;
    this.timeoutMs = options.timeoutMs ?? 15_000;
  }

  async exchange(frame: Uint8Array, signal: AbortSignal): Promise<Uint8Array> {
    if (!(frame instanceof Uint8Array) || frame.byteLength < 1 || frame.byteLength > this.maxFrameBytes) {
      throw new BrokerError("OUTPUT_LIMIT", "Virtualization guest frame exceeded the byte limit");
    }
    if (signal.aborted) throw new BrokerError("CANCELLED", "Virtualization guest frame exchange was cancelled");
    const result = await raceAbort(
      this.native.exchangeGuestFrame(this.handle, this.port, Buffer.from(frame), this.maxFrameBytes, this.timeoutMs),
      signal,
      "Virtualization guest frame exchange was cancelled"
    );
    if (!Buffer.isBuffer(result) && !(result instanceof Uint8Array)) {
      throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest frame response is malformed");
    }
    if (result.byteLength < 1 || result.byteLength > this.maxFrameBytes) {
      throw new BrokerError("OUTPUT_LIMIT", "Virtualization guest frame response exceeded the byte limit");
    }
    return new Uint8Array(result);
  }
}

function unavailableAdapter(): NativeVirtualizationGuestVmAdapter {
  const reject = async (): Promise<never> => {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest VM adapter is not enabled");
  };
  return {
    available: false,
    guestIdentity: null,
    start: reject,
    stop: reject,
    status: reject,
    createChannel: () => {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest VM adapter is not enabled");
    }
  };
}

function validateChannelOptions(options: NativeVirtualizationGuestChannelOptions): void {
  if (options === null || typeof options !== "object" ||
      !Number.isSafeInteger(options.port) || options.port < 1 || options.port > 65_535 ||
      (options.maxFrameBytes !== undefined && (!Number.isSafeInteger(options.maxFrameBytes) || options.maxFrameBytes < 256 || options.maxFrameBytes > 4 * 1024 * 1024)) ||
      (options.timeoutMs !== undefined && (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1 || options.timeoutMs > 120_000))) {
    throw new Error("Virtualization guest channel options are invalid");
  }
}

function parseTransitionResult(
  value: unknown,
  expectedState: "running",
  expectedGuestIdentity: VirtualizationGuestIdentity
): VirtualizationGuestVmStartResult;
function parseTransitionResult(
  value: unknown,
  expectedState: "stopped",
  expectedGuestIdentity: VirtualizationGuestIdentity,
  expectedBootId: string
): VirtualizationGuestVmStopResult;
function parseTransitionResult(
  value: unknown,
  expectedState: "running" | "stopped",
  expectedGuestIdentity: VirtualizationGuestIdentity,
  expectedBootId?: string
): VirtualizationGuestVmStartResult | VirtualizationGuestVmStopResult {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("EXECUTION_FAILED", "Virtualization guest VM adapter returned a malformed result");
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !["bootId", "guestIdentity", "state"].includes(key)) ||
      record.state !== expectedState || typeof record.bootId !== "string" || !BOOT_ID_PATTERN.test(record.bootId) ||
      record.guestIdentity === null || typeof record.guestIdentity !== "object" ||
      !sameVirtualizationGuestIdentity(expectedGuestIdentity, parseVirtualizationGuestIdentity(record.guestIdentity))) {
    throw new BrokerError("VERIFICATION_FAILED", "Virtualization guest VM adapter result identity is invalid");
  }
  if (expectedBootId !== undefined && record.bootId !== expectedBootId) {
    throw new BrokerError("VERIFICATION_FAILED", "Virtualization guest VM adapter boot identity changed");
  }
  return {
    state: expectedState,
    guestIdentity: { ...expectedGuestIdentity },
    bootId: record.bootId
  } as VirtualizationGuestVmStartResult | VirtualizationGuestVmStopResult;
}

function parseStatusResult(value: unknown, expectedGuestIdentity: VirtualizationGuestIdentity): VirtualizationGuestVmStatusResult {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("EXECUTION_FAILED", "Virtualization guest VM status result is malformed");
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !["bootId", "guestIdentity", "state"].includes(key)) ||
      (record.state !== "running" && record.state !== "stopped" && record.state !== "unknown") ||
      record.guestIdentity === null || typeof record.guestIdentity !== "object" ||
      !sameVirtualizationGuestIdentity(expectedGuestIdentity, parseVirtualizationGuestIdentity(record.guestIdentity)) ||
      (record.state === "running" && (typeof record.bootId !== "string" || !BOOT_ID_PATTERN.test(record.bootId))) ||
      (record.state !== "running" && record.bootId !== null)) {
    throw new BrokerError("VERIFICATION_FAILED", "Virtualization guest VM status identity is invalid");
  }
  return {
    state: record.state,
    guestIdentity: { ...expectedGuestIdentity },
    bootId: record.state === "running" ? record.bootId as string : null
  };
}

async function raceAbort<T>(operation: Promise<T>, signal: AbortSignal, message: string): Promise<T> {
  if (signal.aborted) throw new BrokerError("CANCELLED", message);
  let rejectAbort: ((reason: BrokerError) => void) | undefined;
  const aborted = new Promise<T>((_resolve, reject) => { rejectAbort = reject; });
  const onAbort = (): void => rejectAbort?.(new BrokerError("CANCELLED", message));
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    return await Promise.race([operation, aborted]);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

function readArtifact(nativePath: string): NativeAdapterArtifact {
  validateNativeAdapterPath(nativePath);
  const stat = statSync(nativePath);
  if (stat.size > MAX_NATIVE_ADAPTER_BYTES) throw new Error("Virtualization guest VM adapter is oversized");
  return {
    device: stat.dev,
    inode: stat.ino,
    size: stat.size,
    digest: createHash("sha256").update(readFileSync(nativePath)).digest("hex")
  };
}

function sameArtifact(left: NativeAdapterArtifact, right: NativeAdapterArtifact): boolean {
  return left.device === right.device && left.inode === right.inode &&
    left.size === right.size && left.digest === right.digest;
}

export function validateNativeVirtualizationGuestVmAdapterPath(nativePath: string): void {
  validateNativeAdapterPath(nativePath);
}

export function validateNativeVirtualizationGuestVmIdentity(value: VirtualizationGuestIdentity): VirtualizationGuestIdentity {
  const identity = parseVirtualizationGuestIdentity(value);
  if (!SHA256_PATTERN.test(identity.imageSha256) || !RUNTIME_VERSION_PATTERN.test(identity.runtimeVersion)) {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest VM identity is malformed");
  }
  return identity;
}
