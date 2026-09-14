import { BrokerError } from "@mac-operator/contracts";
import { loadAuthenticationKey } from "./credentials.js";
import {
  parseVirtualizationGuestIdentity,
  validateVirtualizationGuestAttestation,
  type SignedVirtualizationGuestAttestation,
  type VirtualizationGuestAttestation,
  type VirtualizationGuestAttestationVerifier,
  type VirtualizationGuestIdentity
} from "./virtualization-guest-attestation.js";
import {
  loadVirtualizationGuestImage,
  type LoadedVirtualizationGuestImage,
  type VirtualizationGuestImageConfig
} from "./virtualization-guest-image.js";
import {
  VirtualizationGuestVmLifecycle,
  type VirtualizationGuestVmLifecycleOptions,
  type VirtualizationGuestVmState,
  type VirtualizationGuestVmStatusResult,
  type VirtualizationGuestVmAdapter
} from "./virtualization-guest-lifecycle.js";
import {
  createNativeVirtualizationGuestVm,
  type NativeVirtualizationGuestChannelOptions,
  type NativeVirtualizationGuestConnectionSourceOptions,
  type NativeVirtualizationGuestVmAdapter,
  type NativeVirtualizationGuestVmOptions
} from "./virtualization-guest-vm-native.js";
import {
  VirtualizationGuestTransportClient,
  type VirtualizationGuestReplayGuard,
  type VirtualizationGuestTransportClientOptions,
  type VirtualizationGuestChannel
} from "./virtualization-guest-transport.js";
import {
  VirtualizationGuestTransportExecutor,
  VirtualizationTaskRunner,
  type TaskIsolationProof,
  type TaskRunner
} from "./task-runner.js";
import type { RuntimeChannel } from "./runtime.js";
import type { VirtualizationGuestConnectionSource } from "./virtualization-guest-bootstrap.js";

/** Stable startup-owned virtio port for the authenticated guest protocol. */
export const DEFAULT_VIRTUALIZATION_GUEST_PORT = 38_765;
const DEFAULT_FRAME_BYTES = 4 * 1024 * 1024;
const DEFAULT_EXCHANGE_TIMEOUT_MS = 15_000;

export interface VirtualizationGuestVmFactory {
  (options: NativeVirtualizationGuestVmOptions): Promise<NativeVirtualizationGuestVmAdapter>;
}

/**
 * Startup-only inputs for the governed Virtualization.framework bridge.
 * None of these values are read from MCP request arguments. The authentication
 * key is loaded from an owner-only file and wiped after the transport takes a
 * defensive copy.
 */
export interface VirtualizationGuestRuntimeStartupOptions {
  image: VirtualizationGuestImageConfig;
  authenticationKeyPath?: string;
  replayGuard?: VirtualizationGuestReplayGuard;
  isolationProof?: TaskIsolationProof;
  attestation?: VirtualizationGuestAttestation;
  signedAttestation?: SignedVirtualizationGuestAttestation;
  attestationVerifier?: VirtualizationGuestAttestationVerifier;
  enabled: boolean;
  hostEvidenceAccepted: boolean;
  port?: number;
  maxFrameBytes?: number;
  exchangeTimeoutMs?: number;
  maxResponseBytes?: number;
  /** Optional host-side listener for guest-initiated bootstrap connections. */
  connectionSource?: NativeVirtualizationGuestConnectionSourceOptions;
  lifecycle?: Pick<VirtualizationGuestVmLifecycleOptions, "startTimeoutMs" | "stopTimeoutMs">;
  now?: () => number;
  /** Test seam; production uses the protected native adapter loader. */
  vmFactory?: VirtualizationGuestVmFactory;
}

export interface VirtualizationGuestRuntimeReadback {
  available: boolean;
  state: VirtualizationGuestVmState;
  bootId: string | null;
  guestIdentity: VirtualizationGuestIdentity;
}

export interface VirtualizationGuestRuntime {
  readonly available: boolean;
  readonly guestIdentity: VirtualizationGuestIdentity;
  readonly lifecycle: VirtualizationGuestVmLifecycle;
  readonly taskRunner: TaskRunner;
  /** Channel suitable for LocalBrokerRuntime operatorChannels. */
  readonly runtimeChannel: RuntimeChannel;
  /** Optional fixed-port source for a separately composed guest bootstrap. */
  readonly connectionSource: VirtualizationGuestConnectionSource | undefined;
  start(signal?: AbortSignal): Promise<void>;
  /** Reads native VM state and reconciles an UNKNOWN lifecycle state. */
  recover(signal?: AbortSignal): Promise<VirtualizationGuestVmStatusResult>;
  stop(signal?: AbortSignal): Promise<void>;
  readback(): VirtualizationGuestRuntimeReadback;
  close(): Promise<void>;
}

/**
 * Composes the immutable image binding, native VM lifecycle, fixed virtio
 * channel, authenticated guest transport, and Broker task runner. The bridge
 * is intentionally disabled unless both independent startup gates are true.
 */
export async function createVirtualizationGuestRuntime(
  options: VirtualizationGuestRuntimeStartupOptions
): Promise<VirtualizationGuestRuntime> {
  validateStartupOptions(options);
  const guestIdentity = parseVirtualizationGuestIdentity({
    imageSha256: options.image.expectedSha256,
    runtimeVersion: options.image.runtimeVersion
  });
  const enabled = options.enabled === true && options.hostEvidenceAccepted === true;

  if (!enabled) {
    const lifecycle = new VirtualizationGuestVmLifecycle({
      enabled: false,
      hostEvidenceAccepted: false,
      expectedGuestIdentity: guestIdentity,
      adapter: disabledAdapter(),
      ...(options.lifecycle ?? {})
    });
    return new VirtualizationGuestRuntimeImpl({ lifecycle, guestIdentity, taskRunner: new VirtualizationTaskRunner(), connectionSource: undefined });
  }

  if (options.authenticationKeyPath === undefined || options.replayGuard === undefined ||
      options.isolationProof === undefined || options.attestation === undefined) {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest startup authority is incomplete");
  }
  const image = await loadVirtualizationGuestImage(options.image);
  if (image.guestIdentity.imageSha256 !== guestIdentity.imageSha256 ||
      image.guestIdentity.runtimeVersion !== guestIdentity.runtimeVersion) {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest image identity does not match startup authority");
  }
  const vmFactory = options.vmFactory ?? createNativeVirtualizationGuestVm;
  const adapter = await vmFactory({ image, enabled: true, hostEvidenceAccepted: true });
  if (adapter === null || typeof adapter !== "object" || typeof adapter.createChannel !== "function") {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest VM channel adapter is unavailable");
  }
  const lifecycle = new VirtualizationGuestVmLifecycle({
    enabled: true,
    hostEvidenceAccepted: true,
    expectedGuestIdentity: guestIdentity,
    adapter,
    ...(options.lifecycle ?? {})
  });
  if (!lifecycle.available) {
    if (typeof adapter.close === "function") await adapter.close().catch(() => undefined);
    return new VirtualizationGuestRuntimeImpl({ lifecycle, guestIdentity, taskRunner: new VirtualizationTaskRunner(), connectionSource: undefined });
  }

  const channelOptions: NativeVirtualizationGuestChannelOptions = {
    port: options.port ?? DEFAULT_VIRTUALIZATION_GUEST_PORT,
    maxFrameBytes: options.maxFrameBytes ?? DEFAULT_FRAME_BYTES,
    timeoutMs: options.exchangeTimeoutMs ?? DEFAULT_EXCHANGE_TIMEOUT_MS
  };
  let transport: VirtualizationGuestTransportClient;
  let channel: VirtualizationGuestChannel;
  let connectionSource: VirtualizationGuestConnectionSource | undefined;
  try {
    channel = adapter.createChannel(channelOptions);
    if (options.connectionSource !== undefined) {
      if (typeof adapter.createConnectionSource !== "function") {
        throw new BrokerError("POLICY_DENIED", "Virtualization guest listener adapter is unavailable");
      }
      connectionSource = adapter.createConnectionSource(options.connectionSource);
    }
    const key = await loadAuthenticationKey(options.authenticationKeyPath);
    try {
      const transportOptions: VirtualizationGuestTransportClientOptions = {
        authenticationKey: key,
        replayGuard: options.replayGuard,
        channel,
        expectedGuestIdentity: guestIdentity,
        ...(options.maxResponseBytes === undefined ? {} : { maxResponseBytes: options.maxResponseBytes }),
        ...(options.now === undefined ? {} : { now: options.now })
      };
      transport = new VirtualizationGuestTransportClient(transportOptions);
    } finally {
      key.fill(0);
    }
  } catch (error) {
    if (connectionSource !== undefined) await connectionSource.close().catch(() => undefined);
    await lifecycle.close().catch(() => undefined);
    throw error;
  }
  try {
    const executor = new VirtualizationGuestTransportExecutor({
      available: lifecycle.available,
      transport,
      guestIdentity,
      attestation: validateVirtualizationGuestAttestation(options.attestation),
      ...(options.signedAttestation === undefined ? {} : { signedAttestation: options.signedAttestation })
    });
    const taskRunner = new VirtualizationTaskRunner({
      enabled: true,
      hostEvidenceAccepted: true,
      executor,
      guestImage: image,
      isolationProof: options.isolationProof,
      ...(options.attestationVerifier === undefined ? {} : { attestationVerifier: options.attestationVerifier })
    });
    return new VirtualizationGuestRuntimeImpl({ lifecycle, guestIdentity, taskRunner, connectionSource });
  } catch (error) {
    if (connectionSource !== undefined) await connectionSource.close().catch(() => undefined);
    transport.close();
    await lifecycle.close().catch(() => undefined);
    throw error;
  }
}

class VirtualizationGuestRuntimeImpl implements VirtualizationGuestRuntime {
  readonly available: boolean;
  readonly guestIdentity: VirtualizationGuestIdentity;
  readonly lifecycle: VirtualizationGuestVmLifecycle;
  readonly taskRunner: TaskRunner;
  readonly runtimeChannel: RuntimeChannel;
  readonly connectionSource: VirtualizationGuestConnectionSource | undefined;
  private closed = false;
  private closePromise: Promise<void> | undefined;

  constructor(options: {
    lifecycle: VirtualizationGuestVmLifecycle;
    guestIdentity: VirtualizationGuestIdentity;
    taskRunner: TaskRunner;
    connectionSource: VirtualizationGuestConnectionSource | undefined;
  }) {
    this.lifecycle = options.lifecycle;
    this.guestIdentity = { ...options.guestIdentity };
    this.available = options.lifecycle.available;
    this.taskRunner = options.taskRunner;
    this.connectionSource = options.connectionSource;
    this.runtimeChannel = {
      listen: () => this.start(),
      close: () => this.close()
    };
  }

  async start(signal?: AbortSignal): Promise<void> {
    if (this.closed) throw new BrokerError("POLICY_DENIED", "Virtualization guest runtime is closed");
    await this.lifecycle.start(signal);
  }

  recover(signal?: AbortSignal): Promise<VirtualizationGuestVmStatusResult> {
    if (this.closed) return Promise.reject(new BrokerError("POLICY_DENIED", "Virtualization guest runtime is closed"));
    return this.lifecycle.status(signal);
  }

  async stop(signal?: AbortSignal): Promise<void> {
    if (this.closed) return;
    await this.lifecycle.stop(signal);
  }

  readback(): VirtualizationGuestRuntimeReadback {
    return {
      available: this.available,
      state: this.lifecycle.state,
      bootId: this.lifecycle.bootId,
      guestIdentity: { ...this.guestIdentity }
    };
  }

  close(): Promise<void> {
    if (this.closePromise !== undefined) return this.closePromise;
    this.closePromise = (async () => {
      let firstError: unknown;
      try { await this.connectionSource?.close(); } catch (error) { firstError ??= error; }
      try { await this.taskRunner.close?.(); } catch (error) { firstError ??= error; }
      try { await this.lifecycle.close(); } catch (error) { firstError ??= error; }
      this.closed = firstError !== undefined;
      if (firstError !== undefined) throw firstError;
      this.closed = true;
    })();
    return this.closePromise;
  }
}

function disabledAdapter(): VirtualizationGuestVmAdapter {
  const reject = async (): Promise<never> => {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest VM adapter is not enabled");
  };
  return {
    available: false,
    guestIdentity: null,
    start: reject,
    stop: reject,
    status: reject,
    close: async () => undefined
  };
}

function validateStartupOptions(options: VirtualizationGuestRuntimeStartupOptions): void {
  if (options === null || typeof options !== "object" || options.image === undefined ||
      typeof options.enabled !== "boolean" || typeof options.hostEvidenceAccepted !== "boolean") {
    throw new Error("Virtualization guest startup options are invalid");
  }
  const port = options.port ?? DEFAULT_VIRTUALIZATION_GUEST_PORT;
  const maxFrameBytes = options.maxFrameBytes ?? DEFAULT_FRAME_BYTES;
  const exchangeTimeoutMs = options.exchangeTimeoutMs ?? DEFAULT_EXCHANGE_TIMEOUT_MS;
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535 ||
      !Number.isSafeInteger(maxFrameBytes) || maxFrameBytes < 256 || maxFrameBytes > DEFAULT_FRAME_BYTES ||
      !Number.isSafeInteger(exchangeTimeoutMs) || exchangeTimeoutMs < 1 || exchangeTimeoutMs > 120_000 ||
      (options.maxResponseBytes !== undefined && (!Number.isSafeInteger(options.maxResponseBytes) || options.maxResponseBytes < 256 || options.maxResponseBytes > DEFAULT_FRAME_BYTES + 64 * 1024)) ||
      (options.now !== undefined && typeof options.now !== "function")) {
    throw new Error("Virtualization guest startup limits are invalid");
  }
  if (options.vmFactory !== undefined && typeof options.vmFactory !== "function") {
    throw new Error("Virtualization guest VM factory is invalid");
  }
}
