import { BrokerError } from "@mac-operator/contracts";
import { VirtualizationGuestAgent, type VirtualizationGuestAgentOptions } from "./virtualization-guest-agent.js";

const FRAME_HEADER_BYTES = 4;
const DEFAULT_MAX_FRAME_BYTES = 64 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024 + 64 * 1024;
const DEFAULT_CONNECTION_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_CONNECTIONS = 8;

export type VirtualizationGuestBootstrapState =
  | "disabled"
  | "stopped"
  | "starting"
  | "running"
  | "stopping"
  | "failed"
  | "closed";

/** One accepted guest-side stream; the transport-specific acceptor owns it. */
export interface VirtualizationGuestStream {
  readonly readable: AsyncIterable<Uint8Array>;
  write(frame: Uint8Array): Promise<void>;
  close(): Promise<void> | void;
}

/**
 * Guest bootstrap deliberately does not know how a vsock is opened. A native
 * guest adapter supplies this accept source and remains responsible for the
 * platform socket policy; the protocol loop below is transport-independent.
 */
export interface VirtualizationGuestConnectionSource {
  accept(signal: AbortSignal): Promise<VirtualizationGuestStream | null>;
  close(): Promise<void>;
}

export interface VirtualizationGuestBootstrapOptions {
  enabled: boolean;
  agent: VirtualizationGuestAgent | VirtualizationGuestAgentOptions;
  source: VirtualizationGuestConnectionSource;
  maxFrameBytes?: number;
  maxResponseBytes?: number;
  connectionTimeoutMs?: number;
  maxConnections?: number;
}

export interface VirtualizationGuestBootstrapReadback {
  state: VirtualizationGuestBootstrapState;
  activeConnections: number;
  acceptedConnections: number;
  completedConnections: number;
  rejectedConnections: number;
}

/**
 * Bounded guest-side server for the authenticated agent protocol. Each
 * connection carries exactly one length-prefixed JSON frame and is closed
 * after one response; extra requests cannot turn a connection into a stream.
 */
export class VirtualizationGuestBootstrap {
  private readonly source: VirtualizationGuestConnectionSource;
  private readonly agent: VirtualizationGuestAgent;
  private readonly maxFrameBytes: number;
  private readonly maxResponseBytes: number;
  private readonly connectionTimeoutMs: number;
  private readonly maxConnections: number;
  private stateValue: VirtualizationGuestBootstrapState;
  private activeConnections = new Set<{ stream: VirtualizationGuestStream; controller: AbortController; promise: Promise<void> }>();
  private acceptAbort: AbortController | undefined;
  private acceptLoop: Promise<void> | undefined;
  private operation: Promise<void> = Promise.resolve();
  private acceptedConnections = 0;
  private completedConnections = 0;
  private rejectedConnections = 0;

  constructor(options: VirtualizationGuestBootstrapOptions) {
    validateOptions(options);
    this.source = options.source;
    this.agent = options.agent instanceof VirtualizationGuestAgent
      ? options.agent
      : new VirtualizationGuestAgent(options.agent);
    this.maxFrameBytes = options.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES;
    this.maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
    this.connectionTimeoutMs = options.connectionTimeoutMs ?? DEFAULT_CONNECTION_TIMEOUT_MS;
    this.maxConnections = options.maxConnections ?? DEFAULT_MAX_CONNECTIONS;
    this.stateValue = options.enabled ? "stopped" : "disabled";
  }

  get state(): VirtualizationGuestBootstrapState {
    return this.stateValue;
  }

  readback(): VirtualizationGuestBootstrapReadback {
    return {
      state: this.stateValue,
      activeConnections: this.activeConnections.size,
      acceptedConnections: this.acceptedConnections,
      completedConnections: this.completedConnections,
      rejectedConnections: this.rejectedConnections
    };
  }

  start(): Promise<void> {
    return this.enqueue(async () => {
      if (this.stateValue === "disabled") throw new BrokerError("POLICY_DENIED", "Virtualization guest bootstrap is disabled");
      if (this.stateValue !== "stopped") throw new BrokerError("CONFLICT", `Virtualization guest bootstrap cannot start from ${this.stateValue}`);
      this.stateValue = "starting";
      this.acceptAbort = new AbortController();
      this.acceptLoop = this.runAcceptLoop(this.acceptAbort.signal);
      this.stateValue = "running";
    });
  }

  close(): Promise<void> {
    return this.enqueue(() => this.closeInternal());
  }

  private async runAcceptLoop(signal: AbortSignal): Promise<void> {
    try {
      while (!signal.aborted) {
        const stream = await this.source.accept(signal);
        if (stream === null) break;
        this.acceptedConnections += 1;
        if (this.activeConnections.size >= this.maxConnections) {
          this.rejectedConnections += 1;
          await Promise.resolve(stream.close()).catch(() => undefined);
          continue;
        }
        const record = { stream, controller: new AbortController(), promise: Promise.resolve() };
        record.promise = this.serveStream(stream, record.controller.signal).finally(() => {
          this.activeConnections.delete(record);
          if (this.stateValue === "stopping" && this.activeConnections.size === 0) this.stateValue = "stopped";
        });
        this.activeConnections.add(record);
      }
      if (!signal.aborted && this.stateValue === "running") {
        this.stateValue = this.activeConnections.size === 0 ? "stopped" : "stopping";
      }
    } catch {
      if (!signal.aborted) this.stateValue = "failed";
    }
  }

  private async serveStream(stream: VirtualizationGuestStream, signal: AbortSignal): Promise<void> {
    const deadline = Date.now() + this.connectionTimeoutMs;
    try {
      const request = await withDeadline(
        readFrame(stream.readable, this.maxFrameBytes),
        deadline,
        "Virtualization guest request frame timed out"
      );
      const response = await withDeadline(
        this.agent.exchange(request, signal),
        deadline,
        "Virtualization guest request execution timed out"
      );
      if (!(response instanceof Uint8Array) || response.byteLength < 1 || response.byteLength > this.maxResponseBytes) {
        throw new BrokerError("OUTPUT_LIMIT", "Virtualization guest response frame exceeded the byte limit");
      }
      const header = Buffer.alloc(FRAME_HEADER_BYTES);
      header.writeUInt32BE(response.byteLength, 0);
      await withDeadline(
        stream.write(Buffer.concat([header, Buffer.from(response)])),
        deadline,
        "Virtualization guest response write timed out"
      );
      this.completedConnections += 1;
    } catch {
      this.rejectedConnections += 1;
    } finally {
      await Promise.resolve(stream.close()).catch(() => undefined);
    }
  }

  private async closeInternal(): Promise<void> {
    if (this.stateValue === "closed") return;
    if (this.stateValue === "disabled") {
      await this.source.close().catch(() => undefined);
      this.agent.close();
      this.stateValue = "closed";
      return;
    }
    this.stateValue = "stopping";
    this.acceptAbort?.abort();
    let firstError: unknown;
    try { await this.source.close(); } catch (error) { firstError = error; }
    if (this.acceptLoop !== undefined) {
      try { await this.acceptLoop; } catch (error) { firstError ??= error; }
    }
    const active = [...this.activeConnections];
    for (const record of active) {
      record.controller.abort();
      await Promise.resolve(record.stream.close()).catch(() => undefined);
    }
    await Promise.allSettled(active.map((record) => record.promise));
    try { this.agent.close(); } catch (error) { firstError ??= error; }
    this.stateValue = firstError === undefined ? "closed" : "failed";
    if (firstError !== undefined) throw firstError;
  }

  private enqueue(operation: () => Promise<void>): Promise<void> {
    const run = this.operation.catch(() => undefined).then(operation);
    this.operation = run;
    return run;
  }
}

async function readFrame(readable: AsyncIterable<Uint8Array>, maxFrameBytes: number): Promise<Uint8Array> {
  let buffer = Buffer.alloc(0);
  for await (const chunk of readable) {
    if (!(chunk instanceof Uint8Array) || chunk.byteLength < 1) {
      throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest stream chunk is invalid");
    }
    if (buffer.byteLength + chunk.byteLength > FRAME_HEADER_BYTES + maxFrameBytes) {
      throw new BrokerError("OUTPUT_LIMIT", "Virtualization guest request frame exceeded the byte limit");
    }
    buffer = Buffer.concat([buffer, Buffer.from(chunk)]);
    if (buffer.byteLength < FRAME_HEADER_BYTES) continue;
    const length = buffer.readUInt32BE(0);
    if (length < 1 || length > maxFrameBytes) {
      throw new BrokerError("OUTPUT_LIMIT", "Virtualization guest request frame length is invalid");
    }
    if (buffer.byteLength < FRAME_HEADER_BYTES + length) continue;
    if (buffer.byteLength !== FRAME_HEADER_BYTES + length) {
      throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest stream contained trailing request data");
    }
    return new Uint8Array(buffer.subarray(FRAME_HEADER_BYTES, FRAME_HEADER_BYTES + length));
  }
  throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest request frame was truncated");
}

async function withDeadline<T>(operation: Promise<T>, deadline: number, message: string): Promise<T> {
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw new BrokerError("TIMEOUT", message);
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<T>((_resolve, reject) => {
        timer = setTimeout(() => reject(new BrokerError("TIMEOUT", message)), remaining);
      })
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function validateOptions(options: VirtualizationGuestBootstrapOptions): void {
  if (options === null || typeof options !== "object" || typeof options.enabled !== "boolean" ||
      options.agent === undefined || options.source === undefined || typeof options.source.accept !== "function" ||
      typeof options.source.close !== "function") {
    throw new Error("Virtualization guest bootstrap options are invalid");
  }
  const maxFrameBytes = options.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES;
  const maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  const connectionTimeoutMs = options.connectionTimeoutMs ?? DEFAULT_CONNECTION_TIMEOUT_MS;
  const maxConnections = options.maxConnections ?? DEFAULT_MAX_CONNECTIONS;
  if (!Number.isSafeInteger(maxFrameBytes) || maxFrameBytes < 256 || maxFrameBytes > DEFAULT_MAX_FRAME_BYTES ||
      !Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 256 || maxResponseBytes > DEFAULT_MAX_RESPONSE_BYTES ||
      !Number.isSafeInteger(connectionTimeoutMs) || connectionTimeoutMs < 1 || connectionTimeoutMs > 120_000 ||
      !Number.isSafeInteger(maxConnections) || maxConnections < 1 || maxConnections > 64) {
    throw new Error("Virtualization guest bootstrap limits are invalid");
  }
}
