import { createRequire } from "node:module";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { BrokerError } from "@mac-operator/contracts";
import type {
  VirtualizationGuestConnectionSource,
  VirtualizationGuestStream
} from "./virtualization-guest-bootstrap.js";

const require = createRequire(import.meta.url);
const MAX_PORT = 65_535;
const MAX_CONNECTIONS = 8;
const MAX_CHUNK_BYTES = 4 * 1024 * 1024 + 64 * 1024;
const MAX_TIMEOUT_MS = 120_000;

export interface LinuxGuestVsockBinding {
  createGuestVsockListener(port: number, backlog: number): unknown;
  acceptGuestVsockConnection(listener: unknown, timeoutMs: number): Promise<unknown | null>;
  readGuestVsockChunk(connection: unknown, maxBytes: number, timeoutMs: number): Promise<Buffer | null>;
  writeGuestVsockChunk(connection: unknown, frame: Buffer, timeoutMs: number): Promise<void>;
  closeGuestVsockConnection(connection: unknown): void;
  closeGuestVsockListener(listener: unknown): void;
}

export interface LinuxGuestVsockSourceOptions {
  /** Fixed startup-owned port; never supplied by an MCP request. */
  port: number;
  maxConnections?: number;
  maxChunkBytes?: number;
  ioTimeoutMs?: number;
  /** Test seam; production loads the Linux-only native adapter. */
  binding?: LinuxGuestVsockBinding;
}

/**
 * Loads the guest-only AF_VSOCK N-API adapter from the immutable Linux image.
 * The macOS Broker must never load this artifact.
 */
export function loadLinuxGuestVsockBinding(): LinuxGuestVsockBinding {
  if (process.platform !== "linux" || process.arch !== "arm64") {
    throw new BrokerError("POLICY_DENIED", "Guest AF_VSOCK adapter requires Linux ARM64");
  }
  try {
    const modulePath = require.resolve("./virtualization_guest_vsock_linux.node");
    const before = readArtifact(modulePath);
    const native = require(modulePath) as Partial<LinuxGuestVsockBinding>;
    const after = readArtifact(modulePath);
    if (before.digest !== after.digest || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
        typeof native.createGuestVsockListener !== "function" ||
        typeof native.acceptGuestVsockConnection !== "function" ||
        typeof native.readGuestVsockChunk !== "function" ||
        typeof native.writeGuestVsockChunk !== "function" ||
        typeof native.closeGuestVsockConnection !== "function" ||
        typeof native.closeGuestVsockListener !== "function") {
      throw new Error("Guest AF_VSOCK native artifact changed or is incompatible");
    }
    return native as LinuxGuestVsockBinding;
  } catch {
    throw new BrokerError("POLICY_DENIED", "Guest AF_VSOCK native adapter is unavailable");
  }
}

/**
 * Adapts the guest's fixed AF_VSOCK listener to the transport-independent
 * authenticated bootstrap. The native layer accepts only the host CID.
 */
export function createLinuxGuestVsockConnectionSource(
  options: LinuxGuestVsockSourceOptions
): VirtualizationGuestConnectionSource {
  validateOptions(options);
  const binding = options.binding ?? loadLinuxGuestVsockBinding();
  const maxConnections = options.maxConnections ?? MAX_CONNECTIONS;
  const maxChunkBytes = options.maxChunkBytes ?? 64 * 1024;
  const ioTimeoutMs = options.ioTimeoutMs ?? 15_000;
  const listener = binding.createGuestVsockListener(options.port, maxConnections);
  let closed = false;
  let activeConnections = 0;

  return {
    accept: async (signal): Promise<VirtualizationGuestStream | null> => {
      while (!closed && !signal.aborted) {
        let connection: unknown | null;
        try {
          const pending = binding.acceptGuestVsockConnection(listener, ioTimeoutMs);
          connection = await raceAbortWithCleanup(
            pending,
            signal,
            (value) => {
              if (value !== null && value !== undefined) binding.closeGuestVsockConnection(value);
            },
            "Guest AF_VSOCK accept was cancelled"
          );
        } catch (error) {
          if (signal.aborted) throw new BrokerError("CANCELLED", "Guest AF_VSOCK accept was cancelled");
          if (closed) return null;
          throw error;
        }
        if (connection === null) continue;
        if (activeConnections >= maxConnections) {
          binding.closeGuestVsockConnection(connection);
          continue;
        }
        activeConnections += 1;
        return new LinuxGuestVsockStream(binding, connection, maxChunkBytes, ioTimeoutMs, () => {
          activeConnections = Math.max(0, activeConnections - 1);
        });
      }
      if (signal.aborted) throw new BrokerError("CANCELLED", "Guest AF_VSOCK accept was cancelled");
      return null;
    },
    close: async (): Promise<void> => {
      if (closed) return;
      closed = true;
      binding.closeGuestVsockListener(listener);
    }
  };
}

class LinuxGuestVsockStream implements VirtualizationGuestStream {
  private closed = false;
  readonly readable: AsyncIterable<Uint8Array> = this.readChunks();

  constructor(
    private readonly binding: LinuxGuestVsockBinding,
    private readonly connection: unknown,
    private readonly maxChunkBytes: number,
    private readonly ioTimeoutMs: number,
    private readonly onClose: () => void
  ) {}

  async write(frame: Uint8Array): Promise<void> {
    this.assertOpen();
    if (!(frame instanceof Uint8Array) || frame.byteLength < 1 || frame.byteLength > MAX_CHUNK_BYTES) {
      throw new BrokerError("OUTPUT_LIMIT", "Guest AF_VSOCK response frame exceeded the byte limit");
    }
    await this.binding.writeGuestVsockChunk(this.connection, Buffer.from(frame), this.ioTimeoutMs);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.binding.closeGuestVsockConnection(this.connection);
    this.onClose();
  }

  private async *readChunks(): AsyncIterable<Uint8Array> {
    while (!this.closed) {
      const chunk = await this.binding.readGuestVsockChunk(this.connection, this.maxChunkBytes, this.ioTimeoutMs);
      if (chunk === null) return;
      if (!Buffer.isBuffer(chunk) || chunk.byteLength < 1 || chunk.byteLength > this.maxChunkBytes) {
        throw new BrokerError("PRECONDITION_FAILED", "Guest AF_VSOCK request chunk is malformed");
      }
      yield new Uint8Array(chunk);
    }
  }

  private assertOpen(): void {
    if (this.closed) throw new BrokerError("CANCELLED", "Guest AF_VSOCK connection is closed");
  }
}

function validateOptions(options: LinuxGuestVsockSourceOptions): void {
  if (options === null || typeof options !== "object" ||
      !Number.isSafeInteger(options.port) || options.port < 1 || options.port > MAX_PORT ||
      (options.maxConnections !== undefined && (!Number.isSafeInteger(options.maxConnections) || options.maxConnections < 1 || options.maxConnections > MAX_CONNECTIONS)) ||
      (options.maxChunkBytes !== undefined && (!Number.isSafeInteger(options.maxChunkBytes) || options.maxChunkBytes < 256 || options.maxChunkBytes > MAX_CHUNK_BYTES)) ||
      (options.ioTimeoutMs !== undefined && (!Number.isSafeInteger(options.ioTimeoutMs) || options.ioTimeoutMs < 1 || options.ioTimeoutMs > MAX_TIMEOUT_MS))) {
    throw new Error("Guest AF_VSOCK source options are invalid");
  }
}

function readArtifact(path: string): { dev: number; ino: number; size: number; digest: string } {
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink() || before.uid !== 0 || (before.mode & 0o022) !== 0 ||
      before.size < 1 || before.size > 16 * 1024 * 1024) {
    throw new Error("Guest AF_VSOCK native artifact is invalid");
  }
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(descriptor);
    if (!opened.isFile() || opened.uid !== 0 || (opened.mode & 0o022) !== 0 ||
        before.dev !== opened.dev || before.ino !== opened.ino || before.size !== opened.size) {
      throw new Error("Guest AF_VSOCK native artifact changed while opening");
    }
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (opened.dev !== after.dev || opened.ino !== after.ino || opened.size !== after.size || bytes.byteLength !== opened.size) {
      throw new Error("Guest AF_VSOCK native artifact changed while reading");
    }
    return {
      dev: after.dev,
      ino: after.ino,
      size: after.size,
      digest: createHash("sha256").update(bytes).digest("hex")
    };
  } finally {
    closeSync(descriptor);
  }
}

async function raceAbortWithCleanup<T>(
  operation: Promise<T>,
  signal: AbortSignal,
  cleanupLateResult: (value: T) => void,
  message: string
): Promise<T> {
  if (signal.aborted) {
    void operation.then(cleanupLateResult, () => undefined);
    throw new BrokerError("CANCELLED", message);
  }
  let rejectAbort: ((error: BrokerError) => void) | undefined;
  let settled = false;
  const aborted = new Promise<T>((_resolve, reject) => {
    rejectAbort = reject;
  });
  const onAbort = (): void => rejectAbort?.(new BrokerError("CANCELLED", message));
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    const value = await Promise.race([operation, aborted]);
    settled = true;
    return value;
  } finally {
    signal.removeEventListener("abort", onAbort);
    if (!settled) void operation.then(cleanupLateResult, () => undefined);
  }
}
