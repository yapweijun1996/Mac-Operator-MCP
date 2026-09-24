import { Socket } from "node:net";
import { BrokerError, parseJsonUtf8Strict } from "@mac-operator/contracts";
import {
  authenticateAuthorityControlCommand,
  signAuthorityControlResponse,
  type AuthorityControlIpcResponse,
  type UnsignedAuthorityControlCommand
} from "./authority-control-ipc.js";
import { MacOsNativePeerIpcServer, type NativePeerPolicy } from "./native-peer-ipc-server.js";

const DEFAULT_MAX_REQUEST_BYTES = 64 * 1024;
const DEFAULT_MAX_REQUEST_AGE_MS = 60_000;
const DEFAULT_ALLOWED_CLOCK_SKEW_MS = 5_000;
const DEFAULT_SOCKET_TIMEOUT_MS = 15_000;

export interface AuthorityControlProxyServerOptions {
  socketPath: string;
  peerPolicy: NativePeerPolicy;
  upstream: AuthorityControlProxyUpstream;
  authenticationKey: Buffer;
  maxRequestBytes?: number;
  maxRequestAgeMs?: number;
  allowedClockSkewMs?: number;
  socketTimeoutMs?: number;
  now?: () => number;
}

export type AuthorityControlProxyUpstream = {
  execute(command: UnsignedAuthorityControlCommand): Promise<Extract<AuthorityControlIpcResponse, { ok: true }>>;
};

/**
 * Owner-only front door for the stable operator LaunchAgent. The operator
 * process is the only peer allowed on the Broker authority socket; interactive
 * CLI callers reach it through this second owner-only socket. The proxy never
 * mutates Broker state and forwards only a fully authenticated command.
 */
export class AuthorityControlProxyServer {
  private readonly authenticationKey: Buffer;
  private readonly maxRequestBytes: number;
  private readonly maxRequestAgeMs: number;
  private readonly allowedClockSkewMs: number;
  private readonly socketTimeoutMs: number;
  private readonly now: () => number;
  private readonly nativeTransport: MacOsNativePeerIpcServer;
  private closed = false;

  constructor(private readonly options: AuthorityControlProxyServerOptions) {
    if (options.peerPolicy.allowedProcessIdentity !== undefined) {
      throw new Error("Authority control proxy accepts owner CLI peers, not a fixed process identity");
    }
    if (options.authenticationKey.byteLength < 32) throw new Error("Authority control proxy key is too short");
    this.authenticationKey = Buffer.from(options.authenticationKey);
    this.maxRequestBytes = bounded(options.maxRequestBytes ?? DEFAULT_MAX_REQUEST_BYTES, 256, 1_048_576, "request bytes");
    this.maxRequestAgeMs = bounded(options.maxRequestAgeMs ?? DEFAULT_MAX_REQUEST_AGE_MS, 1, 600_000, "request age");
    this.allowedClockSkewMs = bounded(options.allowedClockSkewMs ?? DEFAULT_ALLOWED_CLOCK_SKEW_MS, 0, 60_000, "clock skew");
    this.socketTimeoutMs = bounded(options.socketTimeoutMs ?? DEFAULT_SOCKET_TIMEOUT_MS, 1, 600_000, "socket timeout");
    this.now = options.now ?? Date.now;
    this.nativeTransport = new MacOsNativePeerIpcServer({
      socketPath: options.socketPath,
      peerPolicy: options.peerPolicy,
      onSocket: (socket) => this.handleSocket(socket)
    });
  }

  async listen(): Promise<void> {
    if (this.closed) throw new Error("Authority control proxy is closed");
    await this.nativeTransport.listen();
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    try {
      await this.nativeTransport.close();
    } finally {
      this.authenticationKey.fill(0);
    }
  }

  private handleSocket(socket: Socket): void {
    socket.setTimeout(this.socketTimeoutMs, () => socket.destroy());
    let total = 0;
    const chunks: Buffer[] = [];
    let handled = false;
    socket.on("data", (chunk: Buffer) => {
      if (handled) return;
      total += chunk.byteLength;
      if (total > this.maxRequestBytes) {
        handled = true;
        socket.destroy();
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline < 0) return;
      handled = true;
      socket.pause();
      void this.forward(combined.subarray(0, newline), combined.subarray(newline + 1), socket);
    });
  }

  private async forward(frame: Buffer, trailing: Buffer, socket: Socket): Promise<void> {
    let command: UnsignedAuthorityControlCommand | undefined;
    try {
      const raw = parseJsonUtf8Strict(frame);
      command = authenticateAuthorityControlCommand(
        raw,
        this.authenticationKey,
        this.now(),
        this.maxRequestAgeMs,
        this.allowedClockSkewMs
      );
      if (trailing.some((byte) => !isAsciiWhitespace(byte))) {
        throw new BrokerError("PRECONDITION_FAILED", "Authority control proxy request contained trailing data");
      }
      const upstream = await this.options.upstream.execute(command);
      writeResponse(socket, signAuthorityControlResponse(upstream, command, this.authenticationKey));
    } catch (error) {
      if (command === undefined) {
        socket.destroy();
        return;
      }
      const brokerError = error instanceof BrokerError
        ? error
        : new BrokerError("EXECUTION_FAILED", "Authority control proxy forwarding failed", true);
      const failure: AuthorityControlIpcResponse = signAuthorityControlResponse({
        ok: false,
        result_class: brokerError.errorClass,
        error: { message: brokerError.message, retryable: brokerError.retryable },
        responseProof: ""
      }, command, this.authenticationKey);
      writeResponse(socket, failure);
    }
  }
}

function bounded(value: number, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`Authority control proxy ${label} is invalid`);
  }
  return value;
}

function writeResponse(socket: Socket, response: AuthorityControlIpcResponse): void {
  if (!socket.destroyed) socket.end(`${JSON.stringify(response)}\n`);
}

function isAsciiWhitespace(byte: number): boolean {
  return byte === 0x09 || byte === 0x0a || byte === 0x0d || byte === 0x20;
}
