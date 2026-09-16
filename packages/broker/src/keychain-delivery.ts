import { randomBytes } from "node:crypto";
import { BrokerError, decodeUtf8Strict, parseJsonStrict, sha256, parseKeychainDeliveryRequest, type KeychainDeliveryFailure, type KeychainDeliveryRequest, type KeychainDeliveryResponse, type KeychainDeliverySuccess } from "@mac-operator/contracts";
import type { Socket } from "node:net";
import { loadKeychainAuthenticationKey } from "./credentials.js";
import { MacOsNativePeerIpcServer, type NativePeerIpcServerOptions } from "./native-peer-ipc-server.js";
import { validateKeychainCoordinates } from "./peer-credentials.js";
import type { BrokerStore } from "./persistence.js";
import type { RuntimeChannel } from "./runtime.js";

const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const INVALID_REQUEST_ID = "invalid-request";
const INVALID_NONCE = "invalid-nonce";
const INVALID_CHALLENGE = "invalid-challenge";

export interface KeychainDeliveryServerOptions extends Omit<NativePeerIpcServerOptions, "onSocket"> {
  service: string;
  account: string;
  keyId: string;
  keyDigest: string;
  maxRequestBytes?: number;
  requestTimeoutMs?: number;
  /** Broker-owned durable replay admission; memory-only guards are rejected. */
  replayGuard: KeychainDeliveryReplayGuard;
  replayTtlMs?: number;
}

export interface KeychainDeliveryReplayGuard {
  /** Marker proving admission is persisted outside this process. */
  readonly durable: true;
  admit(input: {
    requestId: string;
    nonce: string;
    acceptedAtMs: number;
    expiresAtMs: number;
  }): void;
}

/** Durable replay adapter used by the production Broker startup path. */
export class BrokerStoreKeychainDeliveryReplayGuard implements KeychainDeliveryReplayGuard {
  readonly durable = true as const;

  constructor(private readonly store: BrokerStore) {}

  admit(input: {
    requestId: string;
    nonce: string;
    acceptedAtMs: number;
    expiresAtMs: number;
  }): void {
    this.store.admitKeychainDeliveryRequest(input);
  }
}

/**
 * Delivers one configured Broker Keychain key over a native peer-authenticated
 * local socket. The peer policy is part of the constructor contract; request
 * arguments can select neither the Keychain item nor the authorization scope.
 */
export class KeychainDeliveryServer implements RuntimeChannel {
  private readonly transport: MacOsNativePeerIpcServer;
  private readonly maxRequestBytes: number;
  private readonly requestTimeoutMs: number;
  private readonly replayTtlMs: number;
  private key: Buffer | undefined;
  private listening = false;

  constructor(private readonly options: KeychainDeliveryServerOptions) {
    validateKeychainCoordinates(options.service, options.account);
    if (!IDENTIFIER_PATTERN.test(options.keyId)) throw new Error("Keychain delivery key ID is invalid");
    if (!DIGEST_PATTERN.test(options.keyDigest)) throw new Error("Keychain delivery key digest is invalid");
    if (options.peerPolicy.allowedProcessIdentity === undefined) {
      throw new Error("Keychain delivery requires an explicit native peer process identity");
    }
    if (options.replayGuard === null || typeof options.replayGuard !== "object" ||
        options.replayGuard.durable !== true || typeof options.replayGuard.admit !== "function") {
      throw new Error("Keychain delivery requires a durable replay guard");
    }
    this.maxRequestBytes = options.maxRequestBytes ?? 8_192;
    this.requestTimeoutMs = options.requestTimeoutMs ?? 5_000;
    this.replayTtlMs = options.replayTtlMs ?? 5 * 60_000;
    if (!Number.isSafeInteger(this.maxRequestBytes) || this.maxRequestBytes < 256 || this.maxRequestBytes > 65_536 ||
        !Number.isSafeInteger(this.requestTimeoutMs) || this.requestTimeoutMs < 100 || this.requestTimeoutMs > 30_000 ||
        !Number.isSafeInteger(this.replayTtlMs) || this.replayTtlMs < 1_000 || this.replayTtlMs > 30 * 60_000) {
      throw new Error("Keychain delivery limits are invalid");
    }
    this.transport = new MacOsNativePeerIpcServer({
      ...options,
      onSocket: (socket) => this.handleSocket(socket)
    });
  }

  async listen(): Promise<void> {
    if (this.listening || this.key !== undefined) throw new Error("Keychain delivery server is already running");
    const key = await loadKeychainAuthenticationKey(this.options.service, this.options.account);
    try {
      if (sha256(key) !== this.options.keyDigest) throw new Error("Keychain delivery key digest precondition failed");
      this.key = Buffer.from(key);
      await this.transport.listen();
      this.listening = true;
    } catch (error) {
      key.fill(0);
      this.key?.fill(0);
      this.key = undefined;
      throw error;
    } finally {
      key.fill(0);
    }
  }

  async close(): Promise<void> {
    const shouldCloseTransport = this.listening;
    this.listening = false;
    try {
      if (shouldCloseTransport) await this.transport.close();
    } finally {
      this.key?.fill(0);
      this.key = undefined;
    }
  }

  private handleSocket(socket: Socket): void {
    socket.setTimeout(this.requestTimeoutMs, () => socket.destroy());
    const challenge = randomBytes(32).toString("base64url");
    socket.write(`${JSON.stringify({ protocolVersion: "0.1", type: "challenge", challenge })}\n`);
    let total = 0;
    let chunks: Buffer[] = [];
    let handled = false;
    socket.on("data", (chunk: Buffer) => {
      if (handled) return;
      total += chunk.byteLength;
      if (total > this.maxRequestBytes) {
        handled = true;
        this.writeResponse(socket, this.failure("INVALID_REQUEST", undefined, challenge));
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      handled = true;
      socket.pause();
      const trailing = combined.subarray(newline + 1);
      if (trailing.some((byte) => byte !== 0x09 && byte !== 0x0d && byte !== 0x20)) {
        this.writeResponse(socket, this.failure("INVALID_REQUEST", undefined, challenge));
        return;
      }
      let body: string;
      try { body = decodeUtf8Strict(combined.subarray(0, newline)); }
      catch {
        this.writeResponse(socket, this.failure("INVALID_REQUEST", undefined, challenge));
        return;
      }
      chunks = [];
      void this.respond(socket, body, challenge);
    });
  }

  private async respond(socket: Socket, body: string, challenge: string): Promise<void> {
    let request: KeychainDeliveryRequest;
    try {
      request = parseKeychainDeliveryRequest(parseJsonStrict(body));
    } catch {
      this.writeResponse(socket, this.failure("INVALID_REQUEST", undefined, challenge));
      return;
    }
    if (request.challenge !== challenge) {
      this.writeResponse(socket, this.failure("INVALID_REQUEST", request, challenge));
      return;
    }
    if (request.keyId !== this.options.keyId) {
      this.writeResponse(socket, this.failure("INVALID_REQUEST", request, challenge));
      return;
    }
    const acceptedAtMs = Date.now();
    try {
      this.options.replayGuard.admit({
        requestId: request.requestId,
        nonce: request.nonce,
        acceptedAtMs,
        expiresAtMs: acceptedAtMs + this.replayTtlMs
      });
    } catch (error) {
      const errorClass = error instanceof BrokerError ? error.errorClass : undefined;
      this.writeResponse(socket, this.failure(
        errorClass === "REPLAY_DENIED" ? "REPLAY_DENIED" : "INTERNAL_ERROR",
        request,
        challenge
      ));
      return;
    }
    const key = this.key;
    if (key === undefined) {
      this.writeResponse(socket, this.failure("KEY_UNAVAILABLE", request, challenge));
      return;
    }
    const response: KeychainDeliverySuccess = {
      protocolVersion: "0.1",
      ok: true,
      challenge,
      requestId: request.requestId,
      nonce: request.nonce,
      keyId: this.options.keyId,
      keyDigest: this.options.keyDigest,
      keyBase64: key.toString("base64")
    };
    this.writeResponse(socket, response);
  }

  private failure(
    errorCode: KeychainDeliveryFailure["errorCode"],
    request?: KeychainDeliveryRequest,
    challenge = INVALID_CHALLENGE
  ): KeychainDeliveryFailure {
    return {
      protocolVersion: "0.1",
      ok: false,
      challenge,
      requestId: request?.requestId ?? INVALID_REQUEST_ID,
      nonce: request?.nonce ?? INVALID_NONCE,
      errorCode
    };
  }

  private writeResponse(socket: Socket, response: KeychainDeliveryResponse): void {
    if (!socket.destroyed) socket.end(`${JSON.stringify(response)}\n`);
  }
}
