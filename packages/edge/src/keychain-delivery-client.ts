import { randomUUID } from "node:crypto";
import { createConnection, type Socket } from "node:net";
import { decodeUtf8Strict, parseJsonStrict, sha256, parseKeychainDeliveryChallenge, parseKeychainDeliveryResponse, type KeychainDeliveryRequest, type KeychainDeliveryResponse } from "@mac-operator/contracts";
import { BrokerError } from "@mac-operator/contracts";
import { validateBrokerSocketTarget } from "./ipc-client.js";

const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;

export interface KeychainDeliveryClientOptions {
  socketPath: string;
  keyId: string;
  expectedDigest: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  requestId?: () => string;
  nonce?: () => string;
}

/** Fetches a configured Edge key without accepting a service or account from the caller. */
export async function loadEdgeAuthenticationKeyFromBroker(options: KeychainDeliveryClientOptions): Promise<Buffer> {
  validateClientOptions(options);
  const requestBase: Omit<KeychainDeliveryRequest, "challenge"> = {
    protocolVersion: "0.1",
    requestId: (options.requestId ?? randomUUID)(),
    nonce: (options.nonce ?? randomUUID)(),
    keyId: options.keyId
  };
  if (!IDENTIFIER_PATTERN.test(requestBase.requestId) || !IDENTIFIER_PATTERN.test(requestBase.nonce)) {
    throw new BrokerError("AUTH_INVALID", "Keychain delivery request identity is malformed");
  }
  const expectedIdentity = await validateBrokerSocketTarget(options.socketPath);
  const exchange = await exchangeKeychainDelivery(
    options.socketPath,
    requestBase,
    expectedIdentity,
    options.timeoutMs ?? 5_000,
    options.maxResponseBytes ?? 8_192
  );
  const raw = exchange.raw;
  let parsed: KeychainDeliveryResponse;
  try {
    parsed = parseKeychainDeliveryResponse(parseJsonStrict(raw));
  } catch {
    throw new BrokerError("AUTH_INVALID", "Keychain delivery response is malformed");
  }
  if (parsed.requestId !== requestBase.requestId || parsed.nonce !== requestBase.nonce) {
    throw new BrokerError("AUTH_INVALID", "Keychain delivery response identity does not match the request");
  }
  if (!parsed.ok) {
    if (parsed.errorCode === "REPLAY_DENIED") throw new BrokerError("REPLAY_DENIED", "Keychain delivery request was replayed");
    if (parsed.errorCode === "KEY_UNAVAILABLE") throw new BrokerError("AUTH_INVALID", "Keychain delivery key is unavailable");
    throw new BrokerError("AUTH_INVALID", "Keychain delivery request was rejected");
  }
  if (parsed.keyId !== requestBase.keyId || parsed.challenge !== exchange.challenge) {
    throw new BrokerError("AUTH_INVALID", "Keychain delivery response key identity does not match the request");
  }
  if (parsed.keyDigest !== options.expectedDigest) {
    throw new BrokerError("AUTH_INVALID", "Keychain delivery key digest does not match startup configuration");
  }
  const key = Buffer.from(parsed.keyBase64, "base64");
  if (key.byteLength !== 32 || parsed.keyBase64 !== key.toString("base64") || sha256(key) !== options.expectedDigest) {
    key.fill(0);
    throw new BrokerError("AUTH_INVALID", "Keychain delivery key bytes failed validation");
  }
  return key;
}

function validateClientOptions(options: KeychainDeliveryClientOptions): void {
  if (!IDENTIFIER_PATTERN.test(options.keyId)) throw new BrokerError("AUTH_INVALID", "Keychain delivery key ID is malformed");
  if (!DIGEST_PATTERN.test(options.expectedDigest)) throw new BrokerError("AUTH_INVALID", "Keychain delivery digest is malformed");
  if (!Number.isSafeInteger(options.timeoutMs ?? 5_000) || (options.timeoutMs ?? 5_000) < 100 || (options.timeoutMs ?? 5_000) > 30_000 ||
      !Number.isSafeInteger(options.maxResponseBytes ?? 8_192) || (options.maxResponseBytes ?? 8_192) < 256 || (options.maxResponseBytes ?? 8_192) > 65_536) {
    throw new BrokerError("AUTH_INVALID", "Keychain delivery limits are invalid");
  }
}

function exchangeKeychainDelivery(
  socketPath: string,
  requestBase: Omit<KeychainDeliveryRequest, "challenge">,
  expectedIdentity: { dev: number; ino: number },
  timeoutMs: number,
  maxResponseBytes: number
): Promise<{ raw: string; challenge: string }> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    let settled = false;
    let total = 0;
    let buffer = Buffer.alloc(0);
    let challenge: string | undefined;
    let requestSent = false;
    let ready = false;
    const processBuffer = () => {
      while (!settled) {
        const newline = buffer.indexOf(0x0a);
        if (newline === -1) return;
        let line: string;
        try { line = decodeUtf8Strict(buffer.subarray(0, newline)).trim(); }
        catch {
          finish(new BrokerError("AUTH_INVALID", "Keychain delivery response is not valid UTF-8"));
          return;
        }
        buffer = buffer.subarray(newline + 1);
        if (!requestSent) {
          try {
            challenge = parseKeychainDeliveryChallenge(parseJsonStrict(line)).challenge;
          } catch {
            finish(new BrokerError("AUTH_INVALID", "Keychain delivery challenge is malformed"));
            return;
          }
          const request: KeychainDeliveryRequest = { ...requestBase, challenge };
          socket.write(`${JSON.stringify(request)}\n`);
          requestSent = true;
          continue;
        }
        if (buffer.some((byte) => byte !== 0x09 && byte !== 0x0d && byte !== 0x20)) {
          finish(new BrokerError("AUTH_INVALID", "Keychain delivery response contains trailing data"));
          return;
        }
        finish(undefined, line);
      }
    };
    const finish = (error?: Error, value?: string) => {
      if (settled) return;
      settled = true;
      buffer.fill(0);
      socket.destroy();
      if (error) reject(error);
      else if (challenge === undefined) reject(new BrokerError("AUTH_INVALID", "Keychain delivery challenge is unavailable"));
      else resolve({ raw: value ?? "", challenge });
    };
    socket.setTimeout(timeoutMs, () => finish(new BrokerError("TIMEOUT", "Keychain delivery timed out", true)));
    socket.on("connect", () => {
      void validateBrokerSocketTarget(socketPath).then((after) => {
        if (after.dev !== expectedIdentity.dev || after.ino !== expectedIdentity.ino) {
          finish(new BrokerError("AUTH_INVALID", "Keychain delivery socket target changed while connecting"));
          return;
        }
        ready = true;
        processBuffer();
      }).catch(() => finish(new BrokerError("AUTH_INVALID", "Keychain delivery socket target could not be revalidated")));
    });
    socket.on("data", (chunk: Buffer) => {
      total += chunk.byteLength;
      if (total > maxResponseBytes) {
        finish(new BrokerError("OUTPUT_LIMIT", "Keychain delivery response exceeded the byte limit"));
        return;
      }
      const next = Buffer.allocUnsafe(buffer.byteLength + chunk.byteLength);
      buffer.copy(next);
      chunk.copy(next, buffer.byteLength);
      buffer.fill(0);
      buffer = next;
      if (ready) processBuffer();
    });
    socket.on("error", () => finish(new BrokerError("EXECUTION_FAILED", "Keychain delivery transport failed", true)));
    socket.on("end", () => {
      if (!settled) finish(new BrokerError("AUTH_INVALID", "Keychain delivery response ended prematurely"));
    });
  });
}
