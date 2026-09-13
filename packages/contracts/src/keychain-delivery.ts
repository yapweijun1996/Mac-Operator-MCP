export const KEYCHAIN_DELIVERY_PROTOCOL_VERSION = "0.1" as const;

export interface KeychainDeliveryRequest {
  protocolVersion: typeof KEYCHAIN_DELIVERY_PROTOCOL_VERSION;
  challenge: string;
  requestId: string;
  nonce: string;
  keyId: string;
}

export interface KeychainDeliveryChallenge {
  protocolVersion: typeof KEYCHAIN_DELIVERY_PROTOCOL_VERSION;
  type: "challenge";
  challenge: string;
}

export type KeychainDeliveryErrorCode =
  | "INVALID_REQUEST"
  | "REPLAY_DENIED"
  | "KEY_UNAVAILABLE"
  | "INTERNAL_ERROR";

export interface KeychainDeliverySuccess {
  protocolVersion: typeof KEYCHAIN_DELIVERY_PROTOCOL_VERSION;
  ok: true;
  challenge: string;
  requestId: string;
  nonce: string;
  keyId: string;
  keyDigest: string;
  keyBase64: string;
}

export interface KeychainDeliveryFailure {
  protocolVersion: typeof KEYCHAIN_DELIVERY_PROTOCOL_VERSION;
  ok: false;
  challenge: string;
  requestId: string;
  nonce: string;
  errorCode: KeychainDeliveryErrorCode;
}

export type KeychainDeliveryResponse = KeychainDeliverySuccess | KeychainDeliveryFailure;

const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;

export function parseKeychainDeliveryRequest(value: unknown): KeychainDeliveryRequest {
  assertExactKeys(value, ["protocolVersion", "challenge", "requestId", "nonce", "keyId"]);
  const record = value as Record<string, unknown>;
  if (record.protocolVersion !== KEYCHAIN_DELIVERY_PROTOCOL_VERSION ||
      !isIdentifier(record.challenge) || !isIdentifier(record.requestId) || !isIdentifier(record.nonce) || !isIdentifier(record.keyId)) {
    throw new Error("Keychain delivery request is malformed");
  }
  return {
    protocolVersion: KEYCHAIN_DELIVERY_PROTOCOL_VERSION,
    challenge: record.challenge as string,
    requestId: record.requestId as string,
    nonce: record.nonce as string,
    keyId: record.keyId as string
  };
}

export function parseKeychainDeliveryChallenge(value: unknown): KeychainDeliveryChallenge {
  assertExactKeys(value, ["protocolVersion", "type", "challenge"]);
  const record = value as Record<string, unknown>;
  if (record.protocolVersion !== KEYCHAIN_DELIVERY_PROTOCOL_VERSION || record.type !== "challenge" || !isIdentifier(record.challenge)) {
    throw new Error("Keychain delivery challenge is malformed");
  }
  return {
    protocolVersion: KEYCHAIN_DELIVERY_PROTOCOL_VERSION,
    type: "challenge",
    challenge: record.challenge as string
  };
}

export function parseKeychainDeliveryResponse(value: unknown): KeychainDeliveryResponse {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Keychain delivery response is malformed");
  }
  const record = value as Record<string, unknown>;
  if (record.ok === true) {
    assertExactKeys(record, ["protocolVersion", "ok", "challenge", "requestId", "nonce", "keyId", "keyDigest", "keyBase64"]);
    if (record.protocolVersion !== KEYCHAIN_DELIVERY_PROTOCOL_VERSION ||
        !isIdentifier(record.challenge) || !isIdentifier(record.requestId) || !isIdentifier(record.nonce) || !isIdentifier(record.keyId) ||
        typeof record.keyDigest !== "string" || !DIGEST_PATTERN.test(record.keyDigest) ||
        typeof record.keyBase64 !== "string" || record.keyBase64.length > 128 || !BASE64_PATTERN.test(record.keyBase64) ||
        !isCanonical32ByteBase64(record.keyBase64)) {
      throw new Error("Keychain delivery success is malformed");
    }
    return {
      protocolVersion: KEYCHAIN_DELIVERY_PROTOCOL_VERSION,
      ok: true,
      challenge: record.challenge as string,
      requestId: record.requestId as string,
      nonce: record.nonce as string,
      keyId: record.keyId as string,
      keyDigest: record.keyDigest as string,
      keyBase64: record.keyBase64 as string
    };
  }
  assertExactKeys(record, ["protocolVersion", "ok", "challenge", "requestId", "nonce", "errorCode"]);
  if (record.protocolVersion !== KEYCHAIN_DELIVERY_PROTOCOL_VERSION ||
      record.ok !== false || !isIdentifier(record.challenge) || !isIdentifier(record.requestId) || !isIdentifier(record.nonce) ||
      !isKeychainDeliveryErrorCode(record.errorCode)) {
    throw new Error("Keychain delivery failure is malformed");
  }
  return {
    protocolVersion: KEYCHAIN_DELIVERY_PROTOCOL_VERSION,
    ok: false,
    challenge: record.challenge as string,
    requestId: record.requestId as string,
    nonce: record.nonce as string,
    errorCode: record.errorCode
  };
}

function isCanonical32ByteBase64(value: string): boolean {
  const bytes = Buffer.from(value, "base64");
  return bytes.byteLength === 32 && bytes.toString("base64") === value;
}

function isIdentifier(value: unknown): value is string {
  return typeof value === "string" && IDENTIFIER_PATTERN.test(value);
}

function isKeychainDeliveryErrorCode(value: unknown): value is KeychainDeliveryErrorCode {
  return value === "INVALID_REQUEST" || value === "REPLAY_DENIED" || value === "KEY_UNAVAILABLE" || value === "INTERNAL_ERROR";
}

function assertExactKeys(value: unknown, expected: readonly string[]): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Keychain delivery message is malformed");
  }
  const actual = Object.keys(value as Record<string, unknown>).sort();
  const sortedExpected = [...expected].sort();
  if (actual.length !== sortedExpected.length || actual.some((key, index) => key !== sortedExpected[index])) {
    throw new Error("Keychain delivery message contains unexpected fields");
  }
}
