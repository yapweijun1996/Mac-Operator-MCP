import { BrokerError, isCompatibleVersionPair, PROTOCOL_VERSION, SCOPES, type BrokerRequest, type BrokerRevocationEvent, type Scope } from "@mac-operator/contracts";
import { isPlainDataRecord } from "./plain-record.js";

const KNOWN_SCOPES = new Set<Scope>(SCOPES);

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const HEX_64_PATTERN = /^[a-f0-9]{64}$/u;

export function parseBrokerRequest(value: unknown): BrokerRequest {
  if (!isRecord(value)) throw new BrokerError("AUTH_INVALID", "Request envelope must be an object");
  if (!isSafeRequestValue(value)) throw new BrokerError("AUTH_INVALID", "Request envelope contains unsupported values");
  const exactKeys = new Set([
    "protocolVersion", "requestId", "contractVersion", "tool", "arguments", "principal",
    "timestampMs", "nonce", "policyAudience", "policyVersion", "authenticationKeyId", "payloadDigest", "authenticationProof"
  ]);
  if (Object.keys(value).some((key) => !exactKeys.has(key))) {
    throw new BrokerError("AUTH_INVALID", "Request envelope contains an unknown field");
  }
  if (!isCompatibleVersionPair("edge_broker", value.protocolVersion, value.contractVersion)) {
    throw new BrokerError("UNSUPPORTED_CAPABILITY", "Protocol or contract version is not supported");
  }
  for (const field of ["requestId", "tool", "nonce", "policyAudience", "policyVersion", "authenticationKeyId", "payloadDigest", "authenticationProof"] as const) {
    if (typeof value[field] !== "string") throw new BrokerError("AUTH_INVALID", `${field} must be a string`);
  }
  const requestId = value.requestId as string;
  const nonce = value.nonce as string;
  const tool = value.tool as string;
  const payloadDigest = value.payloadDigest as string;
  const authenticationProof = value.authenticationProof as string;
  if (!ID_PATTERN.test(requestId) || !ID_PATTERN.test(nonce) || !ID_PATTERN.test(tool)) {
    throw new BrokerError("AUTH_INVALID", "Request identifiers are malformed");
  }
  if (!HEX_64_PATTERN.test(payloadDigest) || !HEX_64_PATTERN.test(authenticationProof)) {
    throw new BrokerError("AUTH_INVALID", "Authentication fields are malformed");
  }
  if (!isRecord(value.arguments) || !isRecord(value.principal)) {
    throw new BrokerError("AUTH_INVALID", "Arguments and principal must be objects");
  }
  if (!Number.isSafeInteger(value.timestampMs)) throw new BrokerError("AUTH_INVALID", "timestampMs must be an integer");
  const principal = value.principal;
  const principalKeys = new Set(["principalId", "sessionId", "issuer", "audience", "scopes", "issuedAtMs", "expiresAtMs", "edgeId"]);
  if (Object.keys(principal).some((key) => !principalKeys.has(key))) {
    throw new BrokerError("AUTH_INVALID", "Principal contains an unknown field");
  }
  for (const field of ["principalId", "sessionId", "issuer", "audience", "edgeId"] as const) {
    if (typeof principal[field] !== "string" || !ID_PATTERN.test(principal[field])) {
      throw new BrokerError("AUTH_INVALID", `Principal ${field} is malformed`);
    }
  }
  if (!Number.isSafeInteger(principal.issuedAtMs) || !Number.isSafeInteger(principal.expiresAtMs)) {
    throw new BrokerError("AUTH_INVALID", "Principal times must be integers");
  }
  if (!isKnownScopeList(principal.scopes)) {
    throw new BrokerError("AUTH_INVALID", "Principal scopes contain an unknown value");
  }
  // The parser is the trust-boundary handoff. Do not retain caller-owned
  // objects after validation: a later mutation must not swap the arguments,
  // principal, or target fields while authentication and authorization run.
  return freezeRequestSnapshot(value) as BrokerRequest;
}

/** Parse the separate Edge-to-Broker OAuth authority event contract. */
export function parseBrokerRevocationEvent(value: unknown): BrokerRevocationEvent {
  if (!isRecord(value) || Object.keys(value).some((key) => !new Set([
    "protocolVersion", "eventType", "requestId", "nonce", "edgeId", "authenticationKeyId",
    "principalId", "sessionId", "timestampMs", "payloadDigest", "authenticationProof"
  ]).has(key))) {
    throw new BrokerError("AUTH_INVALID", "Revocation event envelope is malformed");
  }
  const event = value as Record<string, unknown>;
  if (event.protocolVersion !== PROTOCOL_VERSION || event.eventType !== "oauth_authority_revoked" ||
      typeof event.requestId !== "string" || !/^edge-revoke:[A-Za-z0-9._:-]{16,128}$/u.test(event.requestId) ||
      typeof event.nonce !== "string" || !/^edge-revoke-nonce:[A-Za-z0-9._:-]{16,128}$/u.test(event.nonce) ||
      typeof event.edgeId !== "string" || !ID_PATTERN.test(event.edgeId) ||
      typeof event.authenticationKeyId !== "string" || !ID_PATTERN.test(event.authenticationKeyId) ||
      typeof event.principalId !== "string" || !ID_PATTERN.test(event.principalId) ||
      typeof event.sessionId !== "string" || !ID_PATTERN.test(event.sessionId) ||
      !Number.isSafeInteger(event.timestampMs) || (event.timestampMs as number) < 0 ||
      typeof event.payloadDigest !== "string" || !HEX_64_PATTERN.test(event.payloadDigest) ||
      typeof event.authenticationProof !== "string" || !HEX_64_PATTERN.test(event.authenticationProof)) {
    throw new BrokerError("AUTH_INVALID", "Revocation event envelope is malformed");
  }
  return freezeRequestSnapshot(value) as BrokerRevocationEvent;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return isPlainDataRecord(value);
}

function isSafeRequestValue(value: unknown): boolean {
  const active = new Set<object>();
  let nodes = 0;
  const visit = (candidate: unknown, depth: number): boolean => {
    if (nodes++ >= 10_000 || depth > 64) return false;
    if (candidate === null || typeof candidate === "string" || typeof candidate === "boolean") return true;
    if (typeof candidate === "number") return Number.isFinite(candidate);
    if (typeof candidate !== "object" || active.has(candidate)) return false;
    if (Array.isArray(candidate)) {
      if (!isPlainDataArray(candidate)) return false;
      active.add(candidate);
      try { return candidate.every((item) => visit(item, depth + 1)); }
      finally { active.delete(candidate); }
    }
    if (!isPlainDataRecord(candidate)) return false;
    active.add(candidate);
    try {
      return Object.keys(candidate).every((key) => visit(candidate[key], depth + 1));
    } catch {
      return false;
    } finally {
      active.delete(candidate);
    }
  };
  return visit(value, 0);
}

function isPlainDataArray(value: readonly unknown[]): boolean {
  try {
    if (Object.getPrototypeOf(value) !== Array.prototype || Object.getOwnPropertySymbols(value).length > 0 ||
        Object.keys(value).length !== value.length) return false;
    const names = Object.getOwnPropertyNames(value);
    if (names.length !== value.length + 1 || !names.includes("length")) return false;
    for (const name of names) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (descriptor === undefined || !("value" in descriptor)) return false;
      if (name !== "length" && (!/^(?:0|[1-9][0-9]*)$/u.test(name) || Number(name) >= value.length)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function isKnownScopeList(value: unknown): value is readonly Scope[] {
  if (!Array.isArray(value) || !isPlainDataArray(value) || value.length > SCOPES.length) return false;
  const seen = new Set<unknown>();
  for (let index = 0; index < value.length; index += 1) {
    const scope = value[index];
    if (seen.has(scope) || typeof scope !== "string" || !KNOWN_SCOPES.has(scope as Scope)) return false;
    seen.add(scope);
  }
  return true;
}

function freezeRequestSnapshot(value: unknown): unknown {
  const clone = (candidate: unknown): unknown => {
    if (candidate === null || typeof candidate !== "object") return candidate;
    if (Array.isArray(candidate)) {
      const result: unknown[] = [];
      for (const item of candidate) result.push(clone(item));
      return Object.freeze(result);
    }
    const result = Object.create(null) as Record<string, unknown>;
    for (const [key, item] of Object.entries(candidate as Record<string, unknown>)) {
      Object.defineProperty(result, key, {
        configurable: false,
        enumerable: true,
        writable: false,
        value: clone(item)
      });
    }
    return Object.freeze(result);
  };
  return clone(value);
}
