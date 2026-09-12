import { BrokerError, CONTRACT_VERSION, PROTOCOL_VERSION, SCOPES, type BrokerRequest, type Scope } from "@mac-operator/contracts";

const KNOWN_SCOPES = new Set<Scope>(SCOPES);

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const HEX_64_PATTERN = /^[a-f0-9]{64}$/u;

export function parseBrokerRequest(value: unknown): BrokerRequest {
  if (!isRecord(value)) throw new BrokerError("AUTH_INVALID", "Request envelope must be an object");
  const exactKeys = new Set([
    "protocolVersion", "requestId", "contractVersion", "tool", "arguments", "principal",
    "timestampMs", "nonce", "policyAudience", "policyVersion", "authenticationKeyId", "payloadDigest", "authenticationProof"
  ]);
  if (Object.keys(value).some((key) => !exactKeys.has(key))) {
    throw new BrokerError("AUTH_INVALID", "Request envelope contains an unknown field");
  }
  if (value.protocolVersion !== PROTOCOL_VERSION || value.contractVersion !== CONTRACT_VERSION) {
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
  if (!Array.isArray(principal.scopes) || principal.scopes.some((scope) => typeof scope !== "string" || !KNOWN_SCOPES.has(scope as Scope))) {
    throw new BrokerError("AUTH_INVALID", "Principal scopes contain an unknown value");
  }
  return value as unknown as BrokerRequest;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
