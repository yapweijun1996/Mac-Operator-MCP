import { createHmac, timingSafeEqual } from "node:crypto";
import { canonicalJsonUtf8, sha256 } from "./canonical-json.js";
import type {
  AuthenticatedBrokerResponse,
  AuthenticatedBrokerRevocationResponse,
  BrokerRequest,
  BrokerResult,
  BrokerRevocationEvent,
  BrokerRevocationResult,
  UnsignedBrokerRequest,
  UnsignedBrokerRevocationEvent
} from "./types.js";

const REQUEST_PROOF_DOMAIN = "mac-operator-request-v0.1\0";
const RESPONSE_PROOF_DOMAIN = "mac-operator-response-v0.1\0";
const REVOCATION_EVENT_PROOF_DOMAIN = "mac-operator-revocation-event-v0.1\0";
const REVOCATION_RESPONSE_PROOF_DOMAIN = "mac-operator-revocation-response-v0.1\0";

export function requestPayloadDigest(request: UnsignedBrokerRequest): string {
  return sha256(canonicalJsonUtf8(request));
}

export function requestAuthenticationProof(payloadDigest: string, key: Buffer): string {
  return createHmac("sha256", key).update(REQUEST_PROOF_DOMAIN, "utf8").update(payloadDigest, "utf8").digest("hex");
}

export function signBrokerResponse(
  request: BrokerRequest,
  response: BrokerResult,
  key: Buffer
): AuthenticatedBrokerResponse {
  const responseDigest = sha256(canonicalJsonUtf8({
    protocolVersion: request.protocolVersion,
    requestPayloadDigest: request.payloadDigest,
    authenticationKeyId: request.authenticationKeyId,
    response
  }));
  return {
    protocolVersion: request.protocolVersion,
    requestPayloadDigest: request.payloadDigest,
    authenticationKeyId: request.authenticationKeyId,
    responseDigest,
    authenticationProof: createHmac("sha256", key)
      .update(RESPONSE_PROOF_DOMAIN, "utf8")
      .update(responseDigest, "utf8")
      .digest("hex"),
    response
  };
}

export function verifyBrokerResponse(
  request: BrokerRequest,
  envelope: AuthenticatedBrokerResponse,
  key: Buffer
): boolean {
  try {
    if (
      envelope.protocolVersion !== request.protocolVersion ||
      envelope.requestPayloadDigest !== request.payloadDigest ||
      envelope.authenticationKeyId !== request.authenticationKeyId
    ) return false;
    const expectedDigest = sha256(canonicalJsonUtf8({
      protocolVersion: envelope.protocolVersion,
      requestPayloadDigest: envelope.requestPayloadDigest,
      authenticationKeyId: envelope.authenticationKeyId,
      response: envelope.response
    }));
    if (!safeEqualHex(envelope.responseDigest, expectedDigest)) return false;
    const expectedProof = createHmac("sha256", key)
      .update(RESPONSE_PROOF_DOMAIN, "utf8")
      .update(expectedDigest, "utf8")
      .digest("hex");
    return safeEqualHex(envelope.authenticationProof, expectedProof);
  } catch {
    return false;
  }
}

export function signRequest(request: UnsignedBrokerRequest, key: Buffer): BrokerRequest {
  const payloadDigest = requestPayloadDigest(request);
  return {
    ...request,
    payloadDigest,
    authenticationProof: requestAuthenticationProof(payloadDigest, key)
  };
}

export function verifyRequestAuthentication(request: BrokerRequest, key: Buffer): boolean {
  const { payloadDigest, authenticationProof, ...unsigned } = request;
  const actualDigest = requestPayloadDigest(unsigned);
  if (!safeEqualHex(payloadDigest, actualDigest)) return false;
  const expectedProof = requestAuthenticationProof(actualDigest, key);
  return safeEqualHex(authenticationProof, expectedProof);
}

export function revocationEventPayloadDigest(event: UnsignedBrokerRevocationEvent): string {
  return sha256(canonicalJsonUtf8(event));
}

export function revocationEventAuthenticationProof(payloadDigest: string, key: Buffer): string {
  return createHmac("sha256", key)
    .update(REVOCATION_EVENT_PROOF_DOMAIN, "utf8")
    .update(payloadDigest, "utf8")
    .digest("hex");
}

export function signBrokerRevocationEvent(event: UnsignedBrokerRevocationEvent, key: Buffer): BrokerRevocationEvent {
  const payloadDigest = revocationEventPayloadDigest(event);
  return {
    ...event,
    payloadDigest,
    authenticationProof: revocationEventAuthenticationProof(payloadDigest, key)
  };
}

export function verifyBrokerRevocationEvent(event: BrokerRevocationEvent, key: Buffer): boolean {
  try {
    const { payloadDigest, authenticationProof, ...unsigned } = event;
    const actualDigest = revocationEventPayloadDigest(unsigned);
    return safeEqualHex(payloadDigest, actualDigest) &&
      safeEqualHex(authenticationProof, revocationEventAuthenticationProof(actualDigest, key));
  } catch {
    return false;
  }
}

export function signBrokerRevocationResponse(
  event: BrokerRevocationEvent,
  response: BrokerRevocationResult,
  key: Buffer
): AuthenticatedBrokerRevocationResponse {
  const responseDigest = sha256(canonicalJsonUtf8({
    protocolVersion: event.protocolVersion,
    requestPayloadDigest: event.payloadDigest,
    authenticationKeyId: event.authenticationKeyId,
    response
  }));
  return {
    protocolVersion: event.protocolVersion,
    requestPayloadDigest: event.payloadDigest,
    authenticationKeyId: event.authenticationKeyId,
    responseDigest,
    authenticationProof: createHmac("sha256", key)
      .update(REVOCATION_RESPONSE_PROOF_DOMAIN, "utf8")
      .update(responseDigest, "utf8")
      .digest("hex"),
    response
  };
}

export function verifyBrokerRevocationResponse(
  event: BrokerRevocationEvent,
  envelope: AuthenticatedBrokerRevocationResponse,
  key: Buffer
): boolean {
  try {
    if (
      envelope.protocolVersion !== event.protocolVersion ||
      envelope.requestPayloadDigest !== event.payloadDigest ||
      envelope.authenticationKeyId !== event.authenticationKeyId
    ) return false;
    const expectedDigest = sha256(canonicalJsonUtf8({
      protocolVersion: envelope.protocolVersion,
      requestPayloadDigest: envelope.requestPayloadDigest,
      authenticationKeyId: envelope.authenticationKeyId,
      response: envelope.response
    }));
    if (!safeEqualHex(envelope.responseDigest, expectedDigest)) return false;
    return safeEqualHex(envelope.authenticationProof, createHmac("sha256", key)
      .update(REVOCATION_RESPONSE_PROOF_DOMAIN, "utf8")
      .update(expectedDigest, "utf8")
      .digest("hex"));
  } catch {
    return false;
  }
}

function safeEqualHex(left: string, right: string): boolean {
  if (!/^[a-f0-9]+$/u.test(left) || !/^[a-f0-9]+$/u.test(right)) return false;
  const leftBytes = Buffer.from(left, "hex");
  const rightBytes = Buffer.from(right, "hex");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}
