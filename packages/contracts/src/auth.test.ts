import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import {
  canonicalJson,
  requestPayloadDigest,
  signBrokerRevocationEvent,
  signBrokerRevocationResponse,
  signBrokerResponse,
  signRequest,
  verifyBrokerRevocationEvent,
  verifyBrokerRevocationResponse,
  verifyBrokerResponse,
  verifyRequestAuthentication,
  type BrokerResult,
  type BrokerRevocationResult,
  type UnsignedBrokerRequest
} from "./index.js";
import { parseKeychainDeliveryChallenge, parseKeychainDeliveryRequest, parseKeychainDeliveryResponse } from "./keychain-delivery.js";

function request(): UnsignedBrokerRequest {
  const now = 1_700_000_000_000;
  return {
    protocolVersion: "0.1",
    requestId: "request-1",
    contractVersion: "0.1",
    tool: "mac_health",
    arguments: {},
    principal: {
      principalId: "principal-1",
      sessionId: "session-1",
      issuer: "test-issuer",
      audience: "mac-operator-broker",
      scopes: ["mac.control.read"],
      issuedAtMs: now - 1_000,
      expiresAtMs: now + 60_000,
      edgeId: "edge-1"
    },
    timestampMs: now,
    nonce: "nonce-1",
    policyAudience: "mac-operator-broker",
    policyVersion: "policy-0.1",
    authenticationKeyId: "edge-key-1"
  };
}

test("canonical JSON sorts object keys without changing array order", () => {
  assert.equal(canonicalJson({ z: 1, a: [2, 1] }), '{"a":[2,1],"z":1}');
});

test("authentication binds the entire unsigned request", () => {
  const key = randomBytes(32);
  const signed = signRequest(request(), key);
  assert.equal(verifyRequestAuthentication(signed, key), true);
  assert.equal(requestPayloadDigest(request()), signed.payloadDigest);
  const altered = { ...signed, tool: "mac_capabilities" };
  assert.equal(verifyRequestAuthentication(altered, key), false);
});

test("Broker response authentication binds the request and full response", () => {
  const key = randomBytes(32);
  const signedRequest = signRequest(request(), key);
  const response: BrokerResult = {
    ok: true,
    request_id: signedRequest.requestId,
    tool: signedRequest.tool,
    result_class: "SUCCEEDED",
    data: { healthy: true },
    warnings: [],
    truncated: false,
    verification: {},
    duration_ms: 1
  };
  const envelope = signBrokerResponse(signedRequest, response, key);
  assert.equal(verifyBrokerResponse(signedRequest, envelope, key), true);
  const altered = { ...envelope, response: { ...response, data: { healthy: false } } };
  assert.equal(verifyBrokerResponse(signedRequest, altered, key), false);
  const malformed = { ...envelope, response: { data: BigInt(1) } };
  assert.equal(verifyBrokerResponse(signedRequest, malformed as never, key), false);
});

test("OAuth authority revocation event authentication binds identity and response", () => {
  const key = randomBytes(32);
  const event = signBrokerRevocationEvent({
    protocolVersion: "0.1",
    eventType: "oauth_authority_revoked",
    requestId: "edge-revoke:1234567890123456",
    nonce: "edge-revoke-nonce:1234567890123456",
    edgeId: "edge-1",
    authenticationKeyId: "edge-key-1",
    principalId: "principal-1",
    sessionId: "session-1",
    timestampMs: 1_700_000_000_000
  }, key);
  assert.equal(verifyBrokerRevocationEvent(event, key), true);
  assert.equal(verifyBrokerRevocationEvent({ ...event, sessionId: "session-2" }, key), false);
  const response: BrokerRevocationResult = {
    ok: true,
    request_id: event.requestId,
    event_type: event.eventType,
    revoked: true,
    duration_ms: 1
  };
  const envelope = signBrokerRevocationResponse(event, response, key);
  assert.equal(verifyBrokerRevocationResponse(event, envelope, key), true);
  assert.equal(verifyBrokerRevocationResponse(event, { ...envelope, response: { ...response, revoked: false } } as never, key), false);
});

test("Keychain delivery contract is strict and binds the request identity", () => {
  const request = parseKeychainDeliveryRequest({
    protocolVersion: "0.1",
    challenge: "challenge-1",
    requestId: "request-1",
    nonce: "nonce-1",
    keyId: "edge-key-1"
  });
  assert.equal(parseKeychainDeliveryChallenge({
    protocolVersion: "0.1",
    type: "challenge",
    challenge: "challenge-1"
  }).challenge, "challenge-1");
  assert.equal(request.keyId, "edge-key-1");
  assert.throws(() => parseKeychainDeliveryRequest({ ...request, service: "com.mac-operator.test" }), /unexpected fields/u);
  const response = parseKeychainDeliveryResponse({
    protocolVersion: "0.1",
    ok: true,
    challenge: request.challenge,
    requestId: request.requestId,
    nonce: request.nonce,
    keyId: request.keyId,
    keyDigest: "a".repeat(64),
    keyBase64: randomBytes(32).toString("base64")
  });
  assert.equal(response.ok, true);
  assert.throws(() => parseKeychainDeliveryResponse({ ...response, keyDigest: "A".repeat(64) }), /success is malformed/u);
  assert.throws(() => parseKeychainDeliveryResponse({
    protocolVersion: "0.1",
    ok: false,
    challenge: request.challenge,
    requestId: "request-1",
    nonce: "nonce-1",
    errorCode: "REPLAY_DENIED",
    detail: "secret"
  }), /unexpected fields/u);
});
