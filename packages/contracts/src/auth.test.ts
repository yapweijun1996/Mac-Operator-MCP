import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import {
  canonicalJson,
  requestPayloadDigest,
  signBrokerResponse,
  signRequest,
  verifyBrokerResponse,
  verifyRequestAuthentication,
  type BrokerResult,
  type UnsignedBrokerRequest
} from "./index.js";

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
