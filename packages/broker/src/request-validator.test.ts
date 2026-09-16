import assert from "node:assert/strict";
import test from "node:test";
import { signRequest, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { parseBrokerRequest } from "./request-validator.js";

const KEY = Buffer.alloc(32, 0x5a);

function requestFixture(): UnsignedBrokerRequest {
  return {
    protocolVersion: "0.1",
    requestId: "request-snapshot-1",
    contractVersion: "0.1",
    tool: "mac_health",
    arguments: { nested: { path: "/tmp/allowed" }, values: ["safe"] },
    principal: {
      principalId: "principal-snapshot",
      sessionId: "session-snapshot",
      issuer: "issuer-snapshot",
      audience: "mac-operator-broker",
      scopes: ["mac.control.read"],
      issuedAtMs: 1_800_000_000_000,
      expiresAtMs: 1_800_000_030_000,
      edgeId: "edge-snapshot"
    },
    timestampMs: 1_800_000_000_000,
    nonce: "nonce-snapshot-1",
    policyAudience: "mac-operator-broker",
    policyVersion: "policy-snapshot-1",
    authenticationKeyId: "edge-key-snapshot"
  };
}

test("request parser returns an immutable snapshot isolated from caller mutations", () => {
  const unsigned = requestFixture();
  const signed = signRequest(unsigned, KEY);
  const parsed = parseBrokerRequest(signed);

  assert.notEqual(parsed, signed);
  assert.notEqual(parsed.arguments, signed.arguments);
  assert.notEqual(parsed.principal, signed.principal);
  assert.equal(Object.isFrozen(parsed), true);
  assert.equal(Object.isFrozen(parsed.arguments), true);
  assert.equal(Object.isFrozen(parsed.arguments.nested), true);
  assert.equal(Object.isFrozen(parsed.arguments.values), true);
  assert.equal(Object.isFrozen(parsed.principal), true);
  assert.equal(Object.isFrozen(parsed.principal.scopes), true);

  (signed.arguments.nested as Record<string, unknown>).path = "/private";
  (signed.arguments.values as string[]).push("changed");
  (signed.principal.scopes as string[]).push("mac.priv.power");
  signed.principal.principalId = "attacker";

  assert.equal((parsed.arguments.nested as Record<string, unknown>).path, "/tmp/allowed");
  assert.deepEqual(parsed.arguments.values, ["safe"]);
  assert.deepEqual(parsed.principal.scopes, ["mac.control.read"]);
  assert.equal(parsed.principal.principalId, "principal-snapshot");
});

test("request snapshot keeps an own __proto__ field as inert data", () => {
  const unsigned = requestFixture();
  const argumentsValue = unsigned.arguments as Record<string, unknown>;
  Object.defineProperty(argumentsValue, "__proto__", {
    configurable: true,
    enumerable: true,
    writable: true,
    value: { path: "/private" }
  });
  const parsed = parseBrokerRequest(signRequest(unsigned, KEY));
  const snapshotArguments = parsed.arguments as Record<string, unknown>;

  assert.equal(Object.getPrototypeOf(snapshotArguments), null);
  assert.equal(Object.getPrototypeOf(snapshotArguments["__proto__"]), null);
  assert.equal((snapshotArguments["__proto__"] as Record<string, unknown>).path, "/private");
  assert.equal(Object.prototype.hasOwnProperty.call(snapshotArguments, "__proto__"), true);
});

test("request parser rejects authority arrays with custom prototypes", () => {
  const signed = signRequest(requestFixture(), KEY);
  Object.setPrototypeOf(signed.principal.scopes, {
    every: () => true,
    [Symbol.iterator]: function* () { yield "mac.priv.power"; }
  });
  assert.throws(
    () => parseBrokerRequest(signed),
    (error: unknown) => error instanceof Error && error.message === "Request envelope contains unsupported values"
  );
});
