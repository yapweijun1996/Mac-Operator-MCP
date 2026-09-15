import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { signRequest, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring, keyIdentity } from "./edge-keyring.js";
import { BrokerStore } from "./persistence.js";

const NOW = 1_700_000_000_000;

test("overlapping Edge keys support rotation and key-specific revocation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-edge-rotation-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const oldKey = randomBytes(32);
  const newKey = randomBytes(32);
  const keyring = new EdgeKeyring([
    { edgeId: "edge-1", keyId: "edge-key-old", key: oldKey, notBeforeMs: NOW - 60_000, expiresAtMs: NOW + 60_000 },
    { edgeId: "edge-1", keyId: "edge-key-new", key: newKey, notBeforeMs: NOW - 1_000, expiresAtMs: NOW + 120_000 }
  ]);
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.control.read"], ["edge-key-old", "edge-key-new"]),
    edgeAuthenticationKeys: keyring,
    now: () => NOW
  });
  try {
    assert.equal((await broker.handle(signRequest(request("old-1", "edge-key-old"), oldKey))).ok, true);
    assert.equal((await broker.handle(signRequest(request("new-1", "edge-key-new"), newKey))).ok, true);
    store.revoke("edge_key", keyIdentity("edge-1", "edge-key-old"), "ROTATED", NOW);
    assert.equal(
      (await broker.handle(signRequest(request("old-2", "edge-key-old"), oldKey))).result_class,
      "REVOKED"
    );
    assert.equal((await broker.handle(signRequest(request("new-2", "edge-key-new"), newKey))).ok, true);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("unknown and expired Edge key identities fail closed", () => {
  const key = randomBytes(32);
  const keyring = new EdgeKeyring([{
    edgeId: "edge-1", keyId: "expired-key", key,
    notBeforeMs: NOW - 60_000, expiresAtMs: NOW
  }]);
  const unknown = signRequest(request("unknown", "missing-key"), key);
  assert.throws(() => keyring.keyFor(unknown, NOW), (error: unknown) => errorClass(error) === "AUTH_INVALID");
  const expired = signRequest(request("expired", "expired-key"), key);
  assert.throws(() => keyring.keyFor(expired, NOW), (error: unknown) => errorClass(error) === "AUTH_EXPIRED");
});

test("Edge keyring rejects malformed identities before loading authority", () => {
  const key = randomBytes(32);
  for (const record of [
    { edgeId: "../edge", keyId: "edge-key-1" },
    { edgeId: "edge-1", keyId: "../key" },
    { edgeId: "edge-1", keyId: "edge/key" },
    { edgeId: "edge-1", keyId: "" },
    { edgeId: `edge-${"x".repeat(125)}`, keyId: "edge-key-1" }
  ]) {
    assert.throws(() => new EdgeKeyring([{
      ...record,
      key,
      notBeforeMs: NOW - 1_000,
      expiresAtMs: NOW + 60_000
    }]), /identity is malformed/u);
  }
});

test("Edge keyring disposal removes loaded authentication authority", () => {
  const key = randomBytes(32);
  const keyring = new EdgeKeyring([{
    edgeId: "edge-1", keyId: "active-key", key,
    notBeforeMs: NOW - 60_000, expiresAtMs: NOW + 60_000
  }]);
  const signed = signRequest(request("dispose", "active-key"), key);
  assert.ok(keyring.keyFor(signed, NOW));
  keyring.dispose();
  assert.equal(keyring.keyByIdentity("edge-1", "active-key"), undefined);
  assert.throws(() => keyring.keyFor(signed, NOW), (error: unknown) => errorClass(error) === "AUTH_INVALID");
});

function request(suffix: string, keyId: string): UnsignedBrokerRequest {
  return {
    protocolVersion: "0.1",
    requestId: `rotation-request-${suffix}`,
    contractVersion: "0.1",
    tool: "mac_health",
    arguments: {},
    principal: {
      principalId: "principal-1", sessionId: "session-1", issuer: "test-issuer",
      audience: "mac-operator-broker", scopes: ["mac.control.read"],
      issuedAtMs: NOW - 1_000, expiresAtMs: NOW + 60_000, edgeId: "edge-1"
    },
    timestampMs: NOW,
    nonce: `rotation-nonce-${suffix}`,
    policyAudience: "mac-operator-broker",
    policyVersion: "policy-0.1",
    authenticationKeyId: keyId
  };
}

function errorClass(error: unknown): unknown {
  return error !== null && typeof error === "object" && "errorClass" in error
    ? (error as { errorClass: unknown }).errorClass
    : undefined;
}
