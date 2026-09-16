import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError, type CapabilityFamily } from "@mac-operator/contracts";
import { BrokerStore, type AdmitRequestInput } from "./persistence.js";

const REPLAY_CAPACITY = 4_096;

function requestInput(index: number, receivedAtMs = 1): AdmitRequestInput {
  const suffix = String(index).padStart(16, "0");
  return {
    requestId: `request:replay-capacity-${suffix}`,
    edgeId: "edge-replay-capacity",
    nonce: `nonce:replay-capacity-${suffix}`,
    nonceExpiresAtMs: receivedAtMs + 100_000,
    principalId: "principal-replay-capacity",
    sessionId: `session-replay-capacity-${suffix}`,
    tool: "mac_health",
    policyVersion: "policy-0.1",
    payloadDigest: "a".repeat(64),
    mutation: false,
    capabilityFamilies: ["read" satisfies CapabilityFamily],
    receivedAtMs
  };
}

test("request replay ledger is bounded and expired rows are reclaimed transactionally", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-request-replay-capacity-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    for (let index = 0; index < REPLAY_CAPACITY; index += 1) {
      store.admitRequest(requestInput(index));
    }
    assert.throws(
      () => store.admitRequest(requestInput(REPLAY_CAPACITY, 2)),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    assert.equal(store.requestRecord(requestInput(REPLAY_CAPACITY, 2).requestId), undefined);

    const reclaimed = store.admitRequest(requestInput(REPLAY_CAPACITY + 1, 100_001));
    assert.equal(reclaimed.state, "RECEIVED");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("privileged-helper replay ledger reclaims rows exactly at expiry before capacity denial", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-helper-replay-capacity-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    for (let index = 0; index < REPLAY_CAPACITY; index += 1) {
      const suffix = String(index).padStart(16, "0");
      store.admitPrivilegedHelperCommand({
        requestId: `request:helper-replay-capacity-${suffix}`,
        nonce: `helper-nonce-replay-capacity-${suffix}`,
        acceptedAtMs: 1,
        expiresAtMs: 100_001
      });
    }
    assert.throws(
      () => store.admitPrivilegedHelperCommand({
        requestId: `request:helper-replay-capacity-${String(REPLAY_CAPACITY).padStart(16, "0")}`,
        nonce: `helper-nonce-replay-capacity-${String(REPLAY_CAPACITY).padStart(16, "0")}`,
        acceptedAtMs: 2,
        expiresAtMs: 100_002
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    store.admitPrivilegedHelperCommand({
      requestId: `request:helper-replay-capacity-${String(REPLAY_CAPACITY + 1).padStart(16, "0")}`,
      nonce: `helper-nonce-replay-capacity-${String(REPLAY_CAPACITY + 1).padStart(16, "0")}`,
      acceptedAtMs: 100_001,
      expiresAtMs: 200_001
    });
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Keychain delivery replay ledger is bounded and reclaims exact expiry", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-keychain-replay-capacity-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    for (let index = 0; index < REPLAY_CAPACITY; index += 1) {
      const suffix = String(index).padStart(16, "0");
      store.admitKeychainDeliveryRequest({
        requestId: `delivery-request-${suffix}`,
        nonce: `delivery-nonce-${suffix}`,
        acceptedAtMs: 1,
        expiresAtMs: 100_001
      });
    }
    assert.throws(
      () => store.admitKeychainDeliveryRequest({
        requestId: `delivery-request-${String(REPLAY_CAPACITY).padStart(16, "0")}`,
        nonce: `delivery-nonce-${String(REPLAY_CAPACITY).padStart(16, "0")}`,
        acceptedAtMs: 2,
        expiresAtMs: 100_002
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    store.admitKeychainDeliveryRequest({
      requestId: `delivery-request-${String(REPLAY_CAPACITY + 1).padStart(16, "0")}`,
      nonce: `delivery-nonce-${String(REPLAY_CAPACITY + 1).padStart(16, "0")}`,
      acceptedAtMs: 100_001,
      expiresAtMs: 200_001
    });
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
