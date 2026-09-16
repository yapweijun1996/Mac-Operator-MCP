import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";
import {
  BrokerStoreKeychainDeliveryReplayGuard,
  KeychainDeliveryServer,
  type KeychainDeliveryReplayGuard
} from "./keychain-delivery.js";
import { capturePeerProcessIdentity } from "./peer-credentials.js";

function serverOptions(replayGuard: KeychainDeliveryReplayGuard): ConstructorParameters<typeof KeychainDeliveryServer>[0] {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined) throw new Error("POSIX identity is unavailable");
  return {
    socketPath: "/tmp/mac-operator-keychain-delivery-test.sock",
    peerPolicy: {
      expectedUid: uid,
      expectedGid: gid,
      allowedProcessIdentity: capturePeerProcessIdentity(process.pid)
    },
    service: "com.mac-operator.test",
    account: "edge:keychain-test",
    keyId: "edge-key-1",
    keyDigest: "0".repeat(64),
    replayGuard
  };
}

test("Keychain delivery server requires an explicit durable replay guard", () => {
  const guard: KeychainDeliveryReplayGuard = { durable: true, admit: () => undefined };
  assert.doesNotThrow(() => new KeychainDeliveryServer(serverOptions(guard)));
  assert.throws(
    () => new KeychainDeliveryServer({ ...serverOptions(guard), replayGuard: undefined as never }),
    /durable replay guard/u
  );
});

test("BrokerStore Keychain replay guard preserves stable replay errors", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-keychain-delivery-guard-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const guard = new BrokerStoreKeychainDeliveryReplayGuard(store);
    guard.admit({ requestId: "delivery-request-1", nonce: "delivery-nonce-1", acceptedAtMs: 1, expiresAtMs: 100 });
    assert.throws(
      () => guard.admit({ requestId: "delivery-request-1", nonce: "delivery-nonce-2", acceptedAtMs: 2, expiresAtMs: 101 }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "REPLAY_DENIED"
    );
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
