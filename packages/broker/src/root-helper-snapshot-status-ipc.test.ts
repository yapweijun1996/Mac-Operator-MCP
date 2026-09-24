import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import { BrokerError, CONTRACT_VERSION, PROTOCOL_VERSION } from "@mac-operator/contracts";
import { DisabledRootHelperSnapshotTransport } from "./root-helper-snapshot.js";
import {
  MemoryRootHelperSnapshotStatusReplayGuard,
  authenticateRootHelperSnapshotStatusRequest,
  signRootHelperSnapshotStatusRequest,
  validateRootHelperSnapshotStatusReadback,
  validateUnsignedRootHelperSnapshotStatusRequest,
  type RootHelperSnapshotStatusReadback,
  type UnsignedRootHelperSnapshotStatusRequest
} from "./root-helper-snapshot-status-ipc.js";

const key = randomBytes(32);
const now = Date.now();
const request: UnsignedRootHelperSnapshotStatusRequest = {
  protocolVersion: PROTOCOL_VERSION,
  contractVersion: CONTRACT_VERSION,
  requestId: "request:root-helper-status-0123456789abcdef",
  nonce: "root-helper-status-nonce-0123456789abcdef",
  timestampMs: now,
  expiresAtMs: now + 60_000,
  kind: "root_helper_snapshot_status"
};

function status(): RootHelperSnapshotStatusReadback {
  return {
    component: "mac-operator-root-helper-snapshot",
    sourceRevision: "a".repeat(40),
    contractVersion: "0.1",
    state: "running",
    runtimeState: "running",
    nativeTransportRequired: true,
    available: false,
    capability: new DisabledRootHelperSnapshotTransport().capability
  };
}

test("root-helper status request is HMAC authenticated with its exact contract", () => {
  const signed = signRootHelperSnapshotStatusRequest(request, key);
  assert.deepEqual(authenticateRootHelperSnapshotStatusRequest(signed, key, now + 500), request);
  assert.throws(
    () => authenticateRootHelperSnapshotStatusRequest({ ...signed, requestId: "request:root-helper-status-abcdef0123456789" }, key, now + 500),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "AUTH_INVALID"
  );
});

test("root-helper status replay guard rejects both request and nonce reuse", () => {
  const guard = new MemoryRootHelperSnapshotStatusReplayGuard();
  guard.admit(request);
  assert.throws(
    () => guard.admit({ ...request, requestId: "request:root-helper-status-abcdef0123456789" }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "REPLAY_DENIED"
  );
  assert.throws(
    () => guard.admit({ ...request, nonce: "root-helper-status-nonce-abcdef0123456789" }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "REPLAY_DENIED"
  );
});

test("root-helper status readback validates capability and source identity", () => {
  assert.deepEqual(validateRootHelperSnapshotStatusReadback(status()), status());
  assert.throws(
    () => validateRootHelperSnapshotStatusReadback({ ...status(), sourceRevision: "not-a-revision" }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
  );
  assert.throws(
    () => validateUnsignedRootHelperSnapshotStatusRequest({ ...request, requestId: "bad" }),
    /Root-helper snapshot status request fields are malformed/u
  );
});
