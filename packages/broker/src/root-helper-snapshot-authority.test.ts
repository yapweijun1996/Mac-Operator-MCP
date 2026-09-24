import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { BrokerError, sha256 } from "@mac-operator/contracts";
import { capturePeerProcessIdentity } from "./peer-credentials.js";
import {
  authenticateRootHelperSnapshotAuthorityResponse,
  InMemoryRootHelperSnapshotRequestAuthority,
  InMemoryRootHelperSnapshotAuthorityReplayGuard,
  RootHelperSnapshotAuthorityClient,
  RootHelperSnapshotAuthorityIpcServer,
  signRootHelperSnapshotAuthorityRequest,
  type UnsignedRootHelperSnapshotAuthorityRequest
} from "./root-helper-snapshot-authority.js";

function peerPolicy() {
  return {
    expectedUid: process.getuid?.() ?? 1,
    ...(process.getgid?.() === undefined ? {} : { expectedGid: process.getgid() }),
    allowedProcessIdentity: capturePeerProcessIdentity(process.pid)
  };
}

function request(): UnsignedRootHelperSnapshotAuthorityRequest {
  const now = Date.now();
  return {
    protocolVersion: "0.1",
    contractVersion: "0.1",
    requestId: "request:root-helper-authority-0123456789abcdef",
    nonce: "root-helper-authority-nonce-0123456789abcdef",
    nonceExpiresAtMs: now + 10_000,
    timestampMs: now,
    expiresAtMs: now + 10_000,
    kind: "snapshot_authority_check",
    requestDigest: sha256("root-helper-request")
  };
}

test("root-helper snapshot authority signing binds the task request digest", () => {
  const key = randomBytes(32);
  const signed = signRootHelperSnapshotAuthorityRequest(request(), key);
  assert.equal(typeof signed.authenticationProof, "string");
  const body = {
    ok: true as const,
    kind: signed.kind,
    requestId: signed.requestId,
    requestDigest: signed.requestDigest,
    authorized: true as const,
    responseProof: "0".repeat(64)
  };
  assert.throws(
    () => authenticateRootHelperSnapshotAuthorityResponse(body, request(), key),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "AUTH_INVALID"
  );
  key.fill(0);
});

test("root-helper snapshot authority replay guard rejects a repeated poll", () => {
  const guard = new InMemoryRootHelperSnapshotAuthorityReplayGuard();
  const value = request();
  guard.admit(value);
  assert.throws(
    () => guard.admit(value),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "REPLAY_DENIED"
  );
});

test("root-helper snapshot authority admits only active Broker request digests", () => {
  let now = 10_000;
  const authority = new InMemoryRootHelperSnapshotRequestAuthority(4, () => now);
  const digest = sha256("active-root-helper-request");
  authority.admit(digest, now + 100);
  assert.doesNotThrow(() => authority.assertAuthorized(digest));
  authority.revoke(digest);
  assert.throws(
    () => authority.assertAuthorized(digest),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "REVOKED"
  );
  authority.admit(digest, now + 100);
  now += 100;
  assert.throws(
    () => authority.assertAuthorized(digest),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "AUTH_EXPIRED"
  );
  authority.release(digest);
  assert.throws(
    () => authority.assertAuthorized(digest),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "REVOKED"
  );
});

test("root-helper snapshot authority performs an authenticated native-peer poll", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-root-helper-authority-"));
  const socketPath = join(directory, "authority.sock");
  const key = randomBytes(32);
  const digest = sha256("live-root-helper-request");
  let authorizedDigest = "";
  const server = new RootHelperSnapshotAuthorityIpcServer({
    socketPath,
    authenticationKey: key,
    replayGuard: new InMemoryRootHelperSnapshotAuthorityReplayGuard(),
    authorizeRequest: (requestDigest) => {
      authorizedDigest = requestDigest;
    },
    peerPolicy: peerPolicy()
  });
  const client = new RootHelperSnapshotAuthorityClient({ socketPath, authenticationKey: key, peerPolicy: peerPolicy() });
  try {
    await server.listen();
    await client.assertAuthorized(digest, Date.now() + 10_000);
    assert.equal(authorizedDigest, digest);
  } finally {
    client.dispose();
    await server.close();
    key.fill(0);
    await rm(directory, { recursive: true, force: true });
  }
});
