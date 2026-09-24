import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError, canonicalJson, CONTRACT_VERSION, sha256 } from "@mac-operator/contracts";
import {
  authenticatePrivilegedHelperCommand,
  signPrivilegedHelperJobReadbackRequest,
  signPrivilegedHelperCommand,
  type SignedPrivilegedHelperCommand,
  type UnsignedPrivilegedHelperCommand,
  type UnsignedPrivilegedHelperJobReadbackRequest
} from "./privileged-helper.js";
import {
  authenticatePrivilegedHelperAuthorityResponse,
  BrokerStorePrivilegedHelperAuthorityReplayGuard,
  PrivilegedHelperAuthorityIpcServer,
  PrivilegedHelperAuthorityClient,
  signPrivilegedHelperAuthorityRequest,
  type UnsignedPrivilegedHelperAuthorityRequest
} from "./privileged-helper-authority-ipc.js";

const NOW = 1_700_000_000_000;

function command(sequence: number): UnsignedPrivilegedHelperCommand {
  const payload = { operation: "service_control" as const, service_id: "system/com.example.test", action: "start" as const };
  return {
    protocolVersion: "0.1",
    contractVersion: CONTRACT_VERSION,
    commandId: `priv-command:authority-${sequence}`,
    requestId: `request:authority-${sequence}`,
    nonce: `helper-nonce-authority-${String(sequence).padStart(16, "0")}`,
    nonceExpiresAtMs: NOW + 30_000,
    timestampMs: NOW,
    expiresAtMs: NOW + 30_000,
    operation: "service_control",
    targetRef: "service:system/com.example.test",
    payload,
    payloadDigest: sha256(canonicalJson(payload)),
    policyVersion: "policy-test-1",
    approvalId: `approval:authority-${sequence}`,
    intentId: `intent:authority-${sequence}`
  };
}

async function setupAuthorityServer(
  root: string,
  key: Buffer,
  authorizeCommand: (candidate: UnsignedPrivilegedHelperCommand) => void,
  authorizeReadback: (candidate: UnsignedPrivilegedHelperJobReadbackRequest) => void = () => undefined
): Promise<{ server: PrivilegedHelperAuthorityIpcServer; socketPath: string }> {
  const socketPath = join(root, "authority.sock");
  const server = new PrivilegedHelperAuthorityIpcServer({
    socketPath,
    authenticationKey: key,
    replayGuard: {
      admit: () => undefined
    },
    authorizeCommand,
    authorizeReadback,
    peerCredentialVerifier: { verify: () => undefined },
    now: () => NOW
  });
  await server.listen();
  return { server, socketPath };
}

test("authority polling authenticates the helper command and rechecks Broker authority", async () => {
  const root = await mkdtemp(join(tmpdir(), "mops-authority-ipc-"));
  const key = randomBytes(32);
  const signed = signPrivilegedHelperCommand(command(1), key);
  let allowed = true;
  const { server, socketPath } = await setupAuthorityServer(root, key, (candidate) => {
    assert.deepEqual(authenticatePrivilegedHelperCommand(signed, key, NOW), candidate);
    if (!allowed) throw new BrokerError("REVOKED", "Broker authority was revoked");
  });
  const client = new PrivilegedHelperAuthorityClient({ socketPath, authenticationKey: key, peerCredentialVerifier: { verify: () => undefined }, now: () => NOW });
  try {
    await client.assertAuthorized(signed);
    allowed = false;
    await assert.rejects(
      () => client.assertAuthorized(signed),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "REVOKED"
    );
  } finally {
    client.dispose();
    await server.close();
    key.fill(0);
    await rm(root, { recursive: true, force: true });
  }
});

test("authority polling rejects response tampering and key material is wiped on dispose", async () => {
  const root = await mkdtemp(join(tmpdir(), "mops-authority-ipc-tamper-"));
  const key = randomBytes(32);
  const signed = signPrivilegedHelperCommand(command(2), key);
  const { server, socketPath } = await setupAuthorityServer(root, key, () => undefined);
  const client = new PrivilegedHelperAuthorityClient({ socketPath, authenticationKey: key, peerCredentialVerifier: { verify: () => undefined }, now: () => NOW });
  const request: UnsignedPrivilegedHelperAuthorityRequest = {
    protocolVersion: "0.1",
    contractVersion: CONTRACT_VERSION,
    requestId: "request:helper-authority-test-0001-0001-0001",
    nonce: "helper-authority-nonce-test-0001-0001-0001",
    nonceExpiresAtMs: NOW + 5_000,
    timestampMs: NOW,
    expiresAtMs: NOW + 5_000,
    kind: "authority_check",
    command: signed
  };
  const signedRequest = signPrivilegedHelperAuthorityRequest(request, key);
  try {
    const tampered = { ...signedRequest, requestId: "request:helper-authority-test-0002-0002-0002" };
    assert.throws(
      () => authenticatePrivilegedHelperAuthorityResponse({
        ok: true,
        kind: "authority_check",
        requestId: tampered.requestId,
        commandId: signed.commandId,
        authorized: true,
        responseProof: "0".repeat(64)
      }, request, key),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUTH_INVALID"
    );
    await client.assertAuthorized(signed);
    const deniedPeerClient = new PrivilegedHelperAuthorityClient({
      socketPath,
      authenticationKey: key,
      peerCredentialVerifier: { verify: () => { throw new Error("wrong Broker"); } },
      now: () => NOW
    });
    await assert.rejects(
      () => deniedPeerClient.assertAuthorized(signed),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUTH_INVALID"
    );
    deniedPeerClient.dispose();
    client.dispose();
    await assert.rejects(
      () => client.assertAuthorized(signed),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
    );
  } finally {
    await server.close();
    key.fill(0);
    await rm(root, { recursive: true, force: true });
  }
});

test("authority polling binds readback to the exact UNKNOWN Job descriptor", async () => {
  const root = await mkdtemp(join(tmpdir(), "mops-authority-readback-"));
  const key = randomBytes(32);
  const payload = { operation: "service_control" as const, service_id: "system/com.example.test", action: "start" as const };
  const unsigned: UnsignedPrivilegedHelperJobReadbackRequest = {
    protocolVersion: "0.1",
    contractVersion: CONTRACT_VERSION,
    requestId: "request:readback-authority-0001",
    nonce: "readback-nonce-authority-0001",
    timestampMs: NOW,
    expiresAtMs: NOW + 5_000,
    kind: "job_readback",
    jobId: "job:authority-readback-1",
    principalId: "principal-1",
    sessionId: "session-1",
    operation: "service_control",
    targetRef: "service:system/com.example.test",
    payload,
    payloadDigest: sha256(canonicalJson(payload)),
    policyVersion: "policy-test-1"
  };
  const signed = signPrivilegedHelperJobReadbackRequest(unsigned, key);
  let readbackCalls = 0;
  const { server, socketPath } = await setupAuthorityServer(root, key, () => undefined, (candidate) => {
    readbackCalls += 1;
    assert.equal(candidate.jobId, unsigned.jobId);
    assert.equal(candidate.principalId, unsigned.principalId);
    assert.equal(candidate.sessionId, unsigned.sessionId);
    assert.equal(candidate.payloadDigest, unsigned.payloadDigest);
  });
  const client = new PrivilegedHelperAuthorityClient({ socketPath, authenticationKey: key, peerCredentialVerifier: { verify: () => undefined }, now: () => NOW });
  try {
    await client.assertReadbackAuthorized(signed);
    assert.equal(readbackCalls, 1);
  } finally {
    client.dispose();
    await server.close();
    key.fill(0);
    await rm(root, { recursive: true, force: true });
  }
});

test("authority replay adapter maps request timestamps to the durable helper ledger", () => {
  const admitted: Array<{ requestId: string; nonce: string; acceptedAtMs: number; expiresAtMs: number }> = [];
  const guard = new BrokerStorePrivilegedHelperAuthorityReplayGuard({
    admitPrivilegedHelperCommand: (input) => admitted.push(input)
  });
  guard.admit({
    requestId: "request:helper-authority-test-0003-0003-0003",
    nonce: "helper-authority-nonce-test-0003-0003-0003",
    timestampMs: NOW,
    nonceExpiresAtMs: NOW + 5_000
  });
  assert.deepEqual(admitted, [{
    requestId: "request:helper-authority-test-0003-0003-0003",
    nonce: "helper-authority-nonce-test-0003-0003-0003",
    acceptedAtMs: NOW,
    expiresAtMs: NOW + 5_000
  }]);
});
