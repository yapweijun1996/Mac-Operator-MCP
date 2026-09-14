import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import {
  BrokerStoreVirtualizationGuestReplayGuard,
  InMemoryVirtualizationGuestReplayGuard,
  VirtualizationGuestTransportClient,
  createVirtualizationGuestRequest,
  signVirtualizationGuestResponse,
  verifyVirtualizationGuestRequest,
  verifyVirtualizationGuestResponse,
  virtualizationGuestRequestDigest,
  type UnsignedVirtualizationGuestResponse
} from "./virtualization-guest-transport.js";
import { BrokerStore } from "./persistence.js";

const key = Buffer.alloc(32, 0x42);
const guestIdentity = { imageSha256: "a".repeat(64), runtimeVersion: "macos-virtualization-1.0" } as const;
const now = 1_800_000_000_000;

function request() {
  return createVirtualizationGuestRequest({
    guestIdentity,
    sandboxProfile: "guest-task-v1",
    profileDigest: "b".repeat(64),
    taskDigest: "c".repeat(64),
    processTreePolicy: "single_process",
    timeoutMs: 10_000,
    outputCapBytes: 1024,
    requestId: "request:guest-0123456789abcdef",
    nonce: "guest-nonce-0123456789abcdef",
    timestampMs: now,
    expiresAtMs: now + 30_000
  }, key, { now });
}

function responseFor(signedRequest: ReturnType<typeof request>): UnsignedVirtualizationGuestResponse {
  const unsigned = { ...signedRequest };
  delete (unsigned as Partial<typeof unsigned>).authenticationProof;
  const requestDigest = virtualizationGuestRequestDigest(unsigned);
  return {
    schemaVersion: "0.1",
    protocolVersion: "0.1",
    contractVersion: "0.1",
    kind: "virtualization_guest_task_result",
    requestId: signedRequest.requestId,
    nonce: signedRequest.nonce,
    guestIdentity,
    requestDigest,
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
    stdout: "redacted output",
    stderr: "",
    truncated: false,
    durationMs: 12,
    outputPolicy: "broker-redacted-v1",
    verification: { status: "verified", summary: "postcondition verified" }
  };
}

test("authenticated request and response round trip binds guest identity and request digest", () => {
  const signedRequest = request();
  const guard = new InMemoryVirtualizationGuestReplayGuard({ now: () => now });
  const verifiedRequest = verifyVirtualizationGuestRequest(signedRequest, key, { replayGuard: guard, now });
  const signedResponse = signVirtualizationGuestResponse(responseFor(signedRequest), key);
  const verifiedResponse = verifyVirtualizationGuestResponse(signedResponse, key, verifiedRequest, { expectedGuestIdentity: guestIdentity, expectedOutputCapBytes: 1024 });
  assert.equal(verifiedResponse.resultClass, "SUCCEEDED");
  assert.equal(verifiedResponse.requestDigest, virtualizationGuestRequestDigest(verifiedRequest));
});

test("request tampering and wrong key are rejected before admission", () => {
  const signedRequest = request();
  const tampered = { ...signedRequest, taskDigest: "d".repeat(64) };
  assert.throws(() => verifyVirtualizationGuestRequest(tampered, key, { replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }), now }), (error: unknown) => error instanceof BrokerError && error.errorClass === "AUTH_INVALID");
  assert.throws(() => verifyVirtualizationGuestRequest(signedRequest, Buffer.alloc(32, 0x43), { replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }), now }), (error: unknown) => error instanceof BrokerError && error.errorClass === "AUTH_INVALID");
});

test("request nonce and request ID replay are denied", () => {
  const signedRequest = request();
  const guard = new InMemoryVirtualizationGuestReplayGuard({ now: () => now });
  verifyVirtualizationGuestRequest(signedRequest, key, { replayGuard: guard, now });
  assert.throws(() => verifyVirtualizationGuestRequest(signedRequest, key, { replayGuard: guard, now }), (error: unknown) => error instanceof BrokerError && error.errorClass === "REPLAY_DENIED");
});

test("BrokerStore-backed guest replay admission survives a Broker restart", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-guest-replay-"));
  const databasePath = join(directory, "broker.sqlite");
  const signedRequest = request();
  const firstStore = new BrokerStore(databasePath);
  try {
    verifyVirtualizationGuestRequest(signedRequest, key, {
      replayGuard: new BrokerStoreVirtualizationGuestReplayGuard(firstStore, { now: () => now }),
      now
    });
  } finally {
    firstStore.close();
  }
  const reopened = new BrokerStore(databasePath);
  try {
    assert.throws(
      () => verifyVirtualizationGuestRequest(signedRequest, key, {
        replayGuard: new BrokerStoreVirtualizationGuestReplayGuard(reopened, { now: () => now }),
        now
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "REPLAY_DENIED"
    );
  } finally {
    reopened.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("response binding, guest mismatch, and proof tampering are rejected", () => {
  const signedRequest = request();
  const verifiedRequest = verifyVirtualizationGuestRequest(signedRequest, key, { replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }), now });
  const signedResponse = signVirtualizationGuestResponse(responseFor(signedRequest), key);
  assert.throws(() => verifyVirtualizationGuestResponse({ ...signedResponse, requestDigest: "e".repeat(64) }, key, verifiedRequest), (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT");
  assert.throws(() => verifyVirtualizationGuestResponse({ ...signedResponse, guestIdentity: { ...guestIdentity, imageSha256: "f".repeat(64) } }, key, verifiedRequest), (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT");
  assert.throws(() => verifyVirtualizationGuestResponse({ ...signedResponse, responseProof: "0".repeat(64) }, key, verifiedRequest), (error: unknown) => error instanceof BrokerError && error.errorClass === "AUTH_INVALID");
});

test("freshness, strict envelope, and output limits fail closed", () => {
  const signedRequest = request();
  assert.throws(() => verifyVirtualizationGuestRequest(signedRequest, key, { replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }), now: now + 36_000 }), (error: unknown) => error instanceof BrokerError && error.errorClass === "AUTH_EXPIRED");
  assert.throws(() => verifyVirtualizationGuestRequest({ ...signedRequest, unexpected: true }, key, { replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }), now }), (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED");
  const verifiedRequest = verifyVirtualizationGuestRequest(signedRequest, key, { replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }), now });
  const oversized = signVirtualizationGuestResponse({ ...responseFor(signedRequest), stdout: "x".repeat(1025) }, key);
  assert.throws(() => verifyVirtualizationGuestResponse(oversized, key, verifiedRequest, { expectedOutputCapBytes: 1024 }), (error: unknown) => error instanceof BrokerError && error.errorClass === "OUTPUT_LIMIT");
});

test("request contract excludes raw host paths and credentials", () => {
  const signedRequest = request();
  const keys = Object.keys(signedRequest);
  assert.equal(keys.includes("password"), false);
  assert.equal(keys.includes("token"), false);
  assert.equal(keys.includes("executablePath"), false);
  assert.equal(keys.includes("cwd"), false);
  assert.equal(keys.includes("args"), false);
});

test("bounded transport client admits before exchange and verifies the signed response", async () => {
  let sentRequestId = "";
  const client = new VirtualizationGuestTransportClient({
    authenticationKey: key,
    replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }),
    now: () => now,
    expectedGuestIdentity: guestIdentity,
    expectedSandboxProfile: "guest-task-v1",
    expectedProfileDigest: "b".repeat(64),
    channel: {
      async exchange(frame, signal) {
        assert.equal(signal.aborted, false);
        const signedRequest = JSON.parse(Buffer.from(frame).toString("utf8")) as ReturnType<typeof request>;
        sentRequestId = signedRequest.requestId;
        return Buffer.from(JSON.stringify(signVirtualizationGuestResponse(responseFor(signedRequest), key)), "utf8");
      }
    }
  });
  const result = await client.execute({
    guestIdentity,
    sandboxProfile: "guest-task-v1",
    profileDigest: "b".repeat(64),
    taskDigest: "c".repeat(64),
    processTreePolicy: "single_process",
    timeoutMs: 1_000,
    outputCapBytes: 1_024,
    requestId: "request:guest-abcdef0123456789",
    nonce: "guest-nonce-abcdef0123456789",
    timestampMs: now,
    expiresAtMs: now + 30_000
  });
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(sentRequestId, "request:guest-abcdef0123456789");
  client.close();
});

test("transport timeout and cancellation fail closed after request admission", async () => {
  const neverChannel = {
    async exchange(_frame: Uint8Array, _signal: AbortSignal): Promise<Uint8Array> {
      return new Promise<Uint8Array>(() => undefined);
    }
  };
  const channel = {
    async exchange(_frame: Uint8Array, signal: AbortSignal): Promise<Uint8Array> {
      await new Promise<void>((_resolve, reject) => signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true }));
      return Buffer.alloc(0);
    }
  };
  const timeoutClient = new VirtualizationGuestTransportClient({
    authenticationKey: key,
    replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }),
    now: () => now,
    channel: neverChannel
  });
  await assert.rejects(
    timeoutClient.execute({
      guestIdentity,
      sandboxProfile: "guest-task-v1",
      profileDigest: "b".repeat(64),
      taskDigest: "c".repeat(64),
      processTreePolicy: "single_process",
      timeoutMs: 20,
      outputCapBytes: 1_024,
      requestId: "request:guest-timeout-1234567890",
      nonce: "guest-nonce-timeout-1234567890",
      timestampMs: now,
      expiresAtMs: now + 30_000
    }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "TIMEOUT"
  );
  const cancelClient = new VirtualizationGuestTransportClient({
    authenticationKey: key,
    replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }),
    now: () => now,
    channel,
    cancellationPollMs: 10
  });
  await assert.rejects(
    cancelClient.execute({
      guestIdentity,
      sandboxProfile: "guest-task-v1",
      profileDigest: "b".repeat(64),
      taskDigest: "c".repeat(64),
      processTreePolicy: "single_process",
      timeoutMs: 1_000,
      outputCapBytes: 1_024,
      requestId: "request:guest-cancel-1234567890",
      nonce: "guest-nonce-cancel-1234567890",
      timestampMs: now,
      expiresAtMs: now + 30_000
    }, { shouldCancel: () => true }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
  );
});

test("transport loss after admission is an unknown outcome", async () => {
  const client = new VirtualizationGuestTransportClient({
    authenticationKey: key,
    replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }),
    now: () => now,
    channel: { async exchange(): Promise<Uint8Array> { throw new Error("guest channel closed"); } }
  });
  await assert.rejects(
    client.execute({
      guestIdentity,
      sandboxProfile: "guest-task-v1",
      profileDigest: "b".repeat(64),
      taskDigest: "c".repeat(64),
      processTreePolicy: "single_process",
      timeoutMs: 1_000,
      outputCapBytes: 1_024,
      requestId: "request:guest-loss-12345678901",
      nonce: "guest-nonce-loss-12345678901",
      timestampMs: now,
      expiresAtMs: now + 30_000
    }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "UNKNOWN_OUTCOME" && error.retryable === true
  );
});
