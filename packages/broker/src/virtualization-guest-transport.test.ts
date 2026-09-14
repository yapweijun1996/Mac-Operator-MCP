import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import {
  InMemoryVirtualizationGuestReplayGuard,
  createVirtualizationGuestRequest,
  signVirtualizationGuestResponse,
  verifyVirtualizationGuestRequest,
  verifyVirtualizationGuestResponse,
  virtualizationGuestRequestDigest,
  type UnsignedVirtualizationGuestResponse
} from "./virtualization-guest-transport.js";

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
