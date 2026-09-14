import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import {
  InMemoryVirtualizationGuestReplayGuard,
  VirtualizationGuestTransportClient,
  createVirtualizationGuestRequest,
  createVirtualizationGuestStatusRequest,
  virtualizationGuestRequestDigest,
  virtualizationGuestStatusRequestDigest,
  type UnsignedVirtualizationGuestRequest,
  type UnsignedVirtualizationGuestResponse,
  type UnsignedVirtualizationGuestStatusResponse
} from "./virtualization-guest-transport.js";
import { VirtualizationGuestAgent } from "./virtualization-guest-agent.js";

const key = Buffer.alloc(32, 0x61);
const guestIdentity = { imageSha256: "a".repeat(64), runtimeVersion: "macos-26.2-vz-1" } as const;
const now = 1_800_000_000_000;

function requestInput(requestId: string, nonce: string) {
  return {
    guestIdentity,
    sandboxProfile: "guest-task-v1",
    profileDigest: "b".repeat(64),
    taskDigest: "c".repeat(64),
    processTreePolicy: "single_process" as const,
    timeoutMs: 1_000,
    outputCapBytes: 1_024,
    requestId,
    nonce,
    timestampMs: now,
    expiresAtMs: now + 30_000
  };
}

function taskResponse(request: UnsignedVirtualizationGuestRequest): UnsignedVirtualizationGuestResponse {
  return {
    schemaVersion: "0.1",
    protocolVersion: "0.1",
    contractVersion: "0.1",
    kind: "virtualization_guest_task_result",
    requestId: request.requestId,
    nonce: request.nonce,
    guestIdentity,
    requestDigest: virtualizationGuestRequestDigest(request),
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
    stdout: "guest-ok",
    stderr: "",
    truncated: false,
    durationMs: 4,
    outputPolicy: "broker-redacted-v1",
    verification: { status: "verified", summary: "guest postcondition verified" }
  };
}

test("guest agent verifies, replays, and signs one bounded task exchange", async () => {
  let callbackRequest: UnsignedVirtualizationGuestRequest | undefined;
  const agent = new VirtualizationGuestAgent({
    authenticationKey: key,
    replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }),
    expectedGuestIdentity: guestIdentity,
    expectedSandboxProfile: "guest-task-v1",
    expectedProfileDigest: "b".repeat(64),
    now: () => now,
    execute: async (request) => {
      callbackRequest = request;
      return taskResponse(request);
    }
  });
  const client = new VirtualizationGuestTransportClient({
    authenticationKey: key,
    replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }),
    expectedGuestIdentity: guestIdentity,
    expectedSandboxProfile: "guest-task-v1",
    expectedProfileDigest: "b".repeat(64),
    now: () => now,
    channel: { exchange: (frame) => agent.exchange(frame) }
  });
  const result = await client.execute(requestInput("request:guest-agent-0123456789", "guest-nonce-agent-0123456789"));
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(callbackRequest?.requestId, "request:guest-agent-0123456789");
  assert.equal(Object.hasOwn(callbackRequest ?? {}, "executable"), false);
  assert.equal(Object.hasOwn(callbackRequest ?? {}, "cwd"), false);
  assert.equal(Object.hasOwn(callbackRequest ?? {}, "args"), false);
  const replayed = createVirtualizationGuestRequest(
    requestInput("request:guest-agent-0123456789", "guest-nonce-agent-0123456789"),
    key,
    { now }
  );
  await assert.rejects(
    agent.exchange(Buffer.from(JSON.stringify(replayed), "utf8")),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "REPLAY_DENIED"
  );
  client.close();
  agent.close();
});

test("guest agent serves an authenticated status lookup bound to the original task", async () => {
  const original = createVirtualizationGuestRequest(requestInput("request:guest-agent-status-0123456789", "guest-nonce-agent-status-0123456789"), key, { now });
  const unsignedOriginal = { ...original };
  delete (unsignedOriginal as Partial<typeof unsignedOriginal>).authenticationProof;
  const status = createVirtualizationGuestStatusRequest({
    guestIdentity,
    originalRequestId: original.requestId,
    originalNonce: original.nonce,
    originalRequestDigest: virtualizationGuestRequestDigest(unsignedOriginal),
    timeoutMs: 1_000,
    outputCapBytes: 1_024,
    requestId: "request:guest-status-agent-0123456789",
    nonce: "guest-status-nonce-agent-0123456789",
    timestampMs: now,
    expiresAtMs: now + 30_000
  }, key, { now });
  const agent = new VirtualizationGuestAgent({
    authenticationKey: key,
    replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }),
    expectedGuestIdentity: guestIdentity,
    expectedSandboxProfile: "guest-task-v1",
    expectedProfileDigest: "b".repeat(64),
    now: () => now,
    execute: async (request) => taskResponse(request),
    lookup: async (request): Promise<UnsignedVirtualizationGuestStatusResponse> => ({
      schemaVersion: "0.1",
      protocolVersion: "0.1",
      contractVersion: "0.1",
      kind: "virtualization_guest_task_status_result",
      requestId: request.requestId,
      nonce: request.nonce,
      guestIdentity,
      originalRequestId: request.originalRequestId,
      originalNonce: request.originalNonce,
      originalRequestDigest: request.originalRequestDigest,
      statusRequestDigest: virtualizationGuestStatusRequestDigest(request),
      state: "completed",
      resultClass: "SUCCEEDED",
      exitCode: 0,
      stdout: "recovered",
      stderr: "",
      truncated: false,
      durationMs: 3,
      outputPolicy: "broker-redacted-v1",
      verification: { status: "verified", summary: "status postcondition verified" }
    })
  });
  const client = new VirtualizationGuestTransportClient({
    authenticationKey: key,
    replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }),
    expectedGuestIdentity: guestIdentity,
    authorizeStatusLookup: () => undefined,
    now: () => now,
    channel: { exchange: (frame) => agent.exchange(frame) }
  });
  const result = await client.lookup({
    guestIdentity,
    originalRequestId: original.requestId,
    originalNonce: original.nonce,
    originalRequestDigest: virtualizationGuestRequestDigest(unsignedOriginal),
    timeoutMs: 1_000,
    outputCapBytes: 1_024,
    requestId: status.requestId,
    nonce: status.nonce,
    timestampMs: now,
    expiresAtMs: now + 30_000
  });
  assert.equal(result.originalRequestId, original.requestId);
  assert.equal(result.resultClass, "SUCCEEDED");
  client.close();
  agent.close();
});

test("guest agent rejects an executor response that changes the admitted identity", async () => {
  const agent = new VirtualizationGuestAgent({
    authenticationKey: key,
    replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }),
    expectedGuestIdentity: guestIdentity,
    expectedSandboxProfile: "guest-task-v1",
    expectedProfileDigest: "b".repeat(64),
    now: () => now,
    execute: async (request) => ({ ...taskResponse(request), requestDigest: sha256(canonicalJson({ tampered: true })) })
  });
  const signed = createVirtualizationGuestRequest(requestInput("request:guest-agent-tamper-0123456789", "guest-nonce-agent-tamper-0123456789"), key, { now });
  await assert.rejects(
    agent.exchange(Buffer.from(JSON.stringify(signed), "utf8")),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT"
  );
  agent.close();
});

test("guest agent cancels active work before close can publish a signed success", async () => {
  let startedResolve!: () => void;
  let release!: () => void;
  const started = new Promise<void>((resolve) => { startedResolve = resolve; });
  const blocked = new Promise<void>((resolve) => { release = resolve; });
  const agent = new VirtualizationGuestAgent({
    authenticationKey: key,
    replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }),
    expectedGuestIdentity: guestIdentity,
    expectedSandboxProfile: "guest-task-v1",
    expectedProfileDigest: "b".repeat(64),
    now: () => now,
    execute: async (request) => {
      startedResolve();
      await blocked;
      return taskResponse(request);
    }
  });
  const signed = createVirtualizationGuestRequest(
    requestInput("request:guest-agent-close-0123456789", "guest-nonce-agent-close-0123456789"),
    key,
    { now }
  );
  const running = agent.exchange(Buffer.from(JSON.stringify(signed), "utf8"));
  await started;
  agent.close();
  release();
  await assert.rejects(
    running,
    (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
  );
});
