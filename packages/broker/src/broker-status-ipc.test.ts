import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { connect } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerStore } from "./persistence.js";
import {
  authenticateBrokerStatusResponse,
  BrokerStatusIpcServer,
  readBrokerStatus,
  signBrokerStatusRequest,
  type BrokerStatusResponse,
  type UnsignedBrokerStatusRequest
} from "./broker-status-ipc.js";

const NOW = 1_700_000_000_000;

test("Broker status IPC authenticates readback and rejects durable replay", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-broker-status-"));
  let store = new BrokerStore(join(directory, "broker.sqlite"));
  const socketPath = join(directory, "broker-status.sock");
  const authenticationKey = randomBytes(32);
  const status = {
    component: "mac-operator-broker" as const,
    sourceRevision: "0123456789abcdef0123456789abcdef01234567",
    contractVersion: "0.1",
    policyVersion: "policy-1",
    state: "running" as const,
    runtimeState: "running" as const,
    nativeTransportRequired: true as const,
    enabledCapabilities: ["mac_health"]
  };
  let server = new BrokerStatusIpcServer({
    socketPath,
    authenticationKey,
    replayGuard: { admit: (request) => store.admitBrokerStatusRequest(request) },
    peerCredentialVerifier: { verify: () => undefined },
    authorizeStatus: () => undefined,
    readStatus: () => status,
    now: () => NOW
  });
  try {
    await server.listen();
    const readback = await readBrokerStatus({ socketPath, authenticationKey, now: () => NOW });
    assert.deepEqual(readback, status);

    const request: UnsignedBrokerStatusRequest = {
      protocolVersion: "0.1",
      contractVersion: "0.1",
      requestId: `request:broker-status-${"a".repeat(16)}`,
      nonce: `broker-status-nonce-${"b".repeat(16)}`,
      timestampMs: NOW,
      expiresAtMs: NOW + 30_000,
      kind: "broker_status"
    };
    const trailing = await sendStatus(socketPath, signBrokerStatusRequest(request, authenticationKey), "{}\n");
    assert.equal(trailing.ok, false);
    if (!trailing.ok) assert.equal(trailing.resultClass, "PRECONDITION_FAILED");
    const first = await sendStatus(socketPath, signBrokerStatusRequest(request, authenticationKey));
    assert.equal(first.ok, true);
    if (first.ok) {
      const authenticated = authenticateBrokerStatusResponse(first, request, authenticationKey);
      assert.equal(authenticated.ok, true);
      if (authenticated.ok) assert.deepEqual(authenticated.status, status);
      assert.throws(
        () => authenticateBrokerStatusResponse({ ...first, responseProof: "0".repeat(64) }, request, authenticationKey),
        (error: unknown) => error instanceof Error && "errorClass" in error && (error as { errorClass: string }).errorClass === "AUTH_INVALID"
      );
    }
    const replay = await sendStatus(socketPath, signBrokerStatusRequest(request, authenticationKey));
    assert.equal(replay.ok, false);
    if (!replay.ok) assert.equal(replay.resultClass, "REPLAY_DENIED");
    await server.close();
    store.close();
    store = new BrokerStore(join(directory, "broker.sqlite"));
    server = new BrokerStatusIpcServer({
      socketPath,
      authenticationKey,
      replayGuard: { admit: (value) => store.admitBrokerStatusRequest(value) },
      peerCredentialVerifier: { verify: () => undefined },
      authorizeStatus: () => undefined,
      readStatus: () => status,
      now: () => NOW
    });
    await server.listen();
    const replayAfterRestart = await sendStatus(socketPath, signBrokerStatusRequest(request, authenticationKey));
    assert.equal(replayAfterRestart.ok, false);
    if (!replayAfterRestart.ok) assert.equal(replayAfterRestart.resultClass, "REPLAY_DENIED");
  } finally {
    await server.close();
    store.close();
    authenticationKey.fill(0);
    await rm(directory, { recursive: true, force: true });
  }
});

async function sendStatus(socketPath: string, payload: unknown, suffix = ""): Promise<BrokerStatusResponse> {
  return new Promise((resolvePromise, rejectPromise) => {
    const socket = connect(socketPath);
    const chunks: Buffer[] = [];
    socket.once("error", rejectPromise);
    socket.on("data", (chunk) => {
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      socket.destroy();
      try {
        resolvePromise(JSON.parse(combined.subarray(0, newline).toString("utf8")) as BrokerStatusResponse);
      } catch (error) {
        rejectPromise(error);
      }
    });
    socket.on("connect", () => socket.write(`${JSON.stringify(payload)}\n${suffix}`));
  });
}
