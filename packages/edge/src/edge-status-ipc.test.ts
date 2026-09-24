import assert from "node:assert/strict";
import { connect } from "node:net";
import { chmod, lstat, mkdtemp, mkdir, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  EdgeStatusIpcServer,
  authenticateEdgeStatusResponse,
  readEdgeStatus,
  signEdgeStatusRequest,
  type EdgeStatusResponse,
  type UnsignedEdgeStatusRequest
} from "./edge-status-ipc.js";

const NOW = 1_800_000_000_000;

function status() {
  return {
    component: "mac-operator-edge" as const,
    state: "running" as const,
    sourceRevision: "0123456789abcdef0123456789abcdef01234567",
    contractVersion: "0.1",
    policyVersion: "policy-1",
    bindHost: "127.0.0.1",
    bindPort: 44_321,
    listening: true
  };
}

test("Edge status IPC authenticates owner readback and rejects replay", async () => {
  const root = await mkdtemp(join(tmpdir(), "e-s-"));
  const canonicalRoot = await realpath(root);
  const runtime = join(canonicalRoot, "runtime");
  const socketPath = join(runtime, "edge-status.sock");
  const key = Buffer.alloc(32, 0x51);
  await mkdir(runtime, { mode: 0o700 });
  await chmod(runtime, 0o700);
  const server = new EdgeStatusIpcServer({
    socketPath,
    authenticationKey: key,
    readStatus: status,
    authorizeStatus: () => undefined,
    now: () => NOW
  });
  try {
    await server.listen();
    assert.deepEqual(await readEdgeStatus({ socketPath, authenticationKey: key, now: () => NOW }), status());

    const request: UnsignedEdgeStatusRequest = {
      protocolVersion: "0.1",
      contractVersion: "0.1",
      requestId: "request:edge-status-1234567890123456",
      nonce: "edge-status-nonce-1234567890123456",
      timestampMs: NOW,
      expiresAtMs: NOW + 5_000,
      kind: "edge_status"
    };
    const first = await send(socketPath, signEdgeStatusRequest(request, key));
    assert.equal(first.ok, true);
    const replay = await send(socketPath, signEdgeStatusRequest(request, key));
    const parsedReplay = authenticateEdgeStatusResponse(replay, request, key);
    assert.equal(parsedReplay.ok, false);
    if (!parsedReplay.ok) assert.equal(parsedReplay.resultClass, "REPLAY_DENIED");
  } finally {
    await server.close();
    key.fill(0);
    await assert.rejects(lstat(socketPath));
    await rm(root, { recursive: true, force: true });
  }
});

test("Edge status IPC fails closed when the lifecycle authority rejects a read", async () => {
  const root = await mkdtemp(join(tmpdir(), "e-n-"));
  const canonicalRoot = await realpath(root);
  const runtime = join(canonicalRoot, "runtime");
  const socketPath = join(runtime, "edge-status.sock");
  const key = Buffer.alloc(32, 0x52);
  await mkdir(runtime, { mode: 0o700 });
  const server = new EdgeStatusIpcServer({
    socketPath,
    authenticationKey: key,
    readStatus: status,
    authorizeStatus: () => { throw new Error("not ready"); },
    now: () => NOW
  });
  try {
    await server.listen();
    await assert.rejects(readEdgeStatus({ socketPath, authenticationKey: key, now: () => NOW }), /not ready|status request is invalid/u);
  } finally {
    await server.close();
    key.fill(0);
    await rm(root, { recursive: true, force: true });
  }
});

async function send(socketPath: string, value: unknown): Promise<EdgeStatusResponse> {
  return await new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    const chunks: Buffer[] = [];
    let total = 0;
    socket.once("error", reject);
    socket.once("connect", () => socket.end(`${JSON.stringify(value)}\n`));
    socket.on("data", (chunk: Buffer) => {
      total += chunk.byteLength;
      if (total > 128 * 1024) {
        socket.destroy();
        reject(new Error("response too large"));
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      socket.destroy();
      try { resolve(JSON.parse(combined.subarray(0, newline).toString("utf8")) as EdgeStatusResponse); }
      catch (error) { reject(error); }
    });
  });
}
