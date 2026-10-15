import assert from "node:assert/strict";
import { connect, createServer, type Socket } from "node:net";
import { chmod, lstat, mkdtemp, mkdir, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
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

for (const response of ["empty", "partial", "reset", "drip"] as const) {
  test(`Edge status read terminates after ${response} response without a complete frame`, async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), "e-eof-")));
    await chmod(root, 0o700);
    const socketPath = join(root, "status.sock");
    const sockets = new Set<Socket>();
    const server = createServer((socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
      socket.once("data", () => {
        if (response === "empty") socket.end();
        else if (response === "partial") socket.end('{"ok":');
        else if (response === "reset") socket.destroy();
        else {
          socket.write("{");
          const interval = setInterval(() => socket.write(" "), 15);
          socket.once("close", () => clearInterval(interval));
        }
      });
    });
    let watchdog: ReturnType<typeof setTimeout> | undefined;
    try {
      await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(socketPath, resolve); });
      await chmod(socketPath, 0o600);
      const read = readEdgeStatus({ socketPath, authenticationKey: Buffer.alloc(32, 0x53), timeoutMs: 100 });
      const bounded = Promise.race([read, new Promise<never>((_resolve, reject) => {
        watchdog = setTimeout(() => reject(new Error("Status read exceeded regression watchdog")), 2_000);
      })]);
      await assert.rejects(bounded, (error: unknown) => error instanceof BrokerError &&
        error.errorClass === (response === "drip" ? "TIMEOUT" : "EXECUTION_FAILED"));
    } finally {
      clearTimeout(watchdog);
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      await rm(root, { recursive: true, force: true });
    }
  });
}
