import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { chmod, mkdtemp, rm, stat } from "node:fs/promises";
import { createConnection, createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { signRequest, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { BrokerIpcServer, assertSocketNotActive, captureSocketPathIdentity, detachOwnedSocket, removeDetachedSocket, removeStaleSocket } from "./ipc-server.js";
import { MacOsPeerCredentialVerifier } from "./peer-credentials.js";
import { BrokerStore } from "./persistence.js";

test("IPC socket is owner-only and transports an authenticated request", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-ipc-"));
  const socketPath = join(directory, "broker.sock");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const now = Date.now();
  const keyring = new EdgeKeyring([{ edgeId: "edge-1", keyId: "edge-key-1", key, notBeforeMs: now - 1_000, expiresAtMs: now + 60_000 }]);
  const broker = new Broker({ store, policy: createDefaultPolicy("edge-1", true, ["mac.control.read"]), edgeAuthenticationKeys: keyring, now: () => now });
  const server = new BrokerIpcServer({ socketPath, broker, peerCredentialVerifier: currentProcessVerifier() });
  await server.listen();
  try {
    assert.equal((await stat(socketPath)).mode & 0o777, 0o600);
    const unsigned: UnsignedBrokerRequest = {
      protocolVersion: "0.1",
      requestId: "ipc-request-1",
      contractVersion: "0.1",
      tool: "mac_health",
      arguments: {},
      principal: {
        principalId: "principal-1", sessionId: "session-1", issuer: "test-issuer",
        audience: "mac-operator-broker", scopes: ["mac.control.read"],
        issuedAtMs: now - 1_000, expiresAtMs: now + 60_000, edgeId: "edge-1"
      },
      timestampMs: now,
      nonce: "ipc-nonce-1",
      policyAudience: "mac-operator-broker",
      policyVersion: "policy-0.1",
      authenticationKeyId: "edge-key-1"
    };
    const signed = signRequest(unsigned, key);
    const trailing = JSON.parse(await send(socketPath, `${JSON.stringify(signed)}\n{}\n`)) as {
      result_class: string;
      request_id: string;
      tool: string;
    };
    assert.deepEqual(trailing, {
      result_class: "PRECONDITION_FAILED",
      request_id: "invalid-request",
      tool: "unknown",
      ok: false,
      error: { message: "IPC request contains trailing data", retryable: false },
      duration_ms: 0
    });
    assert.deepEqual(store.auditRows(), []);
    const response = await send(socketPath, `${JSON.stringify(signed)}\n`);
    assert.equal((JSON.parse(response) as { response: { ok: boolean } }).response.ok, true);
  } finally {
    await server.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("IPC startup rejects a group-writable socket directory", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-ipc-unsafe-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const now = Date.now();
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", false, ["mac.control.read"]),
    edgeAuthenticationKeys: new EdgeKeyring([{ edgeId: "edge-1", keyId: "edge-key-1", key, notBeforeMs: now - 1_000, expiresAtMs: now + 60_000 }])
  });
  const server = new BrokerIpcServer({
    socketPath: join(directory, "broker.sock"),
    broker,
    peerCredentialVerifier: currentProcessVerifier()
  });
  try {
    await chmod(directory, 0o770);
    await assert.rejects(server.listen(), /must not be writable/u);
  } finally {
    store.close();
    await chmod(directory, 0o700);
    await rm(directory, { recursive: true, force: true });
  }
});

test("IPC startup refuses to unlink an active socket", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-ipc-active-"));
  const socketPath = join(directory, "active.sock");
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, resolve);
  });
  try {
    await assert.rejects(removeStaleSocket(socketPath), /already active/u);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    await rm(directory, { recursive: true, force: true });
  }
});

test("IPC startup preflight rejects an active listener without unlinking it", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-ipc-preflight-"));
  const socketPath = join(directory, "active.sock");
  const server = createServer();
  await listenServer(server, socketPath);
  try {
    await assert.rejects(assertSocketNotActive(socketPath), /already active/u);
    assert.equal((await stat(socketPath)).isSocket(), true);
  } finally {
    await closeServer(server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("IPC close fences a replacement listener while closing", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-ipc-replacement-"));
  const socketPath = join(directory, "replacement.sock");
  const first = createServer();
  const blocked = createServer();
  const second = createServer();
  await listenServer(first, socketPath);
  const firstIdentity = await captureSocketPathIdentity(socketPath);
  const detached = await detachOwnedSocket(socketPath, firstIdentity);
  try {
    await assert.rejects(listenServer(blocked, socketPath), /EADDRINUSE/u);
    await closeServer(first);
    await listenServer(second, socketPath);
    assert.equal((await stat(socketPath)).isSocket(), true);
    await removeDetachedSocket(detached);
  } finally {
    await closeServer(blocked).catch(() => undefined);
    await closeServer(second);
    await rm(directory, { recursive: true, force: true });
  }
});

test("IPC server drops a connection when OS peer credential policy denies it", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-ipc-peer-deny-"));
  const socketPath = join(directory, "broker.sock");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const now = Date.now();
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.control.read"]),
    edgeAuthenticationKeys: new EdgeKeyring([{
      edgeId: "edge-1",
      keyId: "edge-key-1",
      key,
      notBeforeMs: now - 1_000,
      expiresAtMs: now + 60_000
    }]),
    now: () => now
  });
  const server = new BrokerIpcServer({
    socketPath,
    broker,
    peerCredentialVerifier: { verify() { throw new Error("denied"); } }
  });
  await server.listen();
  try {
    try {
      assert.equal(await send(socketPath, "{}\n"), "");
    } catch (error) {
      assert.match(String((error as NodeJS.ErrnoException).code), /^(?:EPIPE|ECONNRESET)$/u);
    }
    assert.deepEqual(store.auditRows(), []);
  } finally {
    await server.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

function send(socketPath: string, body: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    let response = "";
    socket.setEncoding("utf8");
    socket.on("connect", () => socket.write(body));
    socket.on("data", (chunk: string) => { response += chunk; });
    socket.on("end", () => resolve(response.trim()));
    socket.on("error", reject);
  });
}

function currentProcessVerifier(): MacOsPeerCredentialVerifier {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined) throw new Error("POSIX identity is unavailable");
  return new MacOsPeerCredentialVerifier({
    expectedUid: uid,
    expectedGid: gid,
    allowedProcessIds: new Set([process.pid])
  });
}

function listenServer(server: ReturnType<typeof createServer>, socketPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, resolve);
  });
}

function closeServer(server: ReturnType<typeof createServer>): Promise<void> {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
