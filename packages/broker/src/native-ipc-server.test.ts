import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { chmod, mkdtemp, rm, stat } from "node:fs/promises";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { signRequest, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { MacOsNativeBrokerIpcServer } from "./native-ipc-server.js";
import { BrokerStore } from "./persistence.js";

test("native IPC accepts a peer-authenticated fd through public Socket({ fd })", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-native-ipc-"));
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
  const server = new MacOsNativeBrokerIpcServer({
    socketPath,
    broker,
    peerPolicy: currentProcessPeerPolicy()
  });
  await server.listen();
  try {
    assert.equal((await stat(socketPath)).mode & 0o777, 0o600);
    const unsigned: UnsignedBrokerRequest = {
      protocolVersion: "0.1",
      requestId: "native-ipc-request-1",
      contractVersion: "0.1",
      tool: "mac_health",
      arguments: {},
      principal: {
        principalId: "principal-1", sessionId: "session-1", issuer: "test-issuer",
        audience: "mac-operator-broker", scopes: ["mac.control.read"],
        issuedAtMs: now - 1_000, expiresAtMs: now + 60_000, edgeId: "edge-1"
      },
      timestampMs: now,
      nonce: "native-ipc-nonce-1",
      policyAudience: "mac-operator-broker",
      policyVersion: "policy-0.1",
      authenticationKeyId: "edge-key-1"
    };
    const response = JSON.parse(await send(socketPath, `${JSON.stringify(signRequest(unsigned, key))}\n`)) as {
      response: { ok: boolean; tool: string };
    };
    assert.equal(response.response.ok, true);
    assert.equal(response.response.tool, "mac_health");
  } finally {
    await server.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("native IPC drops a denied peer before parsing or auditing", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-native-ipc-"));
  const socketPath = join(directory, "broker.sock");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const now = Date.now();
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.control.read"]),
    edgeAuthenticationKeys: new EdgeKeyring([{
      edgeId: "edge-1", keyId: "edge-key-1", key: randomBytes(32),
      notBeforeMs: now - 1_000, expiresAtMs: now + 60_000
    }]),
    now: () => now
  });
  const server = new MacOsNativeBrokerIpcServer({
    socketPath,
    broker,
    peerPolicy: { expectedUid: process.getuid?.() ?? -1, allowedProcessIds: new Set([process.pid + 1]) }
  });
  await server.listen();
  try {
    try {
      assert.equal(await send(socketPath, "not-json\n"), "");
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

test("native IPC refuses an unsafe parent directory", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-native-ipc-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const now = Date.now();
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1"),
    edgeAuthenticationKeys: new EdgeKeyring([{
      edgeId: "edge-1", keyId: "edge-key-1", key: randomBytes(32),
      notBeforeMs: now - 1_000, expiresAtMs: now + 60_000
    }]),
    now: () => now
  });
  const server = new MacOsNativeBrokerIpcServer({
    socketPath: join(directory, "broker.sock"),
    broker,
    peerPolicy: currentProcessPeerPolicy()
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

function currentProcessPeerPolicy(): { expectedUid: number; expectedGid: number; allowedProcessIds: ReadonlySet<number> } {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined) throw new Error("POSIX identity is unavailable");
  return { expectedUid: uid, expectedGid: gid, allowedProcessIds: new Set([process.pid]) };
}

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
