import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { createConnection, createServer, type Socket } from "node:net";
import test from "node:test";
import { BrokerError, canonicalJson, parseJsonUtf8Strict } from "@mac-operator/contracts";
import {
  BrokerNetworkProxy,
  BrokerNetworkProxyChannel,
  createBrokerNetworkProxyPolicy,
  type BrokerNetworkProxyExchangeControl
} from "./network-proxy.js";

test("BrokerNetworkProxy remains disabled unless explicitly enabled", async () => {
  const policy = createBrokerNetworkProxyPolicy({
    policyId: "tests.network",
    destinations: ["tcp://localhost:43123"]
  });
  const proxy = new BrokerNetworkProxy({ policy });
  await assert.rejects(
    proxy.exchange({ requestId: "network-request:disabled-1", target: "tcp://localhost:43123", payload: Buffer.from("safe") }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
});

class ChannelSocketFixture extends EventEmitter {
  destroyed = false;
  setNoDelay(): void {}
  destroy(): void { this.destroyed = true; this.emit("close"); }
  write(_frame: Buffer, callback: (error?: Error) => void): void { callback(); }
}

function blockedChannel(maxRequests = 32): {
  socket: ChannelSocketFixture; channel: BrokerNetworkProxyChannel; controls: BrokerNetworkProxyExchangeControl[];
} {
  const socket = new ChannelSocketFixture();
  const controls: BrokerNetworkProxyExchangeControl[] = [];
  const proxy = new BrokerNetworkProxy({ enabled: true,
    policy: createBrokerNetworkProxyPolicy({ policyId: "tests.channel-admission", destinations: ["tcp://localhost:43123"] }) });
  proxy.exchange = async (_request, control = {}) => {
    controls.push(control);
    return await new Promise((_resolve, reject) => {
      control.signal!.addEventListener("abort", () => reject(new BrokerError("CANCELLED", "Cancelled fixture exchange")), { once: true });
    });
  };
  const channel = new BrokerNetworkProxyChannel({ socket: socket as unknown as Socket, proxy,
    capabilityToken: "a".repeat(64), maxRequests });
  channel.start();
  return { socket, channel, controls };
}

function channelFrame(index: number, bytes = 32 * 1024): Buffer {
  return Buffer.from(`${canonicalJson({ schemaVersion: "0.1", kind: "network_request",
    requestId: `child-network:queued-${index.toString().padStart(4, "0")}`, capabilityToken: "a".repeat(64),
    target: "tcp://localhost:43123", payloadBase64: Buffer.alloc(bytes, "x").toString("base64") })}\n`);
}

test("Channel request admission closes a flood while the first exchange is blocked", async () => {
  const { socket, channel, controls } = blockedChannel(1);
  socket.emit("data", channelFrame(0));
  await Promise.resolve();
  assert.equal(controls.length, 1);
  for (let index = 1; index <= 300; index++) socket.emit("data", channelFrame(index));
  assert.equal(socket.destroyed, true);
  assert.equal(controls[0]!.signal!.aborted, true);
  await channel.close();
  assert.equal(controls.length, 1, "queued flood never starts another upstream exchange");
});

test("Channel caps retained queued bytes independently of its request budget", async () => {
  const { socket, channel, controls } = blockedChannel();
  socket.emit("data", channelFrame(0));
  await Promise.resolve();
  for (let index = 1; index <= 8; index++) socket.emit("data", channelFrame(index, 64 * 1024));
  assert.equal(socket.destroyed, true, "nine requests are below the count budget but exceed the queued byte cap");
  await channel.close();
  assert.equal(controls.length, 1);
});

for (const peerClosed of [false, true]) {
  test(`Channel ${peerClosed ? "peer disconnect" : "close"} aborts and drains the active upstream exchange`, async () => {
    const { socket, channel, controls } = blockedChannel();
    socket.emit("data", channelFrame(0));
    await Promise.resolve();
    if (peerClosed) socket.emit("close");
    await channel.close();
    assert.equal(controls[0]!.signal!.aborted, true);
    assert.equal(socket.destroyed, true);
    assert.equal(controls.length, 1);
  });
}

test("Network proxy abort signal promptly ends a stalled exchange before its long deadline", async () => {
  const sockets = new Set<Socket>();
  let connected!: () => void;
  const connection = new Promise<void>(resolve => { connected = resolve; });
  const server = createServer({ allowHalfOpen: true }, socket => {
    sockets.add(socket); socket.once("close", () => sockets.delete(socket)); socket.resume(); connected();
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("Network fixture did not expose a numeric port");
  const target = `tcp://localhost:${address.port}`;
  const proxy = new BrokerNetworkProxy({ enabled: true,
    policy: createBrokerNetworkProxyPolicy({ policyId: "tests.channel-abort", destinations: [target], timeoutMs: 60_000 }) });
  const abort = new AbortController();
  try {
    const exchange = proxy.exchange({ requestId: "network-request:signal-0001", target, payload: Buffer.from("safe") }, { signal: abort.signal });
    const rejected = assert.rejects(exchange, error => error instanceof BrokerError && error.errorClass === "CANCELLED");
    await connection;
    abort.abort();
    await rejected;
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});

test("BrokerNetworkProxy exchanges only with the digest-bound loopback target", async () => {
  const server = createServer({ allowHalfOpen: true }, (socket) => {
    socket.on("data", (chunk) => socket.end(Buffer.from(`reply:${chunk.toString("utf8")}`, "utf8")));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("Network fixture did not expose a numeric port");
  const target = `tcp://localhost:${address.port}`;
  const policy = createBrokerNetworkProxyPolicy({ policyId: "tests.network", destinations: [target] });
  const proxy = new BrokerNetworkProxy({ enabled: true, policy });
  try {
    const result = await proxy.exchange({
      requestId: "network-request:allowed-1",
      target,
      payload: Buffer.from("hello", "utf8")
    });
    assert.equal(result.target, target);
    assert.equal(result.response.toString("utf8"), "reply:hello");
    assert.equal(result.responseSha256.length, 64);
    await assert.rejects(
      proxy.exchange({
        requestId: "network-request:allowed-1",
        target,
        payload: Buffer.from("hello", "utf8")
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "REPLAY_DENIED"
    );
    await assert.rejects(
      proxy.exchange({
        requestId: "network-request:denied-1",
        target: `tcp://localhost:${address.port + 1}`,
        payload: Buffer.from("should-not-connect", "utf8")
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "NETWORK_DENIED"
    );
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("BrokerNetworkProxy rejects policy drift, secret payloads, and oversized responses", async () => {
  const policy = createBrokerNetworkProxyPolicy({
    policyId: "tests.network",
    destinations: ["tcp://127.0.0.1:43123"],
    maxRequestBytes: 64,
    maxResponseBytes: 8
  });
  assert.equal(policy.destinations[0], "tcp://localhost:43123");
  assert.throws(
    () => new BrokerNetworkProxy({ policy: { ...policy, destinations: ["tcp://localhost:43124"] } }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  const proxy = new BrokerNetworkProxy({ enabled: true, policy });
  await assert.rejects(
    proxy.exchange({ requestId: "network-request:secret-1", target: "tcp://localhost:43123", payload: Buffer.from("Bearer abcdefghijklmnop") }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  await assert.rejects(
    proxy.exchange({ requestId: "network-request:large-01", target: "tcp://localhost:43123", payload: Buffer.alloc(65) }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "OUTPUT_LIMIT"
  );
});

test("BrokerNetworkProxy maps cancellation and timeout without leaving a socket", async () => {
  const sockets = new Set<import("node:net").Socket>();
  const server = createServer({ allowHalfOpen: true }, (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    socket.resume();
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("Network fixture did not expose a numeric port");
  const policy = createBrokerNetworkProxyPolicy({
    policyId: "tests.network",
    destinations: [`tcp://localhost:${address.port}`],
    timeoutMs: 100
  });
  const proxy = new BrokerNetworkProxy({ enabled: true, policy });
  try {
    await assert.rejects(
      proxy.exchange({ requestId: "network-request:cancel-1", target: `tcp://localhost:${address.port}`, payload: Buffer.from("safe") }, { shouldCancel: () => true }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
    );
    await assert.rejects(
      proxy.exchange({ requestId: "network-request:timeout-1", target: `tcp://localhost:${address.port}`, payload: Buffer.from("safe") }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "TIMEOUT"
    );
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("BrokerNetworkProxyChannel authenticates a child frame and returns only the bound proxy response", async () => {
  const targetServer = createServer((socket) => {
    socket.on("data", (chunk) => socket.end(Buffer.from(`reply:${chunk.toString("utf8")}`, "utf8")));
  });
  await new Promise<void>((resolve, reject) => {
    targetServer.once("error", reject);
    targetServer.listen(0, "127.0.0.1", () => resolve());
  });
  const targetAddress = targetServer.address();
  if (targetAddress === null || typeof targetAddress === "string") throw new Error("Target fixture did not expose a port");
  const target = `tcp://localhost:${targetAddress.port}`;
  const proxy = new BrokerNetworkProxy({
    enabled: true,
    policy: createBrokerNetworkProxyPolicy({ policyId: "tests.channel", destinations: [target] })
  });
  const capabilityToken = "a".repeat(64);
  const channelServer = createServer((socket) => {
    const channel = new BrokerNetworkProxyChannel({ socket, proxy, capabilityToken });
    channel.start();
  });
  await new Promise<void>((resolve, reject) => {
    channelServer.once("error", reject);
    channelServer.listen(0, "127.0.0.1", () => resolve());
  });
  const channelAddress = channelServer.address();
  if (channelAddress === null || typeof channelAddress === "string") throw new Error("Channel fixture did not expose a port");
  let client: Socket | undefined;
  try {
    client = createConnection(channelAddress.port, "127.0.0.1");
    await new Promise<void>((resolve, reject) => {
      client!.once("error", reject);
      client!.once("connect", () => resolve());
    });
    client.write(`${canonicalJson({
      schemaVersion: "0.1",
      kind: "network_request",
      requestId: "child-network:request-0001",
      capabilityToken,
      target,
      payloadBase64: Buffer.from("hello", "utf8").toString("base64")
    })}\n`);
    const result = await new Promise<Record<string, unknown>>((resolve, reject) => {
      let pending = Buffer.alloc(0);
      client!.once("error", reject);
      client!.on("data", (chunk) => {
        pending = Buffer.concat([pending, chunk]);
        const newline = pending.indexOf(0x0a);
        if (newline < 0) return;
        resolve(parseJsonUtf8Strict(pending.subarray(0, newline)) as Record<string, unknown>);
      });
    });
    assert.equal(result.ok, true);
    assert.equal(result.requestId, "child-network:request-0001");
    assert.equal(Buffer.from(result.responseBase64 as string, "base64").toString("utf8"), "reply:hello");
  } finally {
    client?.destroy();
    await new Promise<void>((resolve) => channelServer.close(() => resolve()));
    await new Promise<void>((resolve) => targetServer.close(() => resolve()));
  }
});
