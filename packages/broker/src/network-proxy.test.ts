import assert from "node:assert/strict";
import { createConnection, createServer, type Socket } from "node:net";
import test from "node:test";
import { BrokerError, canonicalJson, parseJsonUtf8Strict } from "@mac-operator/contracts";
import {
  BrokerNetworkProxy,
  BrokerNetworkProxyChannel,
  createBrokerNetworkProxyPolicy
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
