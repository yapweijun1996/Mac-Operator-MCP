import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { createServer } from "node:net";
import { join } from "node:path";
import test from "node:test";
import type { BrokerRequest } from "@mac-operator/contracts";
import { Broker } from "@mac-operator/broker";
import {
  BrokerIpcServer,
  BrokerStore,
  createDefaultPolicy,
  EdgeKeyring,
  MacOsPeerCredentialVerifier
} from "@mac-operator/broker";
import { BrokerIpcClient } from "./ipc-client.js";
import { EdgeRequestFactory } from "./request-factory.js";

test("Edge authenticates a complete Broker IPC round trip", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-edge-ipc-"));
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
  const server = new BrokerIpcServer({ socketPath, broker, peerCredentialVerifier: currentProcessVerifier() });
  await server.listen();
  try {
    const factory = new EdgeRequestFactory({
      authenticationKey: key,
      authenticationKeyId: "edge-key-1",
      brokerAudience: "mac-operator-broker",
      policyVersion: () => "policy-0.1",
      now: () => now,
      randomId: (() => {
        let value = 0;
        return () => `edge-id-${++value}`;
      })()
    });
    const request = factory.create("mac_health", {}, {
      principalId: "principal-1",
      sessionId: "session-1",
      issuer: "test-issuer",
      audience: "mac-operator-broker",
      scopes: ["mac.control.read"],
      issuedAtMs: now - 1_000,
      expiresAtMs: now + 60_000,
      edgeId: "edge-1"
    });
    assert.equal("authenticationKey" in request, false);
    const response = await new BrokerIpcClient(socketPath, (candidate, envelope) => factory.verifyResponse(candidate, envelope)).call(request);
    assert.equal(response.ok, true);
    assert.equal(response.request_id, request.requestId);
    assert.equal(response.tool, "mac_health");
  } finally {
    await server.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Edge rejects a forged response from a replaced local socket", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-edge-forged-"));
  const socketPath = join(directory, "broker.sock");
  const store = new BrokerStore(join(directory, "forged.sqlite"));
  const key = randomBytes(32);
  const attackerKey = randomBytes(32);
  const now = Date.now();
  const attackerBroker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.control.read"]),
    edgeAuthenticationKeys: new EdgeKeyring([{
      edgeId: "edge-1",
      keyId: "edge-key-1",
      key: attackerKey,
      notBeforeMs: now - 1_000,
      expiresAtMs: now + 60_000
    }]),
    now: () => now
  });
  const server = new BrokerIpcServer({
    socketPath,
    broker: attackerBroker,
    peerCredentialVerifier: currentProcessVerifier()
  });
  await server.listen();
  const factory = new EdgeRequestFactory({
    authenticationKey: key,
    authenticationKeyId: "edge-key-1",
    brokerAudience: "mac-operator-broker",
    policyVersion: () => "policy-0.1",
    now: () => now,
    randomId: () => "edge-id"
  });
  const request = factory.create("mac_health", {}, {
    principalId: "principal-1",
    sessionId: "session-1",
    issuer: "test-issuer",
    audience: "mac-operator-broker",
    scopes: ["mac.control.read"],
    issuedAtMs: now - 1_000,
    expiresAtMs: now + 60_000,
    edgeId: "edge-1"
  });
  try {
    await assert.rejects(
      new BrokerIpcClient(socketPath, (candidate, envelope) => factory.verifyResponse(candidate, envelope)).call(request),
      /not authenticated/u
    );
  } finally {
    await server.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Edge IPC client rejects an unsafe socket directory before connecting", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-edge-ipc-directory-"));
  const socketPath = join(directory, "broker.sock");
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, resolve);
  });
  try {
    await chmod(directory, 0o750);
    const client = new BrokerIpcClient(socketPath, () => false);
    await assert.rejects(
      client.call({} as BrokerRequest),
      /socket directory failed ownership or permission checks/u
    );
  } finally {
    await chmod(directory, 0o700);
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  }
});

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
