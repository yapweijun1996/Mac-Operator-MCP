import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { signRequest, verifyBrokerResponse, type AuthenticatedBrokerResponse, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { BrokerStore } from "./persistence.js";

test("Broker IPC response signs the immutable request parsed before async dispatch", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-ipc-request-snapshot-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const nowMs = 1_800_000_000_000;
  const unsigned: UnsignedBrokerRequest = {
    protocolVersion: "0.1",
    requestId: "request:ipc-snapshot",
    contractVersion: "0.1",
    tool: "mac_health",
    arguments: {},
    principal: {
      principalId: "principal-1",
      sessionId: "session-ipc-snapshot",
      issuer: "test-issuer",
      audience: "mac-operator-broker",
      scopes: ["mac.control.read"],
      issuedAtMs: nowMs - 1_000,
      expiresAtMs: nowMs + 30_000,
      edgeId: "edge-ipc-snapshot"
    },
    timestampMs: nowMs,
    nonce: "nonce:ipc-snapshot",
    policyAudience: "mac-operator-broker",
    policyVersion: "policy-0.1",
    authenticationKeyId: "edge-key-ipc-snapshot"
  };
  const request = signRequest(unsigned, key);
  let mutateCallerObject = true;
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-ipc-snapshot", true, ["mac.control.read"], ["edge-key-ipc-snapshot"]),
    edgeAuthenticationKeys: new EdgeKeyring([{
      edgeId: "edge-ipc-snapshot",
      keyId: "edge-key-ipc-snapshot",
      key,
      notBeforeMs: nowMs - 10_000,
      expiresAtMs: nowMs + 60_000
    }]),
    now: () => {
      if (mutateCallerObject) {
        mutateCallerObject = false;
        (request.arguments as Record<string, unknown>).include_components = true;
        request.principal.principalId = "attacker-principal";
      }
      return nowMs;
    }
  });
  try {
    const response = await broker.handleForIpc(request);
    assert.equal("response" in response, true);
    const authenticated = response as AuthenticatedBrokerResponse;
    assert.equal(authenticated.response.ok, true, JSON.stringify(authenticated.response));
    assert.equal(verifyBrokerResponse(request, authenticated, key), true);
    if (authenticated.response.ok) {
      assert.deepEqual(authenticated.response.data, {
        overall: "healthy",
        components: [{ name: "broker", status: "healthy", version: "0.1.0" }]
      });
    }
  } finally {
    await broker.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
    key.fill(0);
  }
});
