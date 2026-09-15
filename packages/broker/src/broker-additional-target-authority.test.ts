import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { signRequest, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import type { FilesystemExecutor } from "./filesystem-executor.js";
import { BrokerStore } from "./persistence.js";
import { PolicyManager } from "./policy-loader.js";

const NOW = 1_700_000_000_000;

function testKeyring(key: Buffer): EdgeKeyring {
  return new EdgeKeyring([{
    edgeId: "edge-1",
    keyId: "edge-key-1",
    key,
    notBeforeMs: NOW - 60_000,
    expiresAtMs: NOW + 60_000
  }]);
}

function request(roots: readonly string[]): UnsignedBrokerRequest {
  return {
    protocolVersion: "0.1",
    requestId: "find-additional-target-revocation",
    contractVersion: "0.1",
    tool: "mac_find_files",
    arguments: { roots: [...roots], query: "safe", max_results: 10 },
    principal: {
      principalId: "principal-1",
      sessionId: "session-1",
      issuer: "test-issuer",
      audience: "mac-operator-broker",
      scopes: ["mac.files.search"],
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 60_000,
      edgeId: "edge-1"
    },
    timestampMs: NOW,
    nonce: "find-additional-target-revocation-nonce",
    policyAudience: "mac-operator-broker",
    policyVersion: "policy-0.1",
    authenticationKeyId: "edge-key-1"
  };
}

test("Broker rejects success when a multi-root additional target is revoked before readback", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-additional-target-authority-"));
  const firstRoot = join(directory, "first");
  const secondRoot = join(directory, "second");
  await mkdir(firstRoot);
  await mkdir(secondRoot);
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const roots = [
    { rootId: "first-root", path: firstRoot, metadata: true, contentRead: false, denyRelativePaths: [] },
    { rootId: "second-root", path: secondRoot, metadata: true, contentRead: false, denyRelativePaths: [] }
  ] as const;
  const initialPolicy = createDefaultPolicy("edge-1", true, ["mac.files.search"], ["edge-key-1"], roots);
  const policyManager = new PolicyManager(initialPolicy);
  const revokedPolicy = {
    ...initialPolicy,
    revision: initialPolicy.revision + 1,
    targetRules: initialPolicy.targetRules.filter((rule) => rule.target.reference !== "second-root")
  };
  let policyRevokedDuringDispatch = false;
  const filesystemExecutor: FilesystemExecutor = {
    stat: async () => { throw new Error("Unexpected stat"); },
    read: async () => { throw new Error("Unexpected read"); },
    find: async (plans, query) => {
      policyManager.activate({ policy: revokedPolicy, payloadDigest: "a".repeat(64), keyId: "test-policy-key" });
      policyRevokedDuringDispatch = true;
      return {
        operation: "find",
        roots: plans.map((plan) => plan.requestedPath),
        query,
        matches: [],
        truncated: false
      };
    }
  };
  const broker = new Broker({
    store,
    policy: policyManager,
    edgeAuthenticationKeys: testKeyring(key),
    filesystemExecutor,
    now: () => NOW
  });
  try {
    const result = await broker.handle(signRequest(request([firstRoot, secondRoot]), key));
    assert.equal(policyRevokedDuringDispatch, true);
    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(result.result_class, "CANCELLED");
    assert.equal(store.requestRecord("find-additional-target-revocation")?.state, "CANCELLED");
    assert.equal(store.auditRows().at(-1)?.result_class, "CANCELLED");
  } finally {
    await broker.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
