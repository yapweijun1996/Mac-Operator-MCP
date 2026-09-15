import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonicalJson, sha256, signRequest, type Scope, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { BrokerStore } from "./persistence.js";
import { BrokerPrivilegedHelperCommandFactory } from "./privileged-helper.js";
import { PrivilegedHelperJobExecutor } from "./privileged-helper-executor.js";
import type { BrokerPolicy } from "./policy.js";

const NOW = 1_700_000_000_000;

function keyring(key: Buffer): EdgeKeyring {
  return new EdgeKeyring([{
    edgeId: "edge-1",
    keyId: "edge-key-1",
    key,
    notBeforeMs: 0,
    expiresAtMs: Number.MAX_SAFE_INTEGER
  }]);
}

function request(key: Buffer, scopes: readonly Scope[]): ReturnType<typeof signRequest> {
  const unsigned: UnsignedBrokerRequest = {
    protocolVersion: "0.1",
    requestId: "request-privileged-dispatch",
    contractVersion: "0.1",
    tool: "mac_priv_service_control",
    arguments: { service_id: "system/com.example.test", action: "start", expected_state: "running" },
    principal: {
      principalId: "principal-1",
      sessionId: "session-privileged",
      issuer: "test-issuer",
      audience: "mac-operator-broker",
      scopes: [...scopes],
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 60_000,
      edgeId: "edge-1"
    },
    timestampMs: NOW,
    nonce: "nonce-privileged-dispatch",
    policyAudience: "mac-operator-broker",
    policyVersion: "policy-0.1",
    authenticationKeyId: "edge-key-1"
  };
  return signRequest(unsigned, key);
}

function enabledPolicy(): BrokerPolicy {
  const base = createDefaultPolicy("edge-1", false, ["mac.priv.service"]);
  const tool = base.tools.get("mac_priv_service_control");
  assert.ok(tool);
  return {
    ...base,
    targetRules: [
      ...base.targetRules,
      {
        ruleId: "privileged-service-allow",
        effect: "allow",
        principalId: "principal-1",
        scope: "mac.priv.service",
        target: { kind: "service", reference: "system/com.example.test" }
      }
    ],
    tools: new Map(base.tools).set("mac_priv_service_control", { ...tool, implemented: true, enabled: true })
  };
}

test("Broker dispatches an approved privileged Job through the helper boundary", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-privileged-dispatch-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const edgeKey = randomBytes(32);
  const helperKey = randomBytes(32);
  const input = request(edgeKey, ["mac.priv.service"]);
  const payload = {
    operation: "service_control" as const,
    service_id: "system/com.example.test",
    action: "start" as const,
    expected_state: "running" as const
  };
  store.issueApproval({
    approvalId: "approval:privileged-dispatch",
    approverPrincipalId: "operator-1",
    requestingPrincipalId: "principal-1",
    tool: input.tool,
    contractVersion: input.contractVersion,
    targetKind: "service",
    targetRef: "service:system/com.example.test",
    payloadDigest: sha256(canonicalJson(payload)),
    policyVersion: input.policyVersion,
    approvalClass: "explicit_privileged_policy",
    unattended: false,
    issuedAtMs: NOW - 1_000,
    expiresAtMs: NOW + 60_000
  });
  const commandFactory = new BrokerPrivilegedHelperCommandFactory({
    store,
    authenticationKey: helperKey,
    authorizeCommand: () => undefined,
    now: () => NOW
  });
  const executor = new PrivilegedHelperJobExecutor({
    store,
    enabled: true,
    commandFactory,
    commandClient: async (command) => ({
      ok: true as const,
      commandId: command.commandId,
      requestId: command.requestId,
      result: {
        operation: "service_control" as const,
        targetRef: command.targetRef,
        state: "completed" as const,
        resultClass: "SUCCEEDED" as const,
        evidence: { pre_state: "stopped", post_state: "running" },
        warnings: [],
        truncated: false,
        verification: { status: "verified" as const, strategy: "allowlisted_postcondition" as const }
      },
      responseProof: ""
    }),
    now: () => NOW
  });
  const broker = new Broker({ store, policy: enabledPolicy(), edgeAuthenticationKeys: keyring(edgeKey), privilegedHelperExecutor: executor, now: () => NOW });
  try {
    const result = await broker.handle(input);
    assert.equal(result.ok, true, JSON.stringify(result));
    if (result.ok) {
      const requestRecord = store.requestRecord(input.requestId);
      const jobId = requestRecord?.jobId;
      assert.ok(jobId);
      assert.equal(result.tool, "mac_priv_service_control");
      assert.deepEqual(result.data, {
        service_id: "system/com.example.test",
        action: "start",
        pre_state: "stopped",
        post_state: "running",
        verification_status: "verified",
        job_id: jobId
      });
    }
    assert.equal(store.requestRecord(input.requestId)?.state, "SUCCEEDED");
    const jobId = store.requestRecord(input.requestId)?.jobId;
    assert.ok(jobId);
    assert.equal(store.ownedJob(jobId, "principal-1")?.state, "completed");
  } finally {
    commandFactory.dispose();
    await broker.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Broker refuses privileged admission when the helper boundary is disabled", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-privileged-disabled-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const edgeKey = randomBytes(32);
  const input = request(edgeKey, ["mac.priv.service"]);
  const payload = {
    operation: "service_control" as const,
    service_id: "system/com.example.test",
    action: "start" as const,
    expected_state: "running" as const
  };
  store.issueApproval({
    approvalId: "approval:privileged-disabled",
    approverPrincipalId: "operator-1",
    requestingPrincipalId: "principal-1",
    tool: input.tool,
    contractVersion: input.contractVersion,
    targetKind: "service",
    targetRef: "service:system/com.example.test",
    payloadDigest: sha256(canonicalJson(payload)),
    policyVersion: input.policyVersion,
    approvalClass: "explicit_privileged_policy",
    unattended: false,
    issuedAtMs: NOW - 1_000,
    expiresAtMs: NOW + 60_000
  });
  const broker = new Broker({ store, policy: enabledPolicy(), edgeAuthenticationKeys: keyring(edgeKey), now: () => NOW });
  try {
    const result = await broker.handle(input);
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.result_class, "POLICY_DENIED");
    assert.equal(store.requestRecord(input.requestId)?.jobId, null);
  } finally {
    await broker.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
