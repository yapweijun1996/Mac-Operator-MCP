import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError, canonicalJson, sha256, signRequest, type Scope, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { BrokerStore } from "./persistence.js";
import type { BrokerPolicy } from "./policy.js";
import {
  UserServiceControlAdapter,
  type UserServiceControlCommandRunner,
  type UserServiceReadbackObserver,
  type UserServiceSourceRevisionReader
} from "./user-service-control.js";
import type { LaunchdJobReadback } from "./launchd-readback.js";
import type { ProcessExecutionRequest, ProcessExecutionResult } from "./process-supervisor.js";
import { UserServiceControlJobExecutor } from "./user-service-control-executor.js";

const NOW = 1_700_000_000_000;
const UID = typeof process.getuid === "function" ? process.getuid() : 501;
const SERVICE_ID = `gui/${UID}/com.mac-operator.test`;
const SOURCE_REVISION = "abcdef1";

function keyring(key: Buffer): EdgeKeyring {
  return new EdgeKeyring([{
    edgeId: "edge-1",
    keyId: "edge-key-1",
    key,
    notBeforeMs: NOW - 60_000,
    expiresAtMs: NOW + 60_000
  }]);
}

function unsigned(requestId: string, nonce: string, argumentsValue: Record<string, unknown>, scopes: readonly Scope[] = ["mac.control.read"]): UnsignedBrokerRequest {
  return {
    protocolVersion: "0.1",
    requestId,
    contractVersion: "0.1",
    tool: "mac_service_control",
    arguments: argumentsValue,
    principal: {
      principalId: "principal-1",
      sessionId: "session-1",
      issuer: "test-issuer",
      audience: "mac-operator-broker",
      scopes,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 60_000,
      edgeId: "edge-1"
    },
    timestampMs: NOW,
    nonce,
    policyAudience: "mac-operator-broker",
    policyVersion: "policy-0.1",
    authenticationKeyId: "edge-key-1"
  };
}

function launchd(state: "running" | "stopped"): LaunchdJobReadback {
  return {
    serviceId: SERVICE_ID,
    domain: `gui/${UID}`,
    label: "com.mac-operator.test",
    type: "LaunchAgent",
    state,
    pid: state === "running" ? 1234 : null,
    program: "/bin/true",
    arguments: ["/bin/true"],
    plistPath: "/Users/test/Library/LaunchAgents/com.mac-operator.test.plist",
    lastExitCode: 0,
    truncated: false
  };
}

function commandResult(): ProcessExecutionResult {
  return {
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
    signal: null,
    stdout: "",
    stderr: "",
    truncated: false,
    durationMs: 1,
    processId: 123,
    processGroupId: 123,
    terminationObserved: true
  };
}

function failedCommandResult(): ProcessExecutionResult {
  return {
    ...commandResult(),
    state: "failed",
    resultClass: "EXECUTION_FAILED",
    exitCode: 1
  };
}

interface CandidateFixtureOptions {
  states?: readonly ("running" | "stopped")[];
  commandResult?: ProcessExecutionResult;
  onCommand?: () => void | Promise<void>;
}

function candidateFixture(store: BrokerStore, options: CandidateFixtureOptions = {}): { adapter: UserServiceControlAdapter; commands: ProcessExecutionRequest[] } {
  const commands: ProcessExecutionRequest[] = [];
  const states: Array<"running" | "stopped"> = [...(options.states ?? ["stopped", "stopped", "running", "running"])] as Array<"running" | "stopped">;
  const observer: UserServiceReadbackObserver = {
    inspect: async () => {
      const state = states.shift();
      if (state === undefined) throw new BrokerError("EXECUTION_FAILED", "fixture readback exhausted");
      return { launchd: launchd(state), sourceRevision: SOURCE_REVISION };
    }
  };
  const sourceRevisionReader: UserServiceSourceRevisionReader = {
    read: async () => SOURCE_REVISION
  };
  const commandRunner: UserServiceControlCommandRunner = {
    run: async (request) => {
      commands.push(request);
      await options.onCommand?.();
      return options.commandResult ?? commandResult();
    }
  };
  const adapter = new UserServiceControlAdapter({
    enabled: true,
    uid: UID,
    bindings: [{
      serviceId: SERVICE_ID,
      sourceRevision: SOURCE_REVISION,
      plistPath: "/Users/test/Library/LaunchAgents/com.mac-operator.test.plist",
      program: "/bin/true",
      arguments: ["/bin/true"]
    }],
    commandRunner,
    inspector: observer,
    sourceRevisionReader,
    now: () => NOW
  });
  // The executor is created by the caller after the adapter is available.
  void store;
  return { adapter, commands };
}

function approvalFor(store: BrokerStore, approvalId: string, argumentsValue: Record<string, unknown>): void {
  const targetRef = `service:${SERVICE_ID}`;
  store.issueApproval({
    approvalId,
    approverPrincipalId: "operator-1",
    requestingPrincipalId: "principal-1",
    tool: "mac_service_control",
    contractVersion: "0.1",
    targetKind: "service",
    targetRef,
    payloadDigest: sha256(canonicalJson(argumentsValue)),
    policyVersion: "policy-0.1",
    approvalClass: "trusted_write",
    unattended: false,
    issuedAtMs: NOW - 1_000,
    expiresAtMs: NOW + 60_000
  });
}

async function withBroker<T>(
  callback: (context: { broker: Broker; store: BrokerStore; key: Buffer; commands: ProcessExecutionRequest[] }) => Promise<T>,
  policy: BrokerPolicy = createDefaultPolicy("edge-1", true, ["mac.control.read"]),
  fixtureOptions: CandidateFixtureOptions = {}
): Promise<T> {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-service-control-admission-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const { adapter, commands } = candidateFixture(store, fixtureOptions);
  const executor = new UserServiceControlJobExecutor({ store, adapter, enabled: true, now: () => NOW });
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: keyring(key),
    userServiceControlCandidate: {
      adapter,
      executor,
      authorizedPrincipalIds: ["principal-1"],
      enabled: true,
      now: () => NOW
    },
    now: () => NOW
  });
  try {
    return await callback({ broker, store, key, commands });
  } finally {
    await broker.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
}

test("Broker candidate admission consumes approval and completes one bounded service Job", async () => {
  await withBroker(async ({ broker, store, key, commands }) => {
    const argumentsValue = {
      service_id: SERVICE_ID,
      action: "start",
      expected_state: "running",
      idempotency_key: "start-once"
    };
    approvalFor(store, "approval:service-control-1", argumentsValue);
    const request = unsigned("request:service-control-1", "nonce:service-control-1", argumentsValue);
    const result = await broker.executeUserServiceControlCandidate(signRequest(request, key));
    assert.equal(result.reused, false);
    assert.equal(result.result?.resultClass, "SUCCEEDED");
    assert.equal(result.job.state, "completed");
    assert.equal(result.job.serviceMetadata, undefined);
    assert.equal(commands.length, 1);
    assert.equal(store.requestRecord(request.requestId)?.state, "SUCCEEDED");
    assert.equal(store.requestRecord(request.requestId)?.edgeKeyId, "edge-1:edge-key-1");
    assert.deepEqual(
      store.auditRows().filter((row) => row.request_id === request.requestId).map((row) => [row.event_type, row.result_class]),
      [["decision", "AUTHORIZED"], ["intent", "INTENT_RECORDED"], ["completion", "SUCCEEDED"]]
    );
  });
});

test("Broker candidate idempotency reuses the existing Job without a second mutation", async () => {
  await withBroker(async ({ broker, store, key, commands }) => {
    const argumentsValue = {
      service_id: SERVICE_ID,
      action: "start",
      expected_state: "running",
      idempotency_key: "start-retry"
    };
    approvalFor(store, "approval:service-control-2", argumentsValue);
    const first = unsigned("request:service-control-2a", "nonce:service-control-2a", argumentsValue);
    const firstResult = await broker.executeUserServiceControlCandidate(signRequest(first, key));
    const second = unsigned("request:service-control-2b", "nonce:service-control-2b", argumentsValue);
    const secondResult = await broker.executeUserServiceControlCandidate(signRequest(second, key));
    assert.equal(firstResult.job.jobId, secondResult.job.jobId);
    assert.equal(secondResult.reused, true);
    assert.equal(commands.length, 1);
    assert.equal(store.requestRecord(second.requestId)?.resultClass, "IDEMPOTENT_REUSE");
  });
});

test("Broker candidate refuses admission without the exact approval and never dispatches", async () => {
  await withBroker(async ({ broker, store, key, commands }) => {
    const argumentsValue = {
      service_id: SERVICE_ID,
      action: "start",
      expected_state: "running",
      idempotency_key: "without-approval"
    };
    const request = unsigned("request:service-control-no-approval", "nonce:service-control-no-approval", argumentsValue);
    await assert.rejects(
      () => broker.executeUserServiceControlCandidate(signRequest(request, key)),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    assert.equal(commands.length, 0);
    assert.equal(store.ownedJobByIdempotencyKey("service-control:without-approval", "principal-1"), undefined);
  });
});

test("public Broker handling does not expose the candidate service-control tool", async () => {
  await withBroker(async ({ broker, key }) => {
    const argumentsValue = {
      service_id: SERVICE_ID,
      action: "start",
      expected_state: "running",
      idempotency_key: "public-denied"
    };
    const request = unsigned("request:service-control-public", "nonce:service-control-public", argumentsValue);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, false);
    assert.equal(result.result_class, "POLICY_DENIED");
    assert.equal(broker.enabledRuntimeCapabilityNames().includes("mac_service_control"), false);
  });
});

function publicServiceControlPolicy(): BrokerPolicy {
  const base = createDefaultPolicy("edge-1", true, ["mac.control.read", "mac.service.control"]);
  const tool = base.tools.get("mac_service_control");
  assert.ok(tool);
  return {
    ...base,
    targetRules: [...base.targetRules, {
      ruleId: "test-user-service-control-allow",
      effect: "allow",
      principalId: "principal-1",
      scope: "mac.service.control",
      target: { kind: "service", reference: SERVICE_ID }
    }],
    tools: new Map(base.tools).set("mac_service_control", { ...tool, implemented: true, enabled: true })
  };
}

test("public Broker service-control path binds approval, Job readback, and idempotency", async () => {
  await withBroker(async ({ broker, store, key, commands }) => {
    const argumentsValue = {
      service_id: SERVICE_ID,
      action: "start",
      expected_state: "running",
      idempotency_key: "public-start-once"
    };
    approvalFor(store, "approval:service-control-public-enabled", argumentsValue);
    const request = unsigned("request:service-control-public-enabled", "nonce:service-control-public-enabled", argumentsValue, ["mac.control.read", "mac.service.control"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.result_class, "SUCCEEDED");
      assert.equal((result.data as Record<string, unknown>).service_id, SERVICE_ID);
      assert.equal((result.data as Record<string, unknown>).post_state, "running");
      assert.equal((result.data as Record<string, unknown>).rollback_status, "not_needed");
    }
    const job = store.ownedJobByIdempotencyKey("service-control:public-start-once", "principal-1");
    assert.equal(job?.state, "completed");
    assert.equal(commands.length, 1);
    assert.equal(store.requestRecord(request.requestId)?.state, "SUCCEEDED");
  }, publicServiceControlPolicy());
});

test("public Broker service-control path reuses a completed Job only after a second exact approval", async () => {
  await withBroker(async ({ broker, store, key, commands }) => {
    const argumentsValue = {
      service_id: SERVICE_ID,
      action: "start",
      expected_state: "running",
      idempotency_key: "public-start-retry"
    };
    approvalFor(store, "approval:service-control-public-retry-1", argumentsValue);
    const first = unsigned("request:service-control-public-retry-1", "nonce:service-control-public-retry-1", argumentsValue, ["mac.control.read", "mac.service.control"]);
    const firstResult = await broker.handle(signRequest(first, key));
    assert.equal(firstResult.ok, true, JSON.stringify(firstResult));
    const jobId = store.requestRecord(first.requestId)?.jobId;
    assert.ok(jobId);

    approvalFor(store, "approval:service-control-public-retry-2", argumentsValue);
    const second = unsigned("request:service-control-public-retry-2", "nonce:service-control-public-retry-2", argumentsValue, ["mac.control.read", "mac.service.control"]);
    const secondResult = await broker.handle(signRequest(second, key));
    assert.equal(secondResult.ok, true, JSON.stringify(secondResult));
    assert.equal(store.requestRecord(second.requestId)?.jobId, jobId);
    assert.equal(store.requestRecord(second.requestId)?.state, "SUCCEEDED");
    assert.equal(commands.length, 1);
    assert.equal(store.ownedJobByIdempotencyKey("service-control:public-start-retry", "principal-1")?.jobId, jobId);
  }, publicServiceControlPolicy());
});

test("public Broker service-control path preserves UNKNOWN after active session revocation", async () => {
  let storeRef: BrokerStore | undefined;
  await withBroker(async ({ broker, store, key, commands }) => {
    storeRef = store;
    const argumentsValue = {
      service_id: SERVICE_ID,
      action: "start",
      expected_state: "running",
      idempotency_key: "public-revoked"
    };
    approvalFor(store, "approval:service-control-public-revoked", argumentsValue);
    const request = unsigned("request:service-control-public-revoked", "nonce:service-control-public-revoked", argumentsValue, ["mac.control.read", "mac.service.control"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, false);
    assert.equal(result.result_class, "UNKNOWN_OUTCOME");
    assert.equal(store.requestRecord(request.requestId)?.state, "UNKNOWN");
    const jobId = store.requestRecord(request.requestId)?.jobId;
    assert.ok(jobId);
    assert.equal(store.ownedJob(jobId, "principal-1")?.state, "unknown");
    assert.equal(commands.length, 1);
  }, publicServiceControlPolicy(), {
    onCommand: () => {
      storeRef?.revoke("session", "session-1", "public-service-revocation", NOW);
    }
  });
});

test("public Broker service-control path persists UNKNOWN when command and rollback are unresolved", async () => {
  await withBroker(async ({ broker, store, key, commands }) => {
    const argumentsValue = {
      service_id: SERVICE_ID,
      action: "start",
      expected_state: "running",
      idempotency_key: "public-unknown"
    };
    approvalFor(store, "approval:service-control-public-unknown", argumentsValue);
    const request = unsigned("request:service-control-public-unknown", "nonce:service-control-public-unknown", argumentsValue, ["mac.control.read", "mac.service.control"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, false);
    assert.equal(result.result_class, "UNKNOWN_OUTCOME");
    assert.equal(store.requestRecord(request.requestId)?.state, "UNKNOWN");
    const jobId = store.requestRecord(request.requestId)?.jobId;
    assert.ok(jobId);
    assert.equal(store.ownedJob(jobId, "principal-1")?.state, "unknown");
    assert.equal(commands.length, 2);
  }, publicServiceControlPolicy(), {
    states: ["stopped", "stopped", "running"],
    commandResult: failedCommandResult()
  });
});
