import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError, CONTRACT_VERSION, sha256 } from "@mac-operator/contracts";
import { BrokerStore, type BrokerJob, type JobLease } from "./persistence.js";
import {
  createPrivilegedHelperCommandClient,
  PrivilegedHelperJobExecutor,
  type PrivilegedHelperJobExecutionInput
} from "./privileged-helper-executor.js";
import type {
  PrivilegedHelperResponse,
  SignedPrivilegedHelperCommand
} from "./privileged-helper.js";
import { signPrivilegedHelperCommand } from "./privileged-helper.js";

const NOW = 1_700_000_000_000;

test("privileged helper Job executor is disabled by default without changing the Job", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-executor-disabled-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const setup = admitRunningJob(store, "job:helper-executor-disabled", "request:helper-executor-disabled");
    const executor = new PrivilegedHelperJobExecutor({ store, now: () => NOW + 10 });
    await assert.rejects(
      () => executor.execute(executionInput(setup.job, setup.lease)),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "PRIVILEGE_DENIED"
    );
    assert.equal(store.ownedJob(setup.job.jobId, "principal-1")?.state, "running");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("enabled privileged helper Job executor commits only a verified completed response", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-executor-success-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const setup = admitRunningJob(store, "job:helper-executor-success", "request:helper-executor-success");
    const command = signedCommand(setup.job.targetRef, setup.job.payloadDigest);
    let authorityChecks = 0;
    const response: PrivilegedHelperResponse = {
      ok: true,
      commandId: command.commandId,
      requestId: command.requestId,
      result: {
        operation: "service_control",
        targetRef: setup.job.targetRef,
        state: "completed",
        resultClass: "SUCCEEDED",
        evidence: { post_state: "running" },
        warnings: [],
        truncated: false,
        verification: { status: "verified", strategy: "allowlisted_postcondition", summary: "state readback matched" }
      },
      responseProof: "a".repeat(64)
    };
    const executor = new PrivilegedHelperJobExecutor({
      store,
      enabled: true,
      now: () => NOW + 10,
      commandFactory: { issue: () => command },
      commandClient: async (received, timeoutMs) => {
        assert.equal(received.commandId, command.commandId);
        assert.equal(timeoutMs, 5_000);
        return response;
      }
    });
    const outcome = await executor.execute(executionInput(setup.job, setup.lease, () => { authorityChecks += 1; }));
    assert.equal(outcome.job.state, "completed");
    assert.equal(outcome.job.resultClass, "success");
    assert.equal(authorityChecks, 2);
    assert.match(outcome.job.stdout, /post_state/u);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("transport loss after command issuance records UNKNOWN_OUTCOME", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-executor-unknown-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const setup = admitRunningJob(store, "job:helper-executor-unknown", "request:helper-executor-unknown");
    const executor = new PrivilegedHelperJobExecutor({
      store,
      enabled: true,
      now: () => NOW + 10,
      commandFactory: { issue: () => signedCommand(setup.job.targetRef, setup.job.payloadDigest) },
      commandClient: async () => {
        throw new BrokerError("TIMEOUT", "helper channel timed out", true);
      }
    });
    await assert.rejects(
      () => executor.execute(executionInput(setup.job, setup.lease)),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "UNKNOWN_OUTCOME" && error.retryable
    );
    const job = store.ownedJob(setup.job.jobId, "principal-1");
    assert.equal(job?.state, "unknown");
    assert.equal(job?.resultClass, "unknown");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("helper acceptance without completion stays UNKNOWN_OUTCOME", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-executor-accepted-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const setup = admitRunningJob(store, "job:helper-executor-accepted", "request:helper-executor-accepted");
    const command = signedCommand(setup.job.targetRef, setup.job.payloadDigest);
    const executor = new PrivilegedHelperJobExecutor({
      store,
      enabled: true,
      now: () => NOW + 10,
      commandFactory: { issue: () => command },
      commandClient: async () => ({
        ok: true,
        commandId: command.commandId,
        requestId: command.requestId,
        result: {
          operation: "service_control",
          targetRef: setup.job.targetRef,
          state: "accepted",
          resultClass: "SUCCEEDED",
          evidence: { accepted: true },
          warnings: [],
          truncated: false,
          verification: { status: "verified", strategy: "allowlisted_postcondition" }
        },
        responseProof: "a".repeat(64)
      })
    });
    const outcome = await executor.execute(executionInput(setup.job, setup.lease));
    assert.equal(outcome.job.state, "unknown");
    assert.equal(outcome.job.resultClass, "unknown");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("command client binding zeroes the short-lived authentication key", async () => {
  const key = randomBytes(32);
  const { authenticationProof: _placeholder, ...unsigned } = signedCommand("service:system/com.example.test", sha256("executor-test"));
  const signed = signPrivilegedHelperCommand(unsigned, key);
  const client = createPrivilegedHelperCommandClient(() => ({
    socketPath: "/private/var/empty/mac-operator-helper.sock",
    authenticationKey: key,
    now: () => NOW
  }));
  await assert.rejects(
    () => client(signed, 5_000),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "TARGET_NOT_FOUND"
  );
  assert.deepEqual(key, Buffer.alloc(32));
});

function executionInput(
  job: ReturnType<typeof admitRunningJob>["job"],
  lease: JobLease,
  assertAuthority: () => void = () => undefined
): PrivilegedHelperJobExecutionInput {
  return {
    requestId: job.jobId.replace(/^job:/u, "request:"),
    principalId: "principal-1",
    sessionId: "session-1",
    job,
    lease,
    operation: "service_control",
    timeoutMs: 5_000,
    assertAuthority
  };
}

function signedCommand(targetRef: string, payloadDigest: string): SignedPrivilegedHelperCommand {
  return {
    protocolVersion: "0.1",
    contractVersion: CONTRACT_VERSION,
    commandId: "priv-command:executor-test",
    requestId: "request:executor-test",
    nonce: "helper-nonce-executor-test-123456",
    nonceExpiresAtMs: NOW + 30_000,
    timestampMs: NOW,
    expiresAtMs: NOW + 30_000,
    operation: "service_control",
    targetRef,
    payloadDigest,
    policyVersion: "policy-0.1",
    approvalId: "approval:executor-test",
    intentId: "intent:executor-test",
    authenticationProof: "a".repeat(64)
  };
}

function admitRunningJob(store: BrokerStore, jobId: string, requestId: string): { job: BrokerJob; lease: JobLease } {
  const targetRef = "service:system/com.example.test";
  const payloadDigest = sha256("executor-payload");
  store.admitRequest({
    requestId,
    edgeId: "edge-1",
    nonce: `nonce-${requestId}`,
    nonceExpiresAtMs: NOW + 60_000,
    principalId: "principal-1",
    sessionId: "session-1",
    tool: "mac_priv_service_control",
    policyVersion: "policy-0.1",
    payloadDigest,
    mutation: true,
    receivedAtMs: NOW
  });
  store.recordRequestDecision({
    requestId,
    principalId: "principal-1",
    tool: "mac_priv_service_control",
    eventType: "decision",
    decision: "allow",
    resultClass: "AUTHORIZED",
    targetRef,
    policyVersion: "policy-0.1",
    evidence: {},
    timestampMs: NOW + 1
  });
  store.issueApproval({
    approvalId: `approval:${requestId.replace(/^request:/u, "")}`,
    approverPrincipalId: "operator-1",
    requestingPrincipalId: "principal-1",
    tool: "mac_priv_service_control",
    contractVersion: CONTRACT_VERSION,
    targetKind: "service",
    targetRef,
    payloadDigest,
    policyVersion: "policy-0.1",
    approvalClass: "explicit_privileged_policy",
    unattended: false,
    issuedAtMs: NOW + 1,
    expiresAtMs: NOW + 60_000
  });
  store.recordRequestIntent({
    requestId,
    principalId: "principal-1",
    tool: "mac_priv_service_control",
    eventType: "intent",
    decision: "allow",
    resultClass: "INTENT_RECORDED",
    targetRef,
    policyVersion: "policy-0.1",
    evidence: {},
    timestampMs: NOW + 2
  }, {
    contractVersion: CONTRACT_VERSION,
    targetKind: "service",
    targetRef,
    payloadDigest,
    approvalClass: "explicit_privileged_policy",
    unattended: false
  });
  const created = store.createJob({
    jobId,
    ownerPrincipalId: "principal-1",
    ownerSessionId: "session-1",
    tool: "mac_priv_service_control",
    targetRef,
    policyVersion: "policy-0.1",
    payloadDigest,
    idempotencyKey: `idem-${jobId.replace(/^job:/u, "")}`,
    createdAtMs: NOW + 2
  });
  store.linkRequestJob(requestId, jobId, NOW + 3);
  store.markRequestRunning(requestId, NOW + 4);
  const lease: JobLease = {
    ownerId: "broker:executor-test",
    token: "lease:executor-test-1234567890",
    expiresAtMs: NOW + 60_000
  };
  const job = store.startJob(jobId, "principal-1", created.job.revision, NOW + 4, lease);
  return { job, lease };
}
