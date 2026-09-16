import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError, canonicalJson, CONTRACT_VERSION, sha256 } from "@mac-operator/contracts";
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
const SERVICE_PAYLOAD = { operation: "service_control" as const, service_id: "system/com.example.test", action: "start" as const };
const SERVICE_PAYLOAD_DIGEST = sha256(canonicalJson(SERVICE_PAYLOAD));

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

test("privileged helper Job executor requires and enforces an explicit operation allowlist", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-executor-allowlist-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    assert.throws(
      () => new PrivilegedHelperJobExecutor({
        store,
        enabled: true,
        commandFactory: { issue: () => signedCommand("service:system/com.example.test", SERVICE_PAYLOAD_DIGEST) },
        commandClient: async () => { throw new Error("helper IPC must not be reached"); }
      }),
      /operation allowlist/u
    );
    const executor = new PrivilegedHelperJobExecutor({
      store,
      enabled: true,
      enabledOperations: ["service_control"],
      commandFactory: { issue: () => signedCommand("service:system/com.example.test", SERVICE_PAYLOAD_DIGEST) },
      commandClient: async () => { throw new Error("helper IPC must not be reached"); }
    });
    assert.equal(executor.available, true);
    assert.equal(executor.supportsOperation("service_control"), true);
    assert.equal(executor.supportsOperation("package_install"), false);
    assert.equal(executor.supportsOperation("power"), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("privileged helper Job executor rejects malformed operation and lease input before dispatch", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-executor-input-boundary-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const setup = admitRunningJob(store, "job:helper-executor-input-boundary", "request:helper-executor-input-boundary");
    let factoryCalls = 0;
    let clientCalls = 0;
    const executor = new PrivilegedHelperJobExecutor({
      store,
      enabled: true,
      enabledOperations: ["service_control"],
      now: () => NOW + 10,
      commandFactory: { issue: () => { factoryCalls += 1; return signedCommand(setup.job.targetRef, setup.job.payloadDigest); } },
      commandClient: async () => { clientCalls += 1; throw new Error("helper IPC must not be reached"); }
    });
    await assert.rejects(
      () => executor.execute({ ...executionInput(setup.job, setup.lease), operation: "raw_shell" } as never),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
    );
    await assert.rejects(
      () => executor.execute({ ...executionInput(setup.job, setup.lease), lease: { ...setup.lease, token: "spoofed" } } as never),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
    );
    await assert.rejects(
      () => executor.execute({ ...executionInput(setup.job, setup.lease), operation: "package_install" } as never),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "PRIVILEGE_DENIED"
    );
    assert.equal(factoryCalls, 0);
    assert.equal(clientCalls, 0);
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
      enabledOperations: ["service_control"],
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

test("long helper execution renews the Broker Job lease before completion", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-executor-lease-renewal-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const setup = admitRunningJob(store, "job:helper-executor-lease-renewal", "request:helper-executor-lease-renewal");
    const command = signedCommand(setup.job.targetRef, setup.job.payloadDigest);
    let nowMs = NOW + 10;
    const executor = new PrivilegedHelperJobExecutor({
      store,
      enabled: true,
      enabledOperations: ["service_control"],
      now: () => nowMs,
      leaseDurationMs: 3_000,
      commandFactory: { issue: () => command },
      commandClient: async () => {
        await new Promise<void>((resolve) => setTimeout(resolve, 700));
        nowMs = NOW + 1_500;
        await new Promise<void>((resolve) => setTimeout(resolve, 700));
        return {
          ok: true as const,
          commandId: command.commandId,
          requestId: command.requestId,
          result: {
            operation: "service_control" as const,
            targetRef: setup.job.targetRef,
            state: "completed" as const,
            resultClass: "SUCCEEDED" as const,
            evidence: { post_state: "running" },
            warnings: [],
            truncated: false,
            verification: { status: "verified" as const, strategy: "allowlisted_postcondition" as const }
          },
          responseProof: "a".repeat(64)
        };
      }
    });
    const outcome = await executor.execute(executionInput(setup.job, setup.lease));
    assert.equal(outcome.job.state, "completed");
    assert.equal(setup.lease.expiresAtMs, NOW + 4_500);
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
      enabledOperations: ["service_control"],
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
      enabledOperations: ["service_control"],
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

test("active cancellation after helper dispatch stays UNKNOWN_OUTCOME", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-executor-cancelled-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const setup = admitRunningJob(store, "job:helper-executor-cancelled", "request:helper-executor-cancelled");
    const command = signedCommand(setup.job.targetRef, setup.job.payloadDigest);
    const executor = new PrivilegedHelperJobExecutor({
      store,
      enabled: true,
      enabledOperations: ["service_control"],
      now: () => NOW + 10,
      commandFactory: { issue: () => command },
      commandClient: async () => {
        const cancellation = store.requestJobCancellation(
          setup.job.jobId,
          "principal-1",
          "operator-cancelled",
          NOW + 20
        );
        assert.equal(cancellation.job.cancelRequested, true);
        return {
          ok: true as const,
          commandId: command.commandId,
          requestId: command.requestId,
          result: {
            operation: "service_control" as const,
            targetRef: setup.job.targetRef,
            state: "completed" as const,
            resultClass: "SUCCEEDED" as const,
            evidence: { post_state: "running" },
            warnings: [],
            truncated: false,
            verification: { status: "verified" as const, strategy: "allowlisted_postcondition" as const }
          },
          responseProof: "a".repeat(64)
        };
      }
    });
    await assert.rejects(
      () => executor.execute(executionInput(setup.job, setup.lease)),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "UNKNOWN_OUTCOME" && error.retryable
    );
    const job = store.ownedJob(setup.job.jobId, "principal-1");
    assert.equal(job?.state, "unknown");
    assert.equal(job?.resultClass, "unknown");
    assert.equal(job?.cancelRequested, true);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("cancellation during command signing closes the Job before helper IPC", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-executor-cancel-before-ipc-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const setup = admitRunningJob(store, "job:helper-executor-cancel-before-ipc", "request:helper-executor-cancel-before-ipc");
    let commandCalls = 0;
    const executor = new PrivilegedHelperJobExecutor({
      store,
      enabled: true,
      enabledOperations: ["service_control"],
      now: () => NOW + 10,
      commandFactory: {
        issue: () => {
          store.requestJobCancellation(setup.job.jobId, "principal-1", "operator-cancelled", NOW + 20);
          return signedCommand(setup.job.targetRef, setup.job.payloadDigest);
        }
      },
      commandClient: async () => {
        commandCalls += 1;
        throw new Error("helper IPC must not be reached");
      }
    });
    await assert.rejects(
      () => executor.execute(executionInput(setup.job, setup.lease)),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
    );
    assert.equal(commandCalls, 0);
    const job = store.ownedJob(setup.job.jobId, "principal-1");
    assert.equal(job?.state, "cancelled");
    assert.equal(job?.resultClass, "denied");
    assert.equal(job?.cancelRequested, true);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("a pre-dispatch cancellation is terminalized without issuing a helper command", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-executor-cancel-pre-dispatch-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const setup = admitRunningJob(store, "job:helper-executor-cancel-pre-dispatch", "request:helper-executor-cancel-pre-dispatch");
    store.requestJobCancellation(setup.job.jobId, "principal-1", "operator-cancelled", NOW + 20);
    let factoryCalls = 0;
    const executor = new PrivilegedHelperJobExecutor({
      store,
      enabled: true,
      enabledOperations: ["service_control"],
      now: () => NOW + 10,
      commandFactory: {
        issue: () => {
          factoryCalls += 1;
          return signedCommand(setup.job.targetRef, setup.job.payloadDigest);
        }
      },
      commandClient: async () => {
        throw new Error("helper IPC must not be reached");
      }
    });
    await assert.rejects(
      () => executor.execute(executionInput(setup.job, setup.lease)),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
    );
    assert.equal(factoryCalls, 0);
    const job = store.ownedJob(setup.job.jobId, "principal-1");
    assert.equal(job?.state, "cancelled");
    assert.equal(job?.resultClass, "denied");
    assert.equal(job?.cancelRequested, true);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("command client binding zeroes the short-lived authentication key", async () => {
  const key = randomBytes(32);
  const { authenticationProof: _placeholder, ...unsigned } = signedCommand("service:system/com.example.test", SERVICE_PAYLOAD_DIGEST);
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
    payload: SERVICE_PAYLOAD,
    payloadDigest,
    policyVersion: "policy-0.1",
    approvalId: "approval:executor-test",
    intentId: "intent:executor-test",
    authenticationProof: "a".repeat(64)
  };
}

function admitRunningJob(store: BrokerStore, jobId: string, requestId: string): { job: BrokerJob; lease: JobLease } {
  const targetRef = "service:system/com.example.test";
  const payloadDigest = SERVICE_PAYLOAD_DIGEST;
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
    createdAtMs: NOW + 2,
    privilegedPayload: SERVICE_PAYLOAD
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
