import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";

const digest = "a".repeat(64);

test("request restart reconciliation rejects a clock behind persisted timestamps", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-reconcile-clock-request-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    store.admitRequest({
      requestId: "request-reconcile-clock",
      edgeId: "edge-1",
      nonce: "nonce-reconcile-clock",
      principalId: "principal-1",
      sessionId: "session-1",
      tool: "mac_health",
      policyVersion: "policy-0.1",
      payloadDigest: digest,
      mutation: false,
      capabilityFamilies: [],
      receivedAtMs: 100,
      nonceExpiresAtMs: 200
    });
    assert.throws(
      () => store.reconcileInterruptedRequests(99),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
    );
    assert.equal(store.requestRecord("request-reconcile-clock")?.state, "RECEIVED");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("queued Job restart reconciliation rejects a clock behind creation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-reconcile-clock-queued-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    store.createJob({
      jobId: "job:reconcile-clock-queued",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_task_run",
      targetRef: "task_profile:tests.echo",
      policyVersion: "policy-0.1",
      payloadDigest: digest,
      idempotencyKey: "reconcile-clock-queued",
      createdAtMs: 100
    });
    assert.throws(
      () => store.reconcileInterruptedJobs(99),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
    );
    assert.equal(store.ownedJob("job:reconcile-clock-queued", "principal-1")?.state, "queued");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("running Job restart reconciliation rejects a clock behind start or heartbeat", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-reconcile-clock-running-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    store.createJob({
      jobId: "job:reconcile-clock-running",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_task_run",
      targetRef: "task_profile:tests.echo",
      policyVersion: "policy-0.1",
      payloadDigest: digest,
      idempotencyKey: "reconcile-clock-running",
      createdAtMs: 100
    });
    store.startJob("job:reconcile-clock-running", "principal-1", 0, 120, {
      ownerId: "broker:clock-test",
      token: "lease:reconcile-clock-1234",
      expiresAtMs: 10_000
    });
    assert.throws(
      () => store.reconcileInterruptedJobs(119),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
    );
    assert.equal(store.ownedJob("job:reconcile-clock-running", "principal-1")?.state, "running");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
