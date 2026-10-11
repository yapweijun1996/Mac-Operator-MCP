import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerStore } from "./persistence.js";

const archiveKey = { keyId: "ledger-link-test", loadKey: () => Buffer.alloc(32, 1) };
const requestId = "rotation-linked-request";
const jobId = "job:rotation-linked";
const common = {
  requestId, principalId: "principal-1", tool: "mac_task_run", targetRef: "task_profile:test", policyVersion: "policy-0.1"
};

function createLinkedHistory(store: BrokerStore, completedAtMs: number | undefined): void {
  store.issueApproval({
    approvalId: "approval:rotation-linked", approverPrincipalId: "operator-1", requestingPrincipalId: common.principalId,
    tool: common.tool, contractVersion: "0.1", targetKind: "task_profile", targetRef: common.targetRef,
    payloadDigest: "b".repeat(64), policyVersion: common.policyVersion, approvalClass: "trusted_profile",
    unattended: false, issuedAtMs: 1, expiresAtMs: 1_000
  });
  store.admitApprovedJob({
    request: {
      requestId, edgeId: "edge-1", edgeKeyId: "edge-1:key-1", nonce: "rotation-linked-nonce", nonceExpiresAtMs: 1_000,
      principalId: common.principalId, sessionId: "session-1", tool: common.tool, policyVersion: common.policyVersion,
      payloadDigest: "a".repeat(64), mutation: true, receivedAtMs: 1
    },
    decision: { ...common, eventType: "decision", decision: "allow", resultClass: "AUTHORIZED", evidence: {}, timestampMs: 2 },
    intent: {
      ...common, eventType: "intent", decision: "allow", resultClass: "INTENT_RECORDED",
      evidence: { argumentDigest: "b".repeat(64) }, timestampMs: 3
    },
    approval: {
      contractVersion: "0.1", targetKind: "task_profile", targetRef: common.targetRef, payloadDigest: "b".repeat(64),
      approvalClass: "trusted_profile", unattended: false
    },
    job: {
      jobId, edgeId: "edge-1", edgeKeyId: "edge-1:key-1", ownerPrincipalId: common.principalId,
      ownerSessionId: "session-1", tool: common.tool, targetRef: common.targetRef, policyVersion: common.policyVersion,
      payloadDigest: "b".repeat(64), idempotencyKey: "rotation-linked", createdAtMs: 3
    }
  });
  store.startJob(jobId, common.principalId, 0, 4);
  store.markRequestRunning(requestId, 5);
  store.finishJob(jobId, common.principalId, 1, { state: "completed", resultClass: "success", finishedAtMs: 6, exitCode: 0 });
  if (completedAtMs !== undefined) {
    store.completeRequest({
      ...common, eventType: "completion", decision: "allow", resultClass: "SUCCEEDED", evidence: {}, timestampMs: completedAtMs
    });
  }
  store.createJob({
    jobId: "job:rotation-independent", ownerPrincipalId: common.principalId, ownerSessionId: "session-1",
    tool: common.tool, targetRef: common.targetRef, policyVersion: common.policyVersion,
    payloadDigest: "c".repeat(64), idempotencyKey: "rotation-independent", createdAtMs: 7
  });
  store.startJob("job:rotation-independent", common.principalId, 0, 8);
  store.finishJob("job:rotation-independent", common.principalId, 1, {
    state: "completed", resultClass: "success", finishedAtMs: 9, exitCode: 0
  });
}

for (const scenario of [
  { name: "retained terminal Request", completedAtMs: 7, retainRequestCount: 1, minAgeMs: 0 },
  { name: "recent terminal Request", completedAtMs: 95, retainRequestCount: 0, minAgeMs: 20 },
  { name: "nonterminal Request", completedAtMs: undefined, retainRequestCount: 0, minAgeMs: 0 }
]) {
  test(`ledger rotation preserves the Job linked by a ${scenario.name} and still rotates unrelated Jobs`, async () => {
    const directory = await mkdtemp(join(tmpdir(), "mac-broker-ledger-link-rotation-"));
    const databasePath = join(directory, "broker.sqlite");
    let store: BrokerStore | undefined = new BrokerStore(databasePath, { runtimeFence: true });
    try {
      createLinkedHistory(store, scenario.completedAtMs);
      if (scenario.completedAtMs !== undefined) {
        store.close();
        store = new BrokerStore(databasePath, { runtimeFence: true });
      } else {
        assert.equal(store.requestRecord(requestId)?.state, "RUNNING");
      }
      const first = await store.rotateLedgerArchive(directory, {
        keySource: archiveKey, retainRequestCount: scenario.retainRequestCount, retainJobCount: 0,
        minAgeMs: scenario.minAgeMs, nowMs: 100
      });
      assert.equal(first.rotatedRequestCount, 0);
      assert.equal(first.rotatedJobCount, 1);
      assert.equal(store.requestRecord(requestId)?.jobId, jobId);
      assert.equal(store.ownedJob(jobId, common.principalId)?.state, "completed");
      assert.equal(store.ownedJob("job:rotation-independent", common.principalId), undefined);
      assert.equal(store.ownedJobStatus("job:rotation-independent", common.principalId).archived?.state, "completed");
      if (scenario.completedAtMs === undefined) {
        store.completeRequest({
          ...common, eventType: "completion", decision: "allow", resultClass: "SUCCEEDED", evidence: {}, timestampMs: 101
        });
      }
      store.close();
      store = new BrokerStore(databasePath, { runtimeFence: true });
      assert.equal(store.requestRecord(requestId)?.jobId, jobId);
      assert.equal(store.ownedJob(jobId, common.principalId)?.state, "completed");
      const second = await store.rotateLedgerArchive(directory, {
        keySource: archiveKey, retainRequestCount: 0, retainJobCount: 0, minAgeMs: 0, nowMs: 200
      });
      assert.equal(second.rotatedRequestCount, 1);
      assert.equal(second.rotatedJobCount, 1);
      assert.equal(store.requestRecord(requestId), undefined);
      assert.equal(store.ownedJob(jobId, common.principalId), undefined);
      store.close();
      store = new BrokerStore(databasePath, { runtimeFence: true });
      assert.equal(store.ownedJobStatus(jobId, common.principalId).archived?.state, "completed");
    } finally {
      store?.close();
      await rm(directory, { recursive: true, force: true });
    }
  });
}
