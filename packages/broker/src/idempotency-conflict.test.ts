import assert from "node:assert/strict";
import test from "node:test";
import { archivedIdempotencyConflict, firstDifferingBinding, idempotencyConflict, type IdempotencyBinding } from "./idempotency-conflict.js";
import type { BrokerJob, JobState } from "./persistence.js";

const FAILURE_MESSAGE_LIMIT = 512;

function holder(overrides: Partial<BrokerJob> = {}): BrokerJob {
  return {
    jobId: "job:holder", ownerEdgeId: "edge-1", ownerEdgeKeyId: "edge-1:edge-key-1", ownerPrincipalId: "principal-1",
    ownerSessionId: "session-1", tool: "mac_task_run", targetRef: "task:test", policyVersion: "policy-0.1",
    payloadDigest: "a".repeat(64), idempotencyKey: "key-1", state: "completed", resultClass: "success", createdAtMs: 1,
    startedAtMs: null, finishedAtMs: null, exitCode: null, stdout: "", stderr: "", truncated: false, cancelRequested: false, revision: 0,
    ...overrides
  };
}

const identical = { tool: "mac_task_run", payloadDigest: "a".repeat(64), targetRef: "task:test", policyVersion: "policy-0.1" };

test("firstDifferingBinding reports bindings in a fixed order and skips what a caller does not bind", () => {
  assert.equal(firstDifferingBinding(holder(), identical), undefined);
  assert.equal(firstDifferingBinding(holder(), { ...identical, tool: "mac_test_run", payloadDigest: "b".repeat(64) }), "tool");
  assert.equal(firstDifferingBinding(holder(), { ...identical, payloadDigest: "b".repeat(64), targetRef: "task:other" }), "arguments");
  assert.equal(firstDifferingBinding(holder(), { ...identical, targetRef: "task:other", policyVersion: "policy-0.2" }), "target");
  assert.equal(firstDifferingBinding(holder(), { ...identical, policyVersion: "policy-0.2", sessionId: "session-2" }), "policy version");

  // The login and the Edge connection are compared only when the caller supplies them.
  assert.equal(firstDifferingBinding(holder(), { ...identical, sessionId: "session-1", edgeId: "edge-1", edgeKeyId: "edge-1:edge-key-1" }), undefined);
  assert.equal(firstDifferingBinding(holder(), { ...identical, sessionId: "session-2", edgeKeyId: "edge-1:edge-key-2" }), "OAuth login");
  assert.equal(firstDifferingBinding(holder(), { ...identical, edgeId: "edge-2" }), "Edge connection");
  assert.equal(firstDifferingBinding(holder(), { ...identical, edgeKeyId: "edge-1:edge-key-2" }), "Edge connection");
  assert.equal(firstDifferingBinding(holder(), { ...identical, edgeKeyId: null }), "Edge connection");
  assert.equal(firstDifferingBinding(holder({ ownerEdgeId: null, ownerEdgeKeyId: null }), { ...identical, edgeId: null, edgeKeyId: null }), undefined);
  assert.equal(firstDifferingBinding(holder({ ownerEdgeId: null, ownerEdgeKeyId: null }), { ...identical, edgeId: "edge-1" }), "Edge connection");
});

test("idempotency conflicts stay inside the failure message bound for the longest stored identifiers", () => {
  const states: JobState[] = ["queued", "running", "completed", "failed", "cancelled", "unknown"];
  const bindings: Array<IdempotencyBinding | undefined> = ["tool", "arguments", "target", "policy version", "OAuth login", "Edge connection", undefined];
  const longest = holder({ jobId: `job:${"j".repeat(240)}`, tool: `mac_${"t".repeat(123)}`, createdAtMs: Number.MAX_SAFE_INTEGER });
  for (const state of states) {
    for (const binding of bindings) {
      const error = idempotencyConflict({ ...longest, state }, binding);
      assert.equal(error.errorClass, "CONFLICT");
      assert.ok(error.message.startsWith("IDEMPOTENCY_KEY_IN_USE: "), error.message);
      assert.ok(error.message.length < FAILURE_MESSAGE_LIMIT, `${state} ${binding}: ${error.message.length}`);
    }
  }
  const archived = archivedIdempotencyConflict({ jobId: longest.jobId, tool: longest.tool, state: "cancelled", finishedAtMs: Number.MAX_SAFE_INTEGER });
  assert.ok(archived.message.length < FAILURE_MESSAGE_LIMIT, `${archived.message.length}`);
});

test("idempotency conflicts clip long names, tolerate timestamps beyond the Date range and never print identity fields", () => {
  const long = holder({ jobId: `job:${"j".repeat(240)}`, createdAtMs: Number.MAX_SAFE_INTEGER });
  const message = idempotencyConflict(long, "target").message;
  assert.ok(message.includes(`${long.jobId.slice(0, 93)}... (mac_task_run, completed, created ${Number.MAX_SAFE_INTEGER})`), message);
  assert.ok(idempotencyConflict(holder({ createdAtMs: 1 }), "tool").message.includes("created 1970-01-01T00:00:00.001Z"));
  for (const hidden of [long.payloadDigest, long.ownerSessionId, long.ownerEdgeId!, long.ownerEdgeKeyId!, long.targetRef, long.idempotencyKey]) {
    assert.ok(!message.includes(hidden), hidden);
  }
});

test("idempotency conflicts advise on the holder state when the request is identical", () => {
  const advice = (state: JobState) => idempotencyConflict(holder({ state }), undefined).message;
  assert.match(advice("queued"), /It has not finished: check it with mac_job_status, then repeat the identical request to replay its outcome\.$/u);
  assert.match(advice("running"), /It has not finished/u);
  assert.match(advice("failed"), /A failed or cancelled job is never re-run under its key: use a new idempotency_key to run the request again\.$/u);
  assert.match(advice("cancelled"), /never re-run under its key/u);
  assert.match(advice("unknown"), /Its outcome is unresolved: inspect it with mac_job_status before choosing a new idempotency_key\.$/u);
  assert.match(advice("completed"), /It has no replayable successful outcome: use a new idempotency_key\.$/u);
});
