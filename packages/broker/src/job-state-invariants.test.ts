import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { BrokerError, sha256 } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";

test("a durable running-job cancellation fences a late success", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-job-state-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    store.createJob({
      jobId: "job:cancel-fence",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_task_run",
      targetRef: "task:bounded",
      policyVersion: "policy-0.1",
      payloadDigest: sha256("payload"),
      idempotencyKey: "cancel-fence",
      createdAtMs: 1
    });
    const running = store.startJob("job:cancel-fence", "principal-1", 0, 2);
    const cancellation = store.requestJobCancellation("job:cancel-fence", "principal-1", "KILL_SWITCH", 3);
    assert.equal(cancellation.job.state, "running");
    assert.equal(cancellation.job.cancelRequested, true);
    assert.throws(
      () => store.finishJob("job:cancel-fence", "principal-1", cancellation.job.revision, {
        state: "completed", resultClass: "success", finishedAtMs: 4
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
    );
    const unknown = store.finishJob("job:cancel-fence", "principal-1", cancellation.job.revision, {
      state: "unknown", resultClass: "unknown", finishedAtMs: 4
    });
    assert.equal(unknown.state, "unknown");
    assert.equal(unknown.resultClass, "unknown");
    assert.equal(running.state, "running");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("stored Job state/result mismatches fail closed on readback", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-job-corruption-"));
  const databasePath = join(directory, "broker.sqlite");
  let store = new BrokerStore(databasePath);
  store.createJob({
    jobId: "job:corrupt-state",
    ownerPrincipalId: "principal-1",
    ownerSessionId: "session-1",
    tool: "mac_task_run",
    targetRef: "task:bounded",
    policyVersion: "policy-0.1",
    payloadDigest: sha256("payload"),
    idempotencyKey: "corrupt-state",
    createdAtMs: 1
  });
  store.close();
  try {
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare("UPDATE jobs SET state = 'completed', result_class = 'accepted', started_at_ms = 2, finished_at_ms = 3 WHERE job_id = ?").run("job:corrupt-state");
    } finally {
      database.close();
    }
    store = new BrokerStore(databasePath);
    assert.throws(
      () => store.ownedJob("job:corrupt-state", "principal-1"),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
