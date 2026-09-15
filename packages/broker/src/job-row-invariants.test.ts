import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import { BrokerStore, type CreateJobInput } from "./persistence.js";

function jobInput(jobId: string): CreateJobInput {
  return {
    jobId,
    ownerPrincipalId: "principal-1",
    ownerSessionId: "session-1",
    tool: "mac_task_run",
    targetRef: "task_profile:tests.sleep",
    policyVersion: "policy-0.1",
    payloadDigest: sha256("task-payload"),
    idempotencyKey: jobId.replace(/^job:/u, "idem-"),
    createdAtMs: 1
  };
}

const lease = {
  ownerId: "broker:row-test",
  token: "lease:row-test-1234567890",
  expiresAtMs: 30
} as const;

const processMetadata = {
  pid: 1234,
  processGroupId: 1234,
  startTimeMicros: 987654321,
  recordedAtMs: 2,
  descendants: []
} as const;

const guestMetadata = {
  requestId: "request:guest-1234567890abcdef",
  nonce: "guest-nonce-1234567890abcdef",
  requestDigest: "b".repeat(64),
  guestIdentity: { imageSha256: "c".repeat(64), runtimeVersion: "macos-guest-1" },
  profileDigest: "d".repeat(64),
  taskDigest: "e".repeat(64),
  timeoutMs: 10_000,
  outputCapBytes: 4_096,
  recordedAtMs: 2
} as const;

test("BrokerStore rejects a malformed persisted Job lease during startup", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-job-lease-row-"));
  const databasePath = join(directory, "broker.sqlite");
  let store: BrokerStore | undefined = new BrokerStore(databasePath);
  try {
    store.createJob(jobInput("job:lease-row"));
    store.startJob("job:lease-row", "principal-1", 0, 2, lease);
    store.close();
    store = undefined;

    const database = new DatabaseSync(databasePath);
    try {
      database.prepare("UPDATE jobs SET lease_owner_id = ? WHERE job_id = ?")
        .run("old worker with spaces", "job:lease-row");
    } finally {
      database.close();
    }

    assert.throws(
      () => { store = new BrokerStore(databasePath); },
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
  } finally {
    store?.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore rejects a persisted Job lease whose heartbeat outlives expiry", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-job-lease-clock-"));
  const databasePath = join(directory, "broker.sqlite");
  let store: BrokerStore | undefined = new BrokerStore(databasePath);
  try {
    store.createJob(jobInput("job:lease-clock"));
    store.startJob("job:lease-clock", "principal-1", 0, 2, lease);
    store.close();
    store = undefined;

    const database = new DatabaseSync(databasePath);
    try {
      database.prepare("UPDATE jobs SET lease_heartbeat_at_ms = ? WHERE job_id = ?")
        .run(31, "job:lease-clock");
    } finally {
      database.close();
    }

    assert.throws(
      () => { store = new BrokerStore(databasePath); },
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
  } finally {
    store?.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore rejects a Job carrying both local-process and guest recovery ownership", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-job-mixed-ownership-"));
  const databasePath = join(directory, "broker.sqlite");
  let store: BrokerStore | undefined = new BrokerStore(databasePath);
  try {
    store.createJob(jobInput("job:mixed-ownership"));
    const running = store.startJob("job:mixed-ownership", "principal-1", 0, 2, lease);
    store.recordJobProcessOwnership(
      "job:mixed-ownership",
      "principal-1",
      running.revision,
      processMetadata,
      lease,
      2
    );
    store.close();
    store = undefined;

    const database = new DatabaseSync(databasePath);
    try {
      database.prepare("UPDATE jobs SET guest_metadata_json = ? WHERE job_id = ?")
        .run(canonicalJson(guestMetadata), "job:mixed-ownership");
    } finally {
      database.close();
    }

    assert.throws(
      () => { store = new BrokerStore(databasePath); },
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
  } finally {
    store?.close();
    await rm(directory, { recursive: true, force: true });
  }
});
