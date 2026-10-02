import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { BrokerError, canonicalJson } from "@mac-operator/contracts";
import { BrokerStore, BROKER_SCHEMA_VERSION, type BrokerJob, type JobLease } from "./persistence.js";
import {
  parseContainerTaskJobMetadata,
  serializeContainerTaskJobMetadata,
  validateContainerTaskJobMetadata,
  type ContainerTaskJobMetadata
} from "./container-job-metadata.js";

const lease = (): JobLease => ({ ownerId: "broker:container-test", token: "lease:container-test-123456", expiresAtMs: 30 });
const metadata = (overrides: Partial<ContainerTaskJobMetadata> = {}): ContainerTaskJobMetadata => ({
  schemaVersion: "0.1", containerId: "b".repeat(64), engineId: "engine-test-1", imageId: `sha256:${"c".repeat(64)}`,
  taskId: "task-container-1", owner: "principal-1", nonce: "d".repeat(64), taskDescriptorDigest: "e".repeat(64),
  recordedAtMs: 2, deadlineAtMs: 10_002, readonlyWorkspace: false, memoryBytes: 512 * 1024 * 1024,
  nanoCpus: 1_000_000_000, pidsLimit: 128, maxRuntimeMs: 10_000, ...overrides
});
const jobInput = (jobId = "job:container-1", tool = "mac_codex_run") => ({
  jobId, ownerPrincipalId: "principal-1", ownerSessionId: "session-1", tool, targetRef: "task:test",
  policyVersion: "policy-0.1", payloadDigest: "a".repeat(64), idempotencyKey: jobId.slice(4), createdAtMs: 1
});
const brokerError = (error: unknown) => error instanceof BrokerError;

function start(store: BrokerStore, tool = "mac_codex_run", id = "job:container-1"): BrokerJob {
  store.createJob(jobInput(id, tool));
  return store.startJob(id, "principal-1", 0, 1, lease());
}

function record(store: BrokerStore, tool = "mac_codex_run", id = "job:container-1", value = metadata()): BrokerJob {
  const running = start(store, tool, id);
  return store.recordJobContainerOwnership(id, "principal-1", running.revision, value, lease(), 2);
}

test("container ownership metadata strictly rejects unknown fields, accessors and unsafe identities", () => {
  const good = metadata();
  assert.deepEqual(parseContainerTaskJobMetadata(serializeContainerTaskJobMetadata(good)), good);
  assert.equal(Object.isFrozen(parseContainerTaskJobMetadata(canonicalJson(good))), true);
  const invalid: unknown[] = [
    { ...good, containerId: "b".repeat(12) }, { ...good, imageId: "node:latest" },
    { ...good, engineId: "unix:///var/run/docker.sock" }, { ...good, owner: "../owner with spaces" },
    { ...good, nonce: "d".repeat(63) }, { ...good, schemaVersion: "future" },
    { ...good, taskId: "../task" }, { ...good, taskDescriptorDigest: "missing" },
    { ...good, recordedAtMs: -1 }, { ...good, deadlineAtMs: good.recordedAtMs },
    { ...good, deadlineAtMs: good.recordedAtMs + 600_001 }, { ...good, deadlineAtMs: Number.MAX_SAFE_INTEGER + 1 },
    { ...good, credentials: "forbidden" }, Object.create(good),
    { ...good, readonlyWorkspace: "true" }, { ...good, memoryBytes: 0 }, { ...good, nanoCpus: 0 },
    { ...good, pidsLimit: 0 }, { ...good, pidsLimit: 513 }, { ...good, maxRuntimeMs: 600_001 },
    { ...good, maxRuntimeMs: 100 },
    Object.defineProperty({ ...good }, "containerId", { get() { throw new Error("Accessor must not execute"); }, enumerable: true }),
    Object.defineProperty({ ...good }, "hidden", { value: true, enumerable: false })
  ];
  for (const value of invalid) assert.throws(() => validateContainerTaskJobMetadata(value), brokerError);
  assert.throws(() => parseContainerTaskJobMetadata('{"containerId":"x","containerId":"y"}'),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE");
});

test("all four registered task tools persist exact container authority with an admission audit", () => {
  const store = new BrokerStore(":memory:");
  try {
    for (const [index, tool] of ["mac_codex_run", "mac_test_run", "mac_build_run", "mac_task_run"].entries()) {
      const expected = metadata({ containerId: String(index + 1).repeat(64) });
      const job = record(store, tool, `job:container-${index}`, expected);
      assert.deepEqual(job.containerMetadata, expected);
      assert.equal(job.processMetadata, undefined);
      assert.equal(job.guestMetadata, undefined);
      assert.equal(job.revision, 2);
    }
    assert.equal(store.listUnresolvedTaskContainers().length, 4);
    assert.equal(store.auditRows().filter(row => row.tool === "internal_container_admission").length, 8);
  } finally { store.close(); }
});

test("container identity cannot be reassigned, duplicated across jobs, or replaced under the same revision", () => {
  const store = new BrokerStore(":memory:");
  try {
    const job = record(store);
    for (const value of [metadata(), metadata({ nonce: "f".repeat(64) }), metadata({ containerId: "f".repeat(64) })]) {
      assert.throws(() => store.recordJobContainerOwnership(job.jobId, "principal-1", job.revision, value, lease(), 2), brokerError);
    }
    const other = start(store, "mac_test_run", "job:container-other");
    assert.throws(() => store.recordJobContainerOwnership(other.jobId, "principal-1", other.revision, metadata(), lease(), 2), brokerError);
    assert.deepEqual(store.ownedJob(job.jobId, "principal-1")?.containerMetadata, metadata());
    assert.equal(store.ownedJob(other.jobId, "principal-1")?.containerMetadata, undefined);
    assert.equal(store.listUnresolvedTaskContainers().length, 1);
  } finally { store.close(); }
});

test("container admission rejects queued and non-task jobs, owner mismatch, stale revisions, expired deadlines and leases", () => {
  const store = new BrokerStore(":memory:");
  try {
    store.createJob(jobInput("job:queued"));
    assert.throws(() => store.recordJobContainerOwnership("job:queued", "principal-1", 0, metadata(), lease(), 2), brokerError);
    const terminal = start(store, "mac_terminal_exec", "job:owner-terminal");
    assert.throws(() => store.recordJobContainerOwnership(terminal.jobId, "principal-1", terminal.revision, metadata(), lease(), 2), brokerError);
    const job = start(store);
    assert.throws(() => store.recordJobContainerOwnership(job.jobId, "principal-1", job.revision,
      metadata({ owner: "principal-2" }), lease(), 2), brokerError);
    assert.throws(() => store.recordJobContainerOwnership(job.jobId, "principal-2", job.revision, metadata(), lease(), 2), brokerError);
    assert.throws(() => store.recordJobContainerOwnership(job.jobId, "principal-1", job.revision - 1, metadata(), lease(), 2), brokerError);
    assert.throws(() => store.recordJobContainerOwnership(job.jobId, "principal-1", job.revision, metadata(),
      { ...lease(), token: "lease:wrong-token-1234567" }, 2), brokerError);
    assert.throws(() => store.recordJobContainerOwnership(job.jobId, "principal-1", job.revision, metadata(), lease(), 31), brokerError);
    assert.throws(() => store.recordJobContainerOwnership(job.jobId, "principal-1", job.revision,
      metadata({ recordedAtMs: 0 }), lease(), 2), brokerError);
    assert.throws(() => store.recordJobContainerOwnership(job.jobId, "principal-1", job.revision,
      metadata({ recordedAtMs: 3 }), lease(), 2), brokerError);
    assert.throws(() => store.recordJobContainerOwnership(job.jobId, "principal-1", job.revision,
      metadata({ deadlineAtMs: 3 }), lease(), 3), brokerError);
    assert.equal(store.ownedJob(job.jobId, "principal-1")?.containerMetadata, undefined);
  } finally { store.close(); }
});

test("durable cancellation denies container admission even with the current revision and active lease", () => {
  const store = new BrokerStore(":memory:");
  try {
    const running = start(store);
    const cancelled = store.requestJobCancellation(running.jobId, "principal-1", "TASK_CANCELLED", 2).job;
    assert.throws(() => store.recordJobContainerOwnership(cancelled.jobId, "principal-1", cancelled.revision,
      metadata(), lease(), 2), (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED");
    assert.equal(store.ownedJob(cancelled.jobId, "principal-1")?.containerMetadata, undefined);
    assert.deepEqual(store.listUnresolvedTaskContainers(), []);
    assert.equal(store.auditRows().filter(row => row.tool === "internal_container_admission").length, 0);
  } finally { store.close(); }
});

test("container ownership remains separate from host process and VM guest ownership", () => {
  const store = new BrokerStore(":memory:");
  const processMetadata = { pid: 1234, processGroupId: 1234, startTimeMicros: 987654321, recordedAtMs: 2, descendants: [] };
  const guestMetadata = { requestId: "request:guest-1234567890abcdef", nonce: "guest-nonce-1234567890abcdef",
    requestDigest: "b".repeat(64), guestIdentity: { imageSha256: "c".repeat(64), runtimeVersion: "guest-test" },
    profileDigest: "d".repeat(64), taskDigest: "e".repeat(64), timeoutMs: 10_000, outputCapBytes: 4096, recordedAtMs: 2 };
  try {
    const job = record(store);
    assert.throws(() => store.recordJobProcessOwnership(job.jobId, "principal-1", job.revision, processMetadata, lease(), 2), brokerError);
    assert.throws(() => store.recordJobGuestRequest(job.jobId, "principal-1", job.revision, guestMetadata, lease(), 2), brokerError);
    for (const kind of ["process", "guest"] as const) {
      const running = start(store, "mac_task_run", `job:${kind}-owned`);
      const owned = kind === "process"
        ? store.recordJobProcessOwnership(running.jobId, "principal-1", running.revision, processMetadata, lease(), 2)
        : store.recordJobGuestRequest(running.jobId, "principal-1", running.revision, guestMetadata, lease(), 2);
      assert.throws(() => store.recordJobContainerOwnership(owned.jobId, "principal-1", owned.revision,
        metadata({ containerId: "f".repeat(64) }), lease(), 2), brokerError);
    }
    assert.deepEqual(store.ownedJob(job.jobId, "principal-1")?.containerMetadata, metadata());
  } finally { store.close(); }
});

test("container terminal completion requires verified cleanup and clears only that owned identity", () => {
  const store = new BrokerStore(":memory:");
  try {
    const job = record(store);
    const success = { state: "completed" as const, resultClass: "success" as const, finishedAtMs: 3, exitCode: 0 };
    assert.throws(() => store.finishJob(job.jobId, "principal-1", job.revision, success, lease(), 3), brokerError);
    assert.equal(store.ownedJob(job.jobId, "principal-1")?.state, "running");
    assert.deepEqual(store.ownedJob(job.jobId, "principal-1")?.containerMetadata, metadata());
    const finished = store.finishJob(job.jobId, "principal-1", job.revision,
      { ...success, containerCleanupVerified: true }, lease(), 3);
    assert.equal(finished.state, "completed");
    assert.equal(finished.containerMetadata, undefined);
    assert.deepEqual(store.listUnresolvedTaskContainers(), []);
  } finally { store.close(); }
});

test("container failure and durable cancellation require cleanup before dropping recovery authority", () => {
  for (const state of ["failed", "cancelled"] as const) {
    const store = new BrokerStore(":memory:");
    try {
      let job = record(store);
      if (state === "cancelled") job = store.requestJobCancellation(job.jobId, "principal-1", "TASK_CANCELLED", 3).job;
      const outcome = { state, resultClass: state === "failed" ? "failed" as const : "denied" as const, finishedAtMs: 4 };
      assert.throws(() => store.finishJob(job.jobId, "principal-1", job.revision, outcome, lease(), 4), brokerError);
      const finished = store.finishJob(job.jobId, "principal-1", job.revision,
        { ...outcome, containerCleanupVerified: true }, lease(), 4);
      assert.equal(finished.state, state);
      assert.equal(finished.containerMetadata, undefined);
    } finally { store.close(); }
  }
});

test("UNKNOWN container jobs keep immutable recovery authority and cannot be recovered as success", () => {
  const store = new BrokerStore(":memory:");
  try {
    const job = record(store);
    const unknown = store.finishJob(job.jobId, "principal-1", job.revision,
      { state: "unknown", resultClass: "unknown", finishedAtMs: 3 }, lease(), 3);
    assert.deepEqual(unknown.containerMetadata, metadata());
    assert.equal(store.hasUnresolvedHostTaskExecution(), false);
    assert.throws(() => store.reconcileUnknownContainerTask(job.jobId, "principal-1", unknown.revision,
      metadata({ engineId: "other-engine" }), { state: "failed", finishedAtMs: 4, containerCleanupVerified: true }), brokerError);
    assert.throws(() => store.reconcileUnknownContainerTask(job.jobId, "principal-1", unknown.revision,
      metadata(), { state: "completed" as never, finishedAtMs: 4, containerCleanupVerified: true }), brokerError);
    assert.throws(() => store.reconcileUnknownContainerTask(job.jobId, "principal-1", unknown.revision,
      metadata(), { state: "cancelled", finishedAtMs: 4, containerCleanupVerified: true }), brokerError);
    const recovered = store.reconcileUnknownContainerTask(job.jobId, "principal-1", unknown.revision,
      metadata(), { state: "failed", finishedAtMs: 4, containerCleanupVerified: true });
    assert.equal(recovered.state, "failed");
    assert.equal(recovered.containerMetadata, undefined);
    assert.deepEqual(store.listUnresolvedTaskContainers(), []);
    assert.equal(store.auditRows().filter(row => row.tool === "internal_container_recovery").length, 2);
  } finally { store.close(); }
});

test("SQLite restart conservatively retains container identity as UNKNOWN with cleared lease and verified recovery", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-container-restart-"));
  const path = join(directory, "broker.sqlite");
  let store = new BrokerStore(path);
  try {
    const job = record(store);
    store.close();
    store = new BrokerStore(path);
    const recovered = store.ownedJob(job.jobId, "principal-1")!;
    assert.equal(recovered.state, "unknown");
    assert.equal(recovered.cancelRequested, true);
    assert.deepEqual(recovered.containerMetadata, metadata());
    assert.equal(store.listUnresolvedTaskContainers().length, 1);
    const database = new DatabaseSync(path, { readOnly: true });
    try {
      const row = database.prepare("SELECT lease_token, cancel_reason FROM jobs WHERE job_id = ?").get(job.jobId);
      assert.deepEqual({ ...row }, { lease_token: null, cancel_reason: "BROKER_RESTART" });
    } finally { database.close(); }
    const terminal = store.reconcileUnknownContainerTask(job.jobId, "principal-1", recovered.revision,
      metadata(), { state: "cancelled", finishedAtMs: Date.now(), containerCleanupVerified: true });
    assert.equal(terminal.state, "cancelled");
    assert.equal(terminal.containerMetadata, undefined);
    store.close();
    store = new BrokerStore(path);
    assert.equal(store.ownedJob(job.jobId, "principal-1")?.state, "cancelled");
    assert.deepEqual(store.listUnresolvedTaskContainers(), []);
  } finally { store.close(); await rm(directory, { recursive: true, force: true }); }
});

test("version19 migration adds container ownership without altering existing host ownership", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-container-migrate-"));
  const path = join(directory, "broker.sqlite");
  const store = new BrokerStore(path);
  const running = start(store, "mac_terminal_exec", "job:legacy-terminal");
  const host = { pid: 1234, processGroupId: 1234, startTimeMicros: 987654321, recordedAtMs: 2, descendants: [] };
  store.recordJobProcessOwnership(running.jobId, "principal-1", running.revision, host, lease(), 2);
  store.close();
  try {
    const database = new DatabaseSync(path);
    try {
      database.exec("ALTER TABLE jobs DROP COLUMN container_metadata_json");
      database.prepare("DELETE FROM schema_migrations WHERE version = 20").run();
      database.exec("PRAGMA user_version = 19");
    } finally { database.close(); }
    const migrated = new BrokerStore(path);
    try {
      const job = migrated.ownedJob(running.jobId, "principal-1")!;
      assert.equal(job.state, "unknown");
      assert.deepEqual(job.processMetadata, host);
      assert.equal(job.containerMetadata, undefined);
      assert.deepEqual(migrated.listUnresolvedTaskContainers(), []);
      const readback = new DatabaseSync(path, { readOnly: true });
      try {
        assert.equal(readback.prepare("PRAGMA user_version").get()?.user_version, BROKER_SCHEMA_VERSION);
        const column = readback.prepare("PRAGMA table_info(jobs)").all().find(row => row.name === "container_metadata_json");
        assert.equal(column?.type, "TEXT"); assert.equal(column?.notnull, 1); assert.equal(column?.dflt_value, "''");
      } finally { readback.close(); }
    } finally { migrated.close(); }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("forged or malformed SQLite container ownership fails closed during restart and recovery lookup", async () => {
  for (const change of [
    { containerId: "short" }, { owner: "principal-2" }, { nonce: "f".repeat(64) },
    { credentials: "forbidden" }
  ]) {
    const directory = await mkdtemp(join(tmpdir(), "mac-operator-container-tamper-"));
    const path = join(directory, "broker.sqlite");
    const store = new BrokerStore(path);
    try {
      const job = record(store);
      const database = new DatabaseSync(path);
      try { database.prepare("UPDATE jobs SET container_metadata_json = ? WHERE job_id = ?")
        .run(canonicalJson({ ...metadata(), ...change }), job.jobId); } finally { database.close(); }
      assert.throws(() => store.listUnresolvedTaskContainers(),
        (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE");
    } finally { store.close(); }
    try {
      assert.throws(() => new BrokerStore(path),
        (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE");
    } finally { await rm(directory, { recursive: true, force: true }); }
  }
});

test("container recovery rejects altered admission decisions and timestamps before clearing ownership", async () => {
  const changes = [
    "UPDATE audit_events SET decision = 'deny' WHERE tool = 'internal_container_admission'",
    "UPDATE audit_events SET timestamp_ms = 1 WHERE tool = 'internal_container_admission'",
    "UPDATE audit_events SET timestamp_ms = 10002 WHERE tool = 'internal_container_admission'",
    "UPDATE audit_events SET timestamp_ms = 3 WHERE tool = 'internal_container_admission' AND event_type = 'completion'"
  ];
  for (const change of changes) {
    const directory = await mkdtemp(join(tmpdir(), "mac-operator-container-audit-tamper-"));
    const path = join(directory, "broker.sqlite");
    const store = new BrokerStore(path);
    try {
      const job = record(store);
      const unknown = store.finishJob(job.jobId, "principal-1", job.revision,
        { state: "unknown", resultClass: "unknown", finishedAtMs: 3 }, lease(), 3);
      const database = new DatabaseSync(path);
      try { database.exec(change); } finally { database.close(); }
      assert.throws(() => store.listUnresolvedTaskContainers(),
        (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE");
      assert.throws(() => store.reconcileUnknownContainerTask(job.jobId, "principal-1", unknown.revision,
        metadata(), { state: "failed", finishedAtMs: 4, containerCleanupVerified: true }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE");
      assert.deepEqual(store.ownedJob(job.jobId, "principal-1")?.containerMetadata, metadata());
    } finally { store.close(); await rm(directory, { recursive: true, force: true }); }
  }
});
