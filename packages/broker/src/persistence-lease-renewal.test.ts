import assert from "node:assert/strict";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { BrokerStore, type BrokerJob, type JobLease } from "./persistence.js";

const START = 1_700_000_000_000;
const JOB = "job:rolling-lease";
const PRINCIPAL = "principal-1";
const LEASE_MS = 30_000;
const MAX_LEASE_MS = 120_000;

type LeaseRow = {
  lease_owner_id: string | null;
  lease_token: string | null;
  lease_acquired_at_ms: number | null;
  lease_heartbeat_at_ms: number | null;
  lease_expires_at_ms: number | null;
};
async function fixture() {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mac-rolling-lease-")));
  const path = join(directory, "broker.sqlite");
  let store = new BrokerStore(path);
  let open = true;
  const lease: JobLease = { ownerId: "broker:rolling-lease-fixture", token: "lease:rolling-fixture-1234567890", expiresAtMs: START + LEASE_MS };
  store.createJob({ jobId: JOB, ownerPrincipalId: PRINCIPAL, ownerSessionId: "session-1", tool: "mac_task_run",
    targetRef: "task_profile:fixture.test", policyVersion: "policy-0.1", payloadDigest: "a".repeat(64),
    idempotencyKey: "rolling-lease", createdAtMs: START });
  store.startJob(JOB, PRINCIPAL, 0, START, lease);
  function row(): LeaseRow {
    const inspected = new DatabaseSync(path, { readOnly: true });
    try { return { ...inspected.prepare("SELECT lease_owner_id, lease_token, lease_acquired_at_ms, lease_heartbeat_at_ms, lease_expires_at_ms FROM jobs WHERE job_id = ?").get(JOB) } as LeaseRow; }
    finally { inspected.close(); }
  }
  function tamper(column: keyof LeaseRow, value: string | number | null) {
    assert.ok(["lease_owner_id", "lease_token", "lease_acquired_at_ms", "lease_heartbeat_at_ms", "lease_expires_at_ms"].includes(column));
    const database = new DatabaseSync(path);
    try { database.prepare(`UPDATE jobs SET ${column} = ? WHERE job_id = ?`).run(value, JOB); }
    finally { database.close(); }
  }
  function read(): BrokerJob {
    const job = store.ownedJob(JOB, PRINCIPAL);
    assert.ok(job);
    return job;
  }
  function renewUntil(elapsedMs: number) {
    for (let elapsed = 25_000; elapsed <= elapsedMs; elapsed += 25_000) {
      const now = START + elapsed;
      assert.equal(store.renewJobLease(JOB, PRINCIPAL, lease, now, LEASE_MS), lease);
      assert.equal(lease.expiresAtMs, now + LEASE_MS);
      assert.equal(read().state, "running");
      const saved = row();
      assert.deepEqual(saved, { lease_owner_id: lease.ownerId, lease_token: lease.token,
        lease_acquired_at_ms: START, lease_heartbeat_at_ms: now, lease_expires_at_ms: now + LEASE_MS });
      assert.equal(saved.lease_expires_at_ms! - saved.lease_heartbeat_at_ms!, LEASE_MS);
    }
  }
  return { path, lease, row, tamper, read, renewUntil, get store() { return store; },
    reopen() { store.close(); open = false; store = new BrokerStore(path); open = true; },
    async close() { if (open) store.close(); await rm(directory, { recursive: true, force: true }); }
  };
}
const brokerError = (error: unknown) => error instanceof BrokerError;

test("rolling SQLite leases remain readable beyond ten minutes and allow verified terminal completion", async () => {
  const f = await fixture();
  try {
    // The Store tests rolling authority only; executors enforce task runtime separately.
    f.renewUntil(900_000);
    const saved = f.row();
    assert.ok(saved.lease_expires_at_ms! - saved.lease_acquired_at_ms! > 600_000);
    assert.ok(saved.lease_expires_at_ms! - saved.lease_acquired_at_ms! > MAX_LEASE_MS);
    const current = f.read();
    const done = f.store.finishJob(JOB, PRINCIPAL, current.revision, { state: "completed", resultClass: "success", finishedAtMs: START + 900_001, exitCode: 0 }, f.lease, START + 900_001);
    assert.equal(done.state, "completed");
    assert.deepEqual(Object.values(f.row()), [null, null, null, null, null]);
    f.store.verifyAuditIntegrity();
    f.reopen();
    assert.equal(f.read().state, "completed");
    assert.equal(f.read().exitCode, 0);
  } finally { await f.close(); }
});

test("restart reads a long renewed lease before conservatively marking interrupted work UNKNOWN", async () => {
  const f = await fixture();
  try {
    f.renewUntil(900_000);
    const before = f.read();
    f.reopen();
    const recovered = f.read();
    assert.equal(recovered.state, "unknown");
    assert.equal(recovered.cancelRequested, true);
    assert.equal(recovered.revision, before.revision + 1);
    assert.deepEqual(Object.values(f.row()), [null, null, null, null, null]);
    assert.throws(() => f.store.renewJobLease(JOB, PRINCIPAL, { ...f.lease, expiresAtMs: START + 920_000 }, START + 900_001, LEASE_MS), brokerError);
    assert.throws(() => f.store.finishJob(JOB, PRINCIPAL, before.revision, { state: "completed", resultClass: "success", finishedAtMs: START + 900_001 }, f.lease, START + 900_001), brokerError);
    assert.equal(f.read().state, "unknown");
    f.store.verifyAuditIntegrity();
  } finally { await f.close(); }
});

test("durable cancellation fences further renewal and success after a long running task", async () => {
  const f = await fixture();
  try {
    f.renewUntil(700_000);
    const cancelled = f.store.requestJobCancellation(JOB, PRINCIPAL, "fixture cancellation", START + 700_001).job;
    const saved = f.row();
    assert.equal(cancelled.cancelRequested, true);
    assert.throws(() => f.store.renewJobLease(JOB, PRINCIPAL, f.lease, START + 700_002, LEASE_MS), brokerError);
    assert.deepEqual(f.row(), saved);
    assert.throws(() => f.store.finishJob(JOB, PRINCIPAL, cancelled.revision, { state: "completed", resultClass: "success", finishedAtMs: START + 700_003 }, f.lease, START + 700_003), brokerError);
    const done = f.store.finishJob(JOB, PRINCIPAL, cancelled.revision, { state: "cancelled", resultClass: "denied", finishedAtMs: START + 700_004 }, f.lease, START + 700_004);
    assert.equal(done.state, "cancelled");
    assert.deepEqual(Object.values(f.row()), [null, null, null, null, null]);
    f.reopen();
    assert.equal(f.read().state, "cancelled");
  } finally { await f.close(); }
});

test("lease renewals preserve bounded per-heartbeat durations at both accepted limits", async () => {
  const f = await fixture();
  try {
    f.store.renewJobLease(JOB, PRINCIPAL, f.lease, START + 1, 1_000);
    assert.equal(f.lease.expiresAtMs, START + 1_001);
    f.store.renewJobLease(JOB, PRINCIPAL, f.lease, START + 2, MAX_LEASE_MS);
    assert.equal(f.lease.expiresAtMs, START + 2 + MAX_LEASE_MS);
    assert.equal(f.read().state, "running");
    assert.equal(f.row().lease_expires_at_ms! - f.row().lease_heartbeat_at_ms!, MAX_LEASE_MS);
    for (const duration of [0, 999, MAX_LEASE_MS + 1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER]) {
      const saved = f.row(), expires = f.lease.expiresAtMs;
      assert.throws(() => f.store.renewJobLease(JOB, PRINCIPAL, f.lease, START + 3, duration), brokerError);
      assert.deepEqual(f.row(), saved);
      assert.equal(f.lease.expiresAtMs, expires);
    }
  } finally { await f.close(); }
});

test("lease renewals reject another owner, token, principal, expired caller and future caller authority", async () => {
  const f = await fixture();
  try {
    f.renewUntil(200_000);
    const now = START + 200_001;
    const saved = f.row();
    for (const [principal, lease] of [
      ["principal-2", { ...f.lease }],
      [PRINCIPAL, { ...f.lease, ownerId: "broker:another-owner" }],
      [PRINCIPAL, { ...f.lease, token: "lease:another-token-1234567890" }],
      [PRINCIPAL, { ...f.lease, expiresAtMs: now }],
      [PRINCIPAL, { ...f.lease, expiresAtMs: now + MAX_LEASE_MS + 1 }]
    ] as const) {
      assert.throws(() => f.store.renewJobLease(JOB, principal, lease, now, LEASE_MS), brokerError);
      assert.deepEqual(f.row(), saved);
    }
    assert.equal(f.read().state, "running");
  } finally { await f.close(); }
});

test("a forged caller expiration cannot revive an expired durable lease", async () => {
  const f = await fixture();
  try {
    f.renewUntil(200_000);
    const now = f.lease.expiresAtMs;
    const forged = { ...f.lease, expiresAtMs: now + LEASE_MS };
    const saved = f.row();
    assert.throws(() => f.store.renewJobLease(JOB, PRINCIPAL, forged, now, LEASE_MS), brokerError);
    assert.throws(() => f.store.finishJob(JOB, PRINCIPAL, f.read().revision, { state: "completed", resultClass: "success", finishedAtMs: now }, forged, now), brokerError);
    assert.deepEqual(f.row(), saved);
    const unknown = f.store.finishJob(JOB, PRINCIPAL, f.read().revision, { state: "unknown", resultClass: "unknown", finishedAtMs: now }, f.lease, now);
    assert.equal(unknown.state, "unknown");
  } finally { await f.close(); }
});

test("lease renewals and terminal completion cannot move before their last durable heartbeat", async () => {
  const f = await fixture();
  try {
    f.renewUntil(200_000);
    const saved = f.row();
    const backwards = START + 199_999;
    assert.throws(() => f.store.renewJobLease(JOB, PRINCIPAL, f.lease, backwards, LEASE_MS), brokerError);
    assert.deepEqual(f.row(), saved);
    for (const state of ["completed", "unknown"] as const) {
      assert.throws(() => f.store.finishJob(JOB, PRINCIPAL, f.read().revision,
        { state, resultClass: state === "completed" ? "success" : "unknown", finishedAtMs: backwards }, f.lease, backwards), brokerError);
      assert.deepEqual(f.row(), saved);
    }
    assert.equal(f.read().state, "running");
  } finally { await f.close(); }
});

test("lease renewal rejects malformed clocks and prevents unsafe expiration arithmetic", async () => {
  const f = await fixture();
  try {
    const saved = f.row();
    for (const now of [-1, NaN, Infinity, START + 0.5, Number.MAX_SAFE_INTEGER + 1]) {
      assert.throws(() => f.store.renewJobLease(JOB, PRINCIPAL, f.lease, now, LEASE_MS), brokerError);
      assert.deepEqual(f.row(), saved);
    }
    // An active lease near the integer boundary still cannot overflow on renewal.
    const high = Number.MAX_SAFE_INTEGER - 10;
    f.tamper("lease_acquired_at_ms", high);
    f.tamper("lease_heartbeat_at_ms", high);
    f.tamper("lease_expires_at_ms", Number.MAX_SAFE_INTEGER);
    assert.equal(f.read().state, "running");
    assert.throws(() => f.store.renewJobLease(JOB, PRINCIPAL, { ...f.lease, expiresAtMs: Number.MAX_SAFE_INTEGER }, high + 1, LEASE_MS), brokerError);
  } finally { await f.close(); }
});

for (const corrupt of [
  { name: "heartbeat before acquisition", column: "lease_heartbeat_at_ms", value: START - 1 },
  { name: "expiration before acquisition", column: "lease_expires_at_ms", value: START - 1 },
  { name: "expiration before heartbeat", column: "lease_expires_at_ms", value: START + 199_999 },
  { name: "heartbeat duration above its cap", column: "lease_expires_at_ms", value: START + 200_000 + MAX_LEASE_MS + 1 },
  { name: "partial lease identity", column: "lease_token", value: null },
  { name: "malformed lease owner", column: "lease_owner_id", value: "owner with spaces" }
] as const) {
  test(`stored rolling leases reject ${corrupt.name} on reads and restart`, async () => {
    const f = await fixture();
    try {
      f.renewUntil(200_000);
      f.tamper(corrupt.column, corrupt.value);
      assert.throws(() => f.store.ownedJob(JOB, PRINCIPAL), (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE");
      assert.throws(() => f.reopen());
    } finally { await f.close(); }
  });
}
