import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { lstat, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import { BrokerStore, BROKER_SCHEMA_VERSION } from "./persistence.js";

const archiveKey = {
  keyId: "ledger-export-test-1",
  loadKey: () => Buffer.from("0123456789abcdef0123456789abcdef", "ascii")
};

test("BrokerStore exports terminal Request and Job history without deleting live records", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-broker-ledger-export-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    store.admitRequest({
      requestId: "ledger-request-denied",
      edgeId: "edge-1",
      nonce: "ledger-nonce-denied",
      nonceExpiresAtMs: 10_000,
      principalId: "principal-1",
      sessionId: "session-1",
      tool: "mac_health",
      policyVersion: "policy-0.1",
      payloadDigest: "c".repeat(64),
      mutation: false,
      receivedAtMs: 1
    });
    store.failRequest({
      requestId: "ledger-request-denied",
      principalId: "principal-1",
      tool: "mac_health",
      eventType: "decision",
      decision: "deny",
      resultClass: "SCOPE_DENIED",
      targetRef: "host:broker",
      policyVersion: "policy-0.1",
      evidence: { reason: "test" },
      timestampMs: 2
    });

    store.createJob({
      jobId: "job:ledger-terminal",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_task_run",
      targetRef: "task:test",
      policyVersion: "policy-0.1",
      payloadDigest: "a".repeat(64),
      idempotencyKey: "ledger-terminal",
      createdAtMs: 1
    });
    store.startJob("job:ledger-terminal", "principal-1", 0, 2);
    store.finishJob("job:ledger-terminal", "principal-1", 1, {
      state: "completed",
      resultClass: "success",
      finishedAtMs: 3,
      exitCode: 0,
      stdout: "safe terminal output"
    });
    store.createJob({
      jobId: "job:ledger-active",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_task_run",
      targetRef: "task:active",
      policyVersion: "policy-0.1",
      payloadDigest: "b".repeat(64),
      idempotencyKey: "ledger-active",
      createdAtMs: 4
    });

    const manifest = await store.exportLedgerArchive(directory, { keySource: archiveKey, nowMs: 1_700_000_000_100 });
    assert.match(manifest.path, /ledger-export-1700000000100-[a-f0-9]{24}\.json\.enc$/u);
    assert.equal(manifest.requestCount, 1);
    assert.equal(manifest.jobCount, 1);
    assert.equal(manifest.encrypted, true);
    assert.equal((await lstat(manifest.path)).mode & 0o777, 0o600);
    assert.equal((await readFile(manifest.path)).includes(Buffer.from("safe terminal output", "utf8")), false);
    assert.deepEqual(await BrokerStore.inspectLedgerArchive(manifest.path, archiveKey), manifest);
    assert.equal(store.requestRecord("ledger-request-denied")?.state, "DENIED");
    assert.equal(store.ownedJob("job:ledger-terminal", "principal-1")?.state, "completed");
    assert.equal(store.ownedJob("job:ledger-active", "principal-1")?.state, "queued");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("ledger archive preserves the authenticated guest result needed by an unknown Job", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-broker-guest-result-archive-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const metadata = {
    requestId: "request:guest-archive-12345678",
    nonce: "guest-nonce-archive-12345678",
    requestDigest: "a".repeat(64),
    guestIdentity: { imageSha256: "b".repeat(64), runtimeVersion: "macos-guest-1" },
    profileDigest: "c".repeat(64),
    taskDigest: "d".repeat(64),
    timeoutMs: 1_000,
    outputCapBytes: 1_024,
    recordedAtMs: 3
  } as const;
  const lease = { ownerId: "broker:guest-archive", token: "lease:guest-archive-1234", expiresAtMs: 30 };
  try {
    store.createJob({
      jobId: "job:guest-result-archive",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_task_run",
      targetRef: "task:test",
      policyVersion: "policy-0.1",
      payloadDigest: "e".repeat(64),
      idempotencyKey: "guest-result-archive",
      createdAtMs: 1
    });
    const started = store.startJob("job:guest-result-archive", "principal-1", 0, 2, lease);
    const admitted = store.recordJobGuestRequest("job:guest-result-archive", "principal-1", started.revision, metadata, lease, 3);
    const journaled = store.recordJobGuestResult(
      "job:guest-result-archive", "principal-1", admitted.revision,
      {
        state: "completed",
        resultClass: "SUCCEEDED",
        exitCode: 0,
        stdout: "journal must remain recoverable",
        stderr: "",
        truncated: false,
        durationMs: 5,
        verification: { status: "verified", summary: "authenticated guest response" }
      },
      lease,
      4
    );
    const unknown = store.finishJob(
      "job:guest-result-archive", "principal-1", journaled.revision,
      { state: "unknown", resultClass: "unknown", finishedAtMs: 5 }, lease, 5
    );
    assert.ok(unknown.guestResultJournal);

    const manifest = await store.exportLedgerArchive(directory, { keySource: archiveKey, nowMs: 1_700_000_000_104 });
    assert.equal(manifest.jobCount, 1);
    assert.equal(manifest.snapshotDigest, sha256(canonicalJson({ requests: [], jobs: [unknown] })));
    assert.equal((await readFile(manifest.path)).includes(Buffer.from("journal must remain recoverable", "utf8")), false);
    assert.deepEqual(await BrokerStore.inspectLedgerArchive(manifest.path, archiveKey), manifest);
    assert.equal(store.ownedJob("job:guest-result-archive", "principal-1")?.state, "unknown");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("encrypted ledger round-trip retains schema-20 UNKNOWN container authority without inferring success", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-broker-container-archive-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  const metadata = {
    schemaVersion: "0.1",
    containerId: "b".repeat(64),
    engineId: "engine-container-archive-1",
    imageId: `sha256:${"c".repeat(64)}`,
    taskId: "task-container-archive-1",
    owner: "principal-1",
    nonce: "d".repeat(64),
    taskDescriptorDigest: "e".repeat(64),
    recordedAtMs: 3,
    deadlineAtMs: 10_003,
    readonlyWorkspace: false,
    memoryBytes: 512 * 1024 * 1024,
    nanoCpus: 1_000_000_000,
    pidsLimit: 128,
    maxRuntimeMs: 10_000
  } as const;
  const lease = { ownerId: "broker:container-archive", token: "lease:container-archive-123456", expiresAtMs: 30 };
  try {
    const database = new DatabaseSync(databasePath, { readOnly: true });
    try {
      assert.equal(BROKER_SCHEMA_VERSION, 20);
      assert.equal(database.prepare("PRAGMA user_version").get()?.user_version, BROKER_SCHEMA_VERSION);
    } finally { database.close(); }
    store.createJob({
      jobId: "job:container-archive",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_codex_run",
      targetRef: "task:container-archive",
      policyVersion: "policy-0.1",
      payloadDigest: "a".repeat(64),
      idempotencyKey: "container-archive",
      createdAtMs: 1
    });
    const started = store.startJob("job:container-archive", "principal-1", 0, 2, lease);
    const admitted = store.recordJobContainerOwnership(started.jobId, "principal-1", started.revision, metadata, lease, 3);
    const unknown = store.finishJob(admitted.jobId, "principal-1", admitted.revision,
      { state: "unknown", resultClass: "unknown", finishedAtMs: 4 }, lease, 4);
    assert.deepEqual(unknown.containerMetadata, metadata);
    assert.deepEqual(store.listUnresolvedTaskContainers(), [unknown]);

    const manifest = await store.exportLedgerArchive(directory, { keySource: archiveKey, nowMs: 1_700_000_000_105 });
    assert.equal(manifest.encrypted, true);
    assert.equal(manifest.jobCount, 1);
    assert.equal(manifest.requestCount, 0);
    // Inspection authenticates and normalizes every record before checking this full-record digest.
    const expectedDigest = sha256(canonicalJson({ requests: [], jobs: [unknown] }));
    assert.equal(manifest.snapshotDigest, expectedDigest);
    assert.deepEqual(await BrokerStore.inspectLedgerArchive(manifest.path, archiveKey), manifest);
    assert.equal((await readFile(manifest.path)).includes(Buffer.from(metadata.engineId, "utf8")), false);
    assert.deepEqual(store.ownedJob(unknown.jobId, "principal-1"), unknown);

    const rejectsRecovery = (error: unknown) => error instanceof BrokerError;
    assert.throws(() => store.reconcileUnknownContainerTask(unknown.jobId, "principal-1", unknown.revision,
      { ...metadata, containerId: "f".repeat(64) },
      { state: "failed", finishedAtMs: 5, containerCleanupVerified: true }), rejectsRecovery);
    assert.throws(() => store.reconcileUnknownContainerTask(unknown.jobId, "principal-1", unknown.revision, metadata,
      { state: "completed" as never, finishedAtMs: 5, containerCleanupVerified: true }), rejectsRecovery);
    assert.throws(() => store.reconcileUnknownContainerTask(unknown.jobId, "principal-1", unknown.revision, metadata,
      { state: "failed", finishedAtMs: 5, containerCleanupVerified: false as never }), rejectsRecovery);
    assert.deepEqual(store.ownedJob(unknown.jobId, "principal-1"), unknown);

    const recovered = store.reconcileUnknownContainerTask(unknown.jobId, "principal-1", unknown.revision, metadata,
      { state: "failed", finishedAtMs: 5, containerCleanupVerified: true });
    assert.equal(recovered.state, "failed");
    assert.equal(recovered.resultClass, "failed");
    assert.equal(recovered.exitCode, null);
    assert.equal(recovered.containerMetadata, undefined);
    assert.deepEqual(store.listUnresolvedTaskContainers(), []);
    // Cleaning the live task cannot rewrite its archived UNKNOWN authority or manufacture a successful result.
    assert.deepEqual(await BrokerStore.inspectLedgerArchive(manifest.path, archiveKey), manifest);
    assert.equal(manifest.snapshotDigest, expectedDigest);
    assert.deepEqual(store.auditRows().filter(row => row.tool === "internal_container_recovery")
      .map(row => row.result_class), ["INTENT_RECORDED", "CONTAINER_CLEANUP_VERIFIED"]);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("ledger export fails before creating a temporary file when capacity is insufficient", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-broker-ledger-export-capacity-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  let requiredBytes = 0;
  try {
    await assert.rejects(
      store.exportLedgerArchive(directory, {
        keySource: archiveKey,
        nowMs: 1_700_000_000_103,
        capacityProbe: async (_path, required) => {
          requiredBytes = required;
          return required - 1;
        }
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE" && error.retryable
    );
    assert.ok(requiredBytes > 0);
    const names = await readdir(directory);
    assert.equal(names.some((name) => name.startsWith("ledger-export-") || name.startsWith(".ledger-export-")), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("ledger archive inspection rejects ciphertext tampering and wrong key material", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-broker-ledger-export-tamper-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const manifest = await store.exportLedgerArchive(directory, { keySource: archiveKey, nowMs: 1_700_000_000_101 });
    const tampered = await readFile(manifest.path);
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 0xff;
    await writeFile(manifest.path, tampered, { mode: 0o600 });
    await assert.rejects(
      BrokerStore.inspectLedgerArchive(manifest.path, archiveKey),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    await assert.rejects(
      BrokerStore.inspectLedgerArchive(manifest.path, {
        keyId: archiveKey.keyId,
        loadKey: () => randomBytes(32)
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("ledger archive inspection rejects a symlinked archive path", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-broker-ledger-export-symlink-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const manifest = await store.exportLedgerArchive(directory, { keySource: archiveKey, nowMs: 1_700_000_000_102 });
    const alias = join(directory, `ledger-export-1700000000103-${"a".repeat(24)}.json.enc`);
    await symlink(manifest.path, alias);
    await assert.rejects(
      BrokerStore.inspectLedgerArchive(alias, archiveKey),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("ledger rotation archives terminal history, preserves tombstone status, and rejects replay or idempotency reuse", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-broker-ledger-rotation-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath, { runtimeFence: true });
  try {
    store.admitRequest({
      requestId: "rotation-request-denied",
      edgeId: "edge-1",
      edgeKeyId: "edge-1:edge-key-rotation",
      nonce: "rotation-nonce-denied",
      nonceExpiresAtMs: 10_000,
      principalId: "principal-1",
      sessionId: "session-1",
      tool: "mac_health",
      policyVersion: "policy-0.1",
      payloadDigest: "c".repeat(64),
      mutation: false,
      receivedAtMs: 1
    });
    store.failRequest({
      requestId: "rotation-request-denied",
      principalId: "principal-1",
      tool: "mac_health",
      eventType: "decision",
      decision: "deny",
      resultClass: "SCOPE_DENIED",
      targetRef: "host:broker",
      policyVersion: "policy-0.1",
      evidence: { reason: "rotation-test" },
      timestampMs: 2
    });

    const terminalJob = {
      jobId: "job:rotation-terminal",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_task_run",
      targetRef: "task:rotation",
      policyVersion: "policy-0.1",
      payloadDigest: "a".repeat(64),
      idempotencyKey: "rotation-terminal",
      createdAtMs: 3
    } as const;
    store.createJob(terminalJob);
    store.startJob(terminalJob.jobId, terminalJob.ownerPrincipalId, 0, 4);
    store.finishJob(terminalJob.jobId, terminalJob.ownerPrincipalId, 1, {
      state: "completed",
      resultClass: "success",
      finishedAtMs: 5,
      exitCode: 0,
      stdout: "terminal output must not remain in the tombstone"
    });

    store.createJob({
      jobId: "job:rotation-active",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_task_run",
      targetRef: "task:active",
      policyVersion: "policy-0.1",
      payloadDigest: "b".repeat(64),
      idempotencyKey: "rotation-active",
      createdAtMs: 6
    });
    store.createJob({
      jobId: "job:rotation-unknown",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_task_run",
      targetRef: "task:unknown",
      policyVersion: "policy-0.1",
      payloadDigest: "d".repeat(64),
      idempotencyKey: "rotation-unknown",
      createdAtMs: 7
    });
    store.startJob("job:rotation-unknown", "principal-1", 0, 8);
    store.finishJob("job:rotation-unknown", "principal-1", 1, {
      state: "unknown",
      resultClass: "unknown",
      finishedAtMs: 9
    });

    const rotation = await store.rotateLedgerArchive(directory, {
      keySource: archiveKey,
      nowMs: 100_000,
      retainRequestCount: 0,
      retainJobCount: 0,
      minAgeMs: 1_000
    });
    assert.equal(rotation.rotatedRequestCount, 1);
    assert.equal(rotation.rotatedJobCount, 1);
    assert.equal(rotation.requestTombstoneCount, 1);
    assert.equal(rotation.jobTombstoneCount, 1);
    assert.deepEqual(await BrokerStore.inspectLedgerArchive(rotation.archive.path, archiveKey), rotation.archive);
    const tombstones = new DatabaseSync(databasePath);
    try {
      const row = tombstones.prepare(
        "SELECT edge_key_id FROM request_tombstones WHERE request_id = ?"
      ).get("rotation-request-denied") as { edge_key_id?: unknown } | undefined;
      assert.equal(row?.edge_key_id, "edge-1:edge-key-rotation");
    } finally {
      tombstones.close();
    }
    assert.equal(store.requestRecord("rotation-request-denied"), undefined);
    assert.equal(store.ownedJob("job:rotation-terminal", "principal-1"), undefined);
    assert.equal(store.ownedJob("job:rotation-active", "principal-1")?.state, "queued");
    assert.equal(store.ownedJob("job:rotation-unknown", "principal-1")?.state, "unknown");

    const archived = store.ownedJobStatus("job:rotation-terminal", "principal-1").archived;
    assert.equal(archived?.state, "completed");
    assert.equal(archived?.resultClass, "success");
    assert.equal(archived?.finishedAtMs, 5);
    assert.equal(archived?.archiveSha256, rotation.archive.sha256);
    assert.throws(
      () => store.admitRequest({
        requestId: "rotation-request-denied",
        edgeId: "edge-1",
        nonce: "rotation-nonce-replay",
        nonceExpiresAtMs: 20_000,
        principalId: "principal-1",
        sessionId: "session-1",
        tool: "mac_health",
        policyVersion: "policy-0.1",
        payloadDigest: "c".repeat(64),
        mutation: false,
        receivedAtMs: 10
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "REPLAY_DENIED"
    );
    assert.throws(
      () => store.createJob(terminalJob),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT"
    );
    assert.throws(
      () => store.createJob({ ...terminalJob, idempotencyKey: "rotation-new-key" }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT"
    );
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("ledger rotation requires the stopped-service runtime fence and reopens verified tombstones", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-broker-ledger-rotation-fence-"));
  const databasePath = join(directory, "broker.sqlite");
  const unfencedStore = new BrokerStore(databasePath);
  try {
    await assert.rejects(
      unfencedStore.rotateLedgerArchive(directory, {
        keySource: archiveKey,
        retainRequestCount: 0,
        retainJobCount: 0,
        minAgeMs: 0,
        nowMs: 100_000
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
  } finally {
    unfencedStore.close();
  }

  const fencedStore = new BrokerStore(databasePath, { runtimeFence: true });
  try {
    fencedStore.createJob({
      jobId: "job:rotation-reopen",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_task_run",
      targetRef: "task:reopen",
      policyVersion: "policy-0.1",
      payloadDigest: "e".repeat(64),
      idempotencyKey: "rotation-reopen",
      createdAtMs: 1
    });
    fencedStore.startJob("job:rotation-reopen", "principal-1", 0, 2);
    fencedStore.finishJob("job:rotation-reopen", "principal-1", 1, {
      state: "failed",
      resultClass: "failed",
      finishedAtMs: 3,
      exitCode: 1
    });
    await assert.rejects(
      fencedStore.rotateLedgerArchive(directory, {
        keySource: {
          keyId: archiveKey.keyId,
          loadKey: () => { throw new Error("archive key unavailable"); }
        },
        capacityProbe: async (_path, requiredBytes) => requiredBytes - 1,
        retainRequestCount: 0,
        retainJobCount: 0,
        minAgeMs: 0,
        nowMs: 100_000
      })
    );
    assert.equal(fencedStore.ownedJob("job:rotation-reopen", "principal-1")?.state, "failed");
    await fencedStore.rotateLedgerArchive(directory, {
      keySource: archiveKey,
      retainRequestCount: 0,
      retainJobCount: 0,
      minAgeMs: 0,
      nowMs: 100_000
    });
  } finally {
    fencedStore.close();
  }

  const reopenedStore = new BrokerStore(databasePath, { runtimeFence: true });
  try {
    const status = reopenedStore.ownedJobStatus("job:rotation-reopen", "principal-1");
    assert.equal(status.archived?.state, "failed");
    assert.equal(status.archived?.resultClass, "failed");
  } finally {
    reopenedStore.close();
    await rm(directory, { recursive: true, force: true });
  }
});
