import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { lstat, mkdtemp, readFile, readdir, rm, symlink, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import { guiSessionApprovalId, BROKER_SCHEMA_VERSION, BrokerStore, type CreateJobInput, type JobState, type SwitchName } from "./persistence.js";

const testBackupKeySource = {
  keyId: "backup-test-1",
  loadKey: () => Buffer.from("0123456789abcdef0123456789abcdef", "ascii")
};

/** Matches a CONFLICT whose message itself (not its string form, which starts with the class name) satisfies the pattern. */
function conflictMatching(pattern: RegExp): (error: unknown) => boolean {
  return (error) => error instanceof BrokerError && error.errorClass === "CONFLICT" && pattern.test(error.message);
}

/** Runs an action that must fail with a CONFLICT and returns its message. */
function conflictMessage(action: () => unknown): string {
  try {
    action();
  } catch (error) {
    assert.ok(error instanceof BrokerError, String(error));
    assert.equal(error.errorClass, "CONFLICT", error.message);
    return error.message;
  }
  return assert.fail("Expected a CONFLICT");
}

test("BrokerStore records a monotonic schema version after initialization", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-schema-version-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  store.close();
  try {
    const database = new DatabaseSync(databasePath);
    try {
      const row = database.prepare("PRAGMA user_version").get() as { user_version?: unknown };
      assert.equal(row.user_version, BROKER_SCHEMA_VERSION);
      const migrations = (database.prepare("SELECT version, name FROM schema_migrations ORDER BY version").all() as Array<{ version: number; name: string }>).map(({ version, name }) => ({ version, name }));
      assert.deepEqual(migrations, [
        { version: 1, name: "baseline" },
        { version: 2, name: "revocations-edge-and-operator-key-kinds" },
        { version: 3, name: "request-approval-and-job-linkage" },
        { version: 4, name: "job-lease-process-and-helper-metadata" },
        { version: 5, name: "broker-runtime-fence" },
        { version: 6, name: "virtualization-guest-replay-ledger" },
        { version: 7, name: "virtualization-guest-task-metadata" },
        { version: 8, name: "virtualization-guest-attestation-key-config" },
        { version: 9, name: "request-capability-family-capacity" },
        { version: 10, name: "job-edge-provenance" },
        { version: 11, name: "job-edge-key-provenance" },
        { version: 12, name: "keychain-delivery-replay-ledger" },
        { version: 13, name: "user-service-control-job-metadata" },
        { version: 14, name: "pending-approval-previews" },
        { version: 15, name: "approval-preview-lifecycle" },
        { version: 16, name: "edge-revocation-replay-ledger" },
        { version: 17, name: "terminal-ledger-tombstones" },
        { version: 18, name: "request-edge-key-provenance" },
        { version: 19, name: "guest-task-authenticated-result-journal" },
        { version: 20, name: "container-task-ownership-metadata" }
      ]);
    } finally {
      database.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore reads back the complete migration registry before startup", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-schema-readback-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  store.close();
  try {
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare("UPDATE schema_migrations SET name = ? WHERE version = 9").run("tampered");
    } finally {
      database.close();
    }
    assert.throws(
      () => new BrokerStore(databasePath),
      /migration identity changed/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore bounds virtualization guest replay ledger capacity", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-guest-replay-capacity-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  try {
    for (let index = 0; index < 4_096; index += 1) {
      const suffix = String(index).padStart(16, "0");
      store.admitVirtualizationGuestRequest({
        requestId: `request:guest-capacity-${suffix}`,
        nonce: `guest-nonce-capacity-${suffix}`,
        acceptedAtMs: 1,
        expiresAtMs: 100_000
      });
    }
    assert.throws(
      () => store.admitVirtualizationGuestRequest({
        requestId: "request:guest-capacity-overflow-123456",
        nonce: "guest-nonce-capacity-overflow-123456",
        acceptedAtMs: 2,
        expiresAtMs: 100_000
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    store.admitVirtualizationGuestRequest({
      requestId: "request:guest-capacity-expired-123456",
      nonce: "guest-nonce-capacity-expired-123456",
      acceptedAtMs: 100_001,
      expiresAtMs: 200_000
    });
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore persists Keychain delivery replay identities across restart and reclaims exact expiry", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-keychain-replay-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  try {
    store.admitKeychainDeliveryRequest({
      requestId: "keychain-request-1",
      nonce: "keychain-nonce-1",
      acceptedAtMs: 100,
      expiresAtMs: 200
    });
    assert.throws(
      () => store.admitKeychainDeliveryRequest({
        requestId: "keychain-request-1",
        nonce: "keychain-nonce-2",
        acceptedAtMs: 101,
        expiresAtMs: 201
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "REPLAY_DENIED"
    );
  } finally {
    store.close();
  }
  const reopened = new BrokerStore(databasePath);
  try {
    assert.throws(
      () => reopened.admitKeychainDeliveryRequest({
        requestId: "keychain-request-2",
        nonce: "keychain-nonce-1",
        acceptedAtMs: 150,
        expiresAtMs: 250
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "REPLAY_DENIED"
    );
    reopened.admitKeychainDeliveryRequest({
      requestId: "keychain-request-2",
      nonce: "keychain-nonce-2",
      acceptedAtMs: 200,
      expiresAtMs: 300
    });
  } finally {
    reopened.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore persists Edge OAuth revocation replay identities across restart", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-edge-revocation-replay-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  try {
    store.admitEdgeRevocationEvent({
      requestId: "edge-revoke:1234567890123456",
      nonce: "edge-revoke-nonce:1234567890123456",
      edgeId: "edge-1",
      acceptedAtMs: 100,
      expiresAtMs: 200
    });
    assert.throws(
      () => store.admitEdgeRevocationEvent({
        requestId: "edge-revoke:1234567890123456",
        nonce: "edge-revoke-nonce:2234567890123456",
        edgeId: "edge-1",
        acceptedAtMs: 101,
        expiresAtMs: 201
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "REPLAY_DENIED"
    );
  } finally {
    store.close();
  }
  const reopened = new BrokerStore(databasePath);
  try {
    assert.throws(
      () => reopened.admitEdgeRevocationEvent({
        requestId: "edge-revoke:2234567890123456",
        nonce: "edge-revoke-nonce:1234567890123456",
        edgeId: "edge-1",
        acceptedAtMs: 150,
        expiresAtMs: 250
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "REPLAY_DENIED"
    );
    reopened.admitEdgeRevocationEvent({
      requestId: "edge-revoke:2234567890123456",
      nonce: "edge-revoke-nonce:2234567890123456",
      edgeId: "edge-1",
      acceptedAtMs: 200,
      expiresAtMs: 300
    });
  } finally {
    reopened.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("enabled Broker runtime fencing rejects stale writers after takeover", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-runtime-fence-"));
  const databasePath = join(directory, "broker.sqlite");
  const firstStore = new BrokerStore(databasePath, { runtimeFence: true });
  let secondStore: BrokerStore | undefined;
  try {
    firstStore.createJob({
      jobId: "job:runtime-fence",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_task_run",
      targetRef: "task_profile:tests.sleep",
      policyVersion: "policy-0.1",
      payloadDigest: "a".repeat(64),
      idempotencyKey: "runtime-fence",
      createdAtMs: 1
    });
    const lease = { ownerId: "broker:old", token: "lease:runtime-fence-1234", expiresAtMs: 30_000 };
    const started = firstStore.startJob("job:runtime-fence", "principal-1", 0, 2, lease);
    secondStore = new BrokerStore(databasePath, { runtimeFence: true });
    assert.equal(secondStore.ownedJob("job:runtime-fence", "principal-1")?.state, "unknown");
    assert.throws(
      () => firstStore.finishJob("job:runtime-fence", "principal-1", started.revision, {
        state: "completed", resultClass: "success", finishedAtMs: 3
      }, lease, 3),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT"
    );
    assert.equal(secondStore.ownedJob("job:runtime-fence", "principal-1")?.state, "unknown");
  } finally {
    secondStore?.close();
    firstStore.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore refuses an inconsistent schema migration registry", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-schema-registry-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  store.close();
  const database = new DatabaseSync(databasePath);
  database.prepare("DELETE FROM schema_migrations WHERE version = ?").run(2);
  database.close();
  try {
    assert.throws(
      () => new BrokerStore(databasePath),
      /schema migration registry is incomplete/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore rolls back a failed schema migration before startup", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-schema-rollback-"));
  const databasePath = join(directory, "broker.sqlite");
  const legacy = new DatabaseSync(databasePath);
  legacy.exec(`
    CREATE TABLE revocations (
      kind TEXT NOT NULL CHECK (kind IN ('principal', 'session', 'edge')),
      subject_id TEXT NOT NULL,
      revoked_at_ms INTEGER NOT NULL,
      reason TEXT NOT NULL,
      PRIMARY KEY (kind, subject_id)
    ) STRICT;
    CREATE TABLE revocations_v0 (marker INTEGER) STRICT;
  `);
  legacy.close();
  try {
    assert.throws(() => new BrokerStore(databasePath), /revocations_v0/u);
    const check = new DatabaseSync(databasePath);
    try {
      const table = check.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'revocations'").get() as { sql?: string } | undefined;
      assert.match(table?.sql ?? "", /'edge'\)/u);
      assert.equal((check.prepare("PRAGMA user_version").get() as { user_version: number }).user_version, 0);
      assert.equal((check.prepare("SELECT COUNT(*) AS count FROM schema_migrations").get() as { count: number }).count, 0);
    } finally {
      check.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore refuses a database from a newer schema runtime", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-schema-future-"));
  const databasePath = join(directory, "broker.sqlite");
  const database = new DatabaseSync(databasePath);
  database.exec(`PRAGMA user_version = ${BROKER_SCHEMA_VERSION + 1}`);
  database.close();
  try {
    assert.throws(
      () => new BrokerStore(databasePath),
      /schema version is newer than this runtime/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore migrates the legacy revocation constraint without losing data", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-migration-"));
  const databasePath = join(directory, "broker.sqlite");
  const legacy = new DatabaseSync(databasePath);
  legacy.exec(`
    CREATE TABLE revocations (
      kind TEXT NOT NULL CHECK (kind IN ('principal', 'session', 'edge')),
      subject_id TEXT NOT NULL,
      revoked_at_ms INTEGER NOT NULL,
      reason TEXT NOT NULL,
      PRIMARY KEY (kind, subject_id)
    ) STRICT;
    INSERT INTO revocations VALUES ('session', 'session-old', 1, 'TEST');
  `);
  legacy.close();
  const store = new BrokerStore(databasePath);
  try {
    assert.equal(store.isRevoked("session", "session-old"), true);
    store.revoke("edge_key", "edge-1:edge-key-old", "ROTATED", 2);
    assert.equal(store.isRevoked("edge_key", "edge-1:edge-key-old"), true);
    store.revoke("approval_key", "operator-1:operator-key-old", "ROTATED", 3);
    assert.equal(store.isRevoked("approval_key", "operator-1:operator-key-old"), true);
    store.revoke("policy_signer", "policy-key-old", "ROTATED", 4);
    assert.equal(store.isRevoked("policy_signer", "policy-key-old"), true);
    store.revoke("authority_key", "authority-key-old", "ROTATED", 5);
    assert.equal(store.isRevoked("authority_key", "authority-key-old"), true);
    store.revoke("helper_key", "helper-key-old", "ROTATED", 6);
    assert.equal(store.isRevoked("helper_key", "helper-key-old"), true);
    const migrated = new DatabaseSync(databasePath);
    try {
      const row = migrated.prepare("PRAGMA user_version").get() as { user_version?: unknown };
      assert.equal(row.user_version, BROKER_SCHEMA_VERSION);
    } finally {
      migrated.close();
    }
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore adds approval linkage to an existing request ledger", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-request-migration-"));
  const databasePath = join(directory, "broker.sqlite");
  const legacy = new DatabaseSync(databasePath);
  legacy.exec(`
    CREATE TABLE requests (
      request_id TEXT PRIMARY KEY,
      edge_id TEXT NOT NULL,
      principal_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      tool TEXT NOT NULL,
      policy_version TEXT NOT NULL,
      payload_digest TEXT NOT NULL,
      mutation INTEGER NOT NULL CHECK (mutation IN (0, 1)),
      state TEXT NOT NULL,
      result_class TEXT,
      target_ref TEXT,
      received_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      revision INTEGER NOT NULL
    ) STRICT;
    INSERT INTO requests VALUES (
      'request-legacy', 'edge-1', 'principal-1', 'session-1', 'mac_health',
      'policy-0.1', '${"a".repeat(64)}', 0, 'SUCCEEDED', 'SUCCEEDED',
      'host:broker', 1, 2, 3
    );
  `);
  legacy.close();
  const store = new BrokerStore(databasePath);
  try {
    assert.equal(store.requestRecord("request-legacy")?.approvalId, null);
    assert.equal(store.requestRecord("request-legacy")?.edgeKeyId, null);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore migrates version 17 Request and tombstone Edge-key columns as nullable legacy data", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-request-edge-key-migration-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  store.admitRequest({
    ...requestInput("request:pre-v18", "nonce:pre-v18", false),
    edgeKeyId: "edge-1:edge-key-1"
  });
  store.close();
  try {
    const legacy = new DatabaseSync(databasePath);
    try {
      legacy.exec("ALTER TABLE requests DROP COLUMN edge_key_id");
      legacy.exec("ALTER TABLE request_tombstones DROP COLUMN edge_key_id");
      legacy.prepare("DELETE FROM schema_migrations WHERE version >= 18").run();
      legacy.exec("PRAGMA user_version = 17");
    } finally {
      legacy.close();
    }

    const migrated = new BrokerStore(databasePath);
    try {
      assert.equal(migrated.requestRecord("request:pre-v18")?.edgeKeyId, null);
      const check = new DatabaseSync(databasePath);
      try {
        for (const table of ["requests", "request_tombstones"]) {
          const columns = check.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string; type: string; notnull: number }>;
          const edgeKeyColumn = columns.find((column) => column.name === "edge_key_id");
          assert.deepEqual(edgeKeyColumn && { type: edgeKeyColumn.type, notnull: edgeKeyColumn.notnull }, { type: "TEXT", notnull: 0 });
        }
      } finally {
        check.close();
      }
    } finally {
      migrated.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore adds the authenticated guest-result journal to a version 18 database", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-guest-result-migration-"));
  const databasePath = join(directory, "broker.sqlite");
  const initial = new BrokerStore(databasePath);
  initial.createJob(jobInput("job:pre-v19", "pre-v19"));
  initial.close();
  try {
    const legacy = new DatabaseSync(databasePath);
    try {
      legacy.exec("ALTER TABLE jobs DROP COLUMN guest_result_json");
      legacy.prepare("DELETE FROM schema_migrations WHERE version >= 19").run();
      legacy.exec("PRAGMA user_version = 18");
    } finally {
      legacy.close();
    }

    const migrated = new BrokerStore(databasePath);
    try {
      assert.equal(migrated.ownedJob("job:pre-v19", "principal-1")?.state, "cancelled");
      const database = new DatabaseSync(databasePath);
      try {
        const columns = database.prepare("PRAGMA table_info(jobs)").all() as Array<{ name: string; type: string; notnull: number }>;
        assert.deepEqual(columns.find((column) => column.name === "guest_result_json") && {
          type: columns.find((column) => column.name === "guest_result_json")?.type,
          notnull: columns.find((column) => column.name === "guest_result_json")?.notnull
        }, { type: "TEXT", notnull: 1 });
        assert.equal((database.prepare("PRAGMA user_version").get() as { user_version: number }).user_version, 20);
      } finally {
        database.close();
      }
    } finally {
      migrated.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore adds write metadata storage to an existing Job Ledger", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-job-migration-"));
  const databasePath = join(directory, "broker.sqlite");
  const legacy = new DatabaseSync(databasePath);
  legacy.exec(`
    CREATE TABLE jobs (
      job_id TEXT PRIMARY KEY,
      owner_principal_id TEXT NOT NULL,
      owner_session_id TEXT NOT NULL,
      tool TEXT NOT NULL,
      target_ref TEXT NOT NULL,
      policy_version TEXT NOT NULL,
      payload_digest TEXT NOT NULL,
      idempotency_key TEXT NOT NULL,
      state TEXT NOT NULL,
      result_class TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      started_at_ms INTEGER,
      finished_at_ms INTEGER,
      exit_code INTEGER,
      stdout_text TEXT NOT NULL,
      stderr_text TEXT NOT NULL,
      output_truncated INTEGER NOT NULL,
      cancel_requested INTEGER NOT NULL,
      cancel_reason TEXT,
      revision INTEGER NOT NULL,
      UNIQUE (owner_principal_id, idempotency_key)
    ) STRICT;
    INSERT INTO jobs VALUES (
      'job:legacy', 'principal-1', 'session-1', 'mac_task_run', 'task:test', 'policy-0.1',
      '${"a".repeat(64)}', 'legacy-job', 'completed', 'success', 1, 1, 2, 0, '', '', 0, 0, NULL, 1
    );
  `);
  legacy.close();
  const store = new BrokerStore(databasePath);
  try {
    assert.equal(store.ownedJob("job:legacy", "principal-1")?.writeMetadata, undefined);
    const migrated = new DatabaseSync(databasePath);
    try {
      const columns = migrated.prepare("PRAGMA table_info(jobs)").all() as Array<{ name: string }>;
      const names = new Set(columns.map((column) => column.name));
      for (const name of ["owner_edge_id", "owner_edge_key_id", "lease_owner_id", "lease_token", "lease_acquired_at_ms", "lease_heartbeat_at_ms", "lease_expires_at_ms", "process_metadata_json", "service_metadata_json", "privileged_payload_json"]) {
        assert.equal(names.has(name), true, `expected migrated Job column ${name}`);
      }
    } finally {
      migrated.close();
    }
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("policy signer command nonce replay remains denied after store reopen", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-policy-signer-nonce-"));
  const databasePath = join(directory, "broker.sqlite");
  let store = new BrokerStore(databasePath);
  try {
    store.admitPolicySignerCommand({
      requestId: "policy-command-1",
      nonce: "policy-command-nonce-0001",
      acceptedAtMs: 1,
      expiresAtMs: 10_000
    });
    store.close();
    store = new BrokerStore(databasePath);
    assert.throws(() => store.admitPolicySignerCommand({
      requestId: "policy-command-1",
      nonce: "policy-command-nonce-0001",
      acceptedAtMs: 2,
      expiresAtMs: 10_000
    }), /REPLAY_DENIED|already accepted/u);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore rejects a tampered audit chain on reopen", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-integrity-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  store.appendAudit({
    requestId: "request-1",
    principalId: "principal-1",
    tool: "mac_health",
    eventType: "completion",
    decision: "allow",
    resultClass: "SUCCEEDED",
    targetRef: "host:broker",
    policyVersion: "policy-0.1",
    evidence: {},
    timestampMs: 1
  });
  store.close();
  const tamper = new DatabaseSync(databasePath);
  tamper.prepare("UPDATE audit_events SET result_class = 'FORGED' WHERE sequence = 1").run();
  tamper.close();
  try {
    assert.throws(() => new BrokerStore(databasePath), /Audit evidence chain failed integrity verification/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore binds the audit tail to an owner-only keyed sidecar", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-anchor-store-"));
  const databasePath = join(directory, "broker.sqlite");
  const anchorPath = join(directory, "audit.anchor");
  const anchorOptions = {
    path: anchorPath,
    keySource: {
      keyId: "audit-key-1",
      loadKey: () => Buffer.from("audit-anchor-store-key-0123456789", "ascii")
    }
  };
  let store: BrokerStore | undefined = new BrokerStore(databasePath, { auditAnchor: anchorOptions });
  store.appendAudit({
    requestId: "anchored-request",
    principalId: "principal-1",
    tool: "mac_health",
    eventType: "completion",
    decision: "allow",
    resultClass: "SUCCEEDED",
    targetRef: "host:broker",
    policyVersion: "policy-0.1",
    evidence: { persisted: true },
    timestampMs: 1
  });
  store.close();
  store = undefined;
  try {
    const reopened = new BrokerStore(databasePath, { auditAnchor: anchorOptions });
    reopened.close();
    const anchor = JSON.parse(await readFile(anchorPath, "utf8")) as { mac: string };
    anchor.mac = "0".repeat(64);
    await writeFile(anchorPath, `${JSON.stringify(anchor)}\n`, { mode: 0o600 });
    assert.throws(
      () => new BrokerStore(databasePath, { auditAnchor: anchorOptions }),
      /Audit anchor does not match/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("audit anchor publication outage leaves the store ahead and blocks restart", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-anchor-outage-"));
  const databasePath = join(directory, "broker.sqlite");
  const anchorPath = join(directory, "audit.anchor");
  const anchorOptions = {
    path: anchorPath,
    keySource: {
      keyId: "audit-key-outage",
      loadKey: () => Buffer.from("audit-anchor-outage-key-0123456789", "ascii")
    }
  };
  let store: BrokerStore | undefined = new BrokerStore(databasePath, { auditAnchor: anchorOptions });
  const auditEvent = (requestId: string) => ({
    requestId,
    principalId: "principal-1",
    tool: "mac_health",
    eventType: "completion" as const,
    decision: "allow" as const,
    resultClass: "SUCCEEDED",
    targetRef: "host:broker",
    policyVersion: "policy-0.1",
    evidence: { outage: true },
    timestampMs: requestId === "anchor-outage-before" ? 1 : 2
  });
  try {
    store.appendAudit(auditEvent("anchor-outage-before"));
    await writeFile(`${anchorPath}.lock`, "operator-held\n", { mode: 0o600 });
    assert.throws(
      () => store!.appendAudit(auditEvent("anchor-outage-after")),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    assert.equal(store.auditRows().length, 2);
    await rm(`${anchorPath}.lock`, { force: true });
    assert.throws(
      () => store!.appendAudit(auditEvent("anchor-outage-retry")),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    assert.equal(store.auditRows().length, 2);
    store.close();
    store = undefined;
    assert.throws(
      () => new BrokerStore(databasePath, { auditAnchor: anchorOptions }),
      /Audit anchor does not match/u
    );
  } finally {
    await rm(`${anchorPath}.lock`, { force: true });
    store?.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore refuses plaintext backups and mismatched backup keys", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-backup-key-boundary-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    await assert.rejects(
      store.backupTo(directory),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    const manifest = await store.backupTo(directory, { keySource: testBackupKeySource, nowMs: 500 });
    const wrongKey = {
      keyId: "backup-other",
      loadKey: () => Buffer.from("fedcba9876543210fedcba9876543210", "ascii")
    };
    await assert.rejects(
      BrokerStore.restoreBackup(manifest.path, join(directory, "wrong-key.sqlite"), wrongKey),
      /key identity does not match/u
    );
    const wrongMaterial = {
      keyId: testBackupKeySource.keyId,
      loadKey: () => Buffer.from("fedcba9876543210fedcba9876543210", "ascii")
    };
    await assert.rejects(
      BrokerStore.restoreBackup(manifest.path, join(directory, "wrong-material.sqlite"), wrongMaterial),
      /decrypted/u
    );
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore creates an owner-only backup and restores it with integrity readback", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-backup-restore-"));
  const databasePath = join(directory, "broker.sqlite");
  let store = new BrokerStore(databasePath);
  store.appendAudit({
    requestId: "backup-request",
    principalId: "principal-1",
    tool: "mac_health",
    eventType: "completion",
    decision: "allow",
    resultClass: "SUCCEEDED",
    targetRef: "host:broker",
    policyVersion: "policy-0.1",
    evidence: { persisted: true },
    timestampMs: 1
  });
  try {
    const manifest = await store.backupTo(directory, { keySource: testBackupKeySource, nowMs: 1_700_000_000_000, retainCount: 2 });
    assert.match(manifest.path, /broker-backup-1700000000000-[a-f0-9]{24}\.sqlite\.enc$/u);
    assert.equal(manifest.encrypted, true);
    assert.equal(manifest.keyId, testBackupKeySource.keyId);
    const encryptedBytes = await readFile(manifest.path);
    assert.equal(encryptedBytes.subarray(0, 8).toString("ascii"), "MOPSBAK1");
    assert.equal(encryptedBytes.includes(Buffer.from("SQLite format 3", "ascii")), false);
    assert.equal(manifest.auditEventCount, 1);
    assert.notEqual(manifest.auditTailHash, "0".repeat(64));
    assert.equal((await lstat(manifest.path)).mode & 0o777, 0o600);
    assert.equal((await readdir(directory)).some((name) => name.includes(".tmp-")), false);

    store.close();
    const restoredPath = join(directory, "restored.sqlite");
    const restoredManifest = await BrokerStore.restoreBackup(manifest.path, restoredPath, testBackupKeySource);
    assert.equal(restoredManifest.sha256, manifest.sha256);
    assert.equal(restoredManifest.auditTailHash, manifest.auditTailHash);
    store = new BrokerStore(restoredPath);
    assert.equal(store.auditRows().length, 1);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore retention is bounded and rejects symlink backup entries", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-backup-retention-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  try {
    await store.backupTo(directory, { keySource: testBackupKeySource, nowMs: 100, retainCount: 3 });
    await store.backupTo(directory, { keySource: testBackupKeySource, nowMs: 200, retainCount: 3 });
    await store.backupTo(directory, { keySource: testBackupKeySource, nowMs: 300, retainCount: 3 });
    const pruned = await store.pruneBackups(directory, 2);
    assert.equal(pruned.removed.length, 1);
    assert.equal(pruned.retained.length, 2);

    const unsafe = join(directory, `broker-backup-999-${"a".repeat(24)}.sqlite.enc`);
    await symlink(databasePath, unsafe);
    await assert.rejects(store.pruneBackups(directory, 2), /unsafe backup entry/u);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore restore never replaces an existing destination", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-backup-restore-no-replace-"));
  const databasePath = join(directory, "broker.sqlite");
  const destinationPath = join(directory, "restored.sqlite");
  const store = new BrokerStore(databasePath);
  try {
    const manifest = await store.backupTo(directory, { keySource: testBackupKeySource, nowMs: 1_700_000_000_100 });
    await writeFile(destinationPath, "operator-placeholder", { mode: 0o600 });
    await assert.rejects(
      BrokerStore.restoreBackup(manifest.path, destinationPath, testBackupKeySource),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT"
    );
    assert.equal(await readFile(destinationPath, "utf8"), "operator-placeholder");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore retention refuses legacy plaintext backup names", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-backup-plaintext-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const legacyPath = join(directory, `broker-backup-999-${"b".repeat(24)}.sqlite`);
    await writeFile(legacyPath, "legacy", { mode: 0o600 });
    await assert.rejects(store.pruneBackups(directory, 2), /Unencrypted Broker backup entries/u);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore removes stale backup temporaries left by a hard-crashed backup process", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-backup-crash-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  let child: ReturnType<typeof spawn> | undefined;
  try {
    const backupModule = new URL("./persistence-backup.js", import.meta.url).href;
    const childScript = `
      const [directory, databasePath, backupModule] = process.argv.slice(1);
      const { createBrokerBackup } = await import(backupModule);
      const { DatabaseSync } = await import("node:sqlite");
      const database = new DatabaseSync(databasePath);
      await createBrokerBackup(database, directory, {
        keySource: { keyId: "backup-test-1", loadKey: () => Buffer.from("0123456789abcdef0123456789abcdef", "ascii") },
        faultInjector: (point) => { if (point === "after_backup") process.kill(process.pid, "SIGKILL"); }
      });
    `;
    child = spawn(process.execPath, ["--input-type=module", "-e", childScript, directory, databasePath, backupModule], {
      stdio: ["ignore", "ignore", "pipe"]
    });
    const result = await waitForChild(child);
    assert.equal(result.code, null);
    assert.equal(result.signal, "SIGKILL");
    const temporaryNames = (await readdir(directory)).filter((name) => /^\.broker-backup-.*\.sqlite\.tmp-[a-f0-9]{24}(?:-(?:wal|shm|journal))?$/u.test(name));
    assert.notEqual(temporaryNames.length, 0, "the hard-crashed process should leave a temporary artifact");
    const stale = new Date(Date.now() - 2 * 60 * 60 * 1000);
    for (const name of temporaryNames) await utimes(join(directory, name), stale, stale);
    const pruned = await store.pruneBackups(directory, 2);
    assert.equal(temporaryNames.every((name) => pruned.removed.includes(join(directory, name))), true);
    for (const name of temporaryNames) await assert.rejects(lstat(join(directory, name)), { code: "ENOENT" });
  } finally {
    if (child && child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore serializes concurrent process writers without breaking the audit chain", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-persistence-concurrency-"));
  const databasePath = join(directory, "broker.sqlite");
  const initial = new BrokerStore(databasePath);
  initial.close();
  const persistenceModule = new URL("./persistence.js", import.meta.url).href;
  const childScript = `
    const [databasePath, prefix, persistenceModule] = process.argv.slice(1);
    const { BrokerStore } = await import(persistenceModule);
    const store = new BrokerStore(databasePath);
    try {
      for (let index = 0; index < 8; index += 1) {
        store.appendAudit({
          requestId: prefix + "-" + index,
          principalId: prefix,
          tool: "mac_health",
          eventType: "completion",
          decision: "allow",
          resultClass: "SUCCEEDED",
          targetRef: "host:broker",
          policyVersion: "policy-0.1",
          evidence: { index },
          timestampMs: index + 1
        });
      }
    } finally {
      store.close();
    }
  `;
  const children = ["writer-a", "writer-b"].map((prefix) => spawn(
    process.execPath,
    ["--input-type=module", "-e", childScript, databasePath, prefix, persistenceModule],
    { stdio: ["ignore", "ignore", "pipe"] }
  ));
  try {
    const results = await Promise.all(children.map(waitForChild));
    for (const result of results) {
      assert.equal(result.code, 0, result.stderr);
      assert.equal(result.signal, null, result.stderr);
    }
    const reopened = new BrokerStore(databasePath);
    try {
      reopened.verifyAuditIntegrity();
      assert.equal(reopened.auditRows().length, 16);
    } finally {
      reopened.close();
    }
  } finally {
    for (const child of children) {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    }
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore maps a simulated ENOSPC publication failure to retryable audit unavailability", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-backup-enospc-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  try {
    await assert.rejects(
      store.backupTo(directory, {
        keySource: testBackupKeySource,
        faultInjector: (point) => {
          if (point !== "after_temp_verify") return;
          const error = Object.assign(new Error("No space left on device"), { code: "ENOSPC" });
          throw error;
        }
      }),
      (error: unknown) => {
        assert.equal(error instanceof BrokerError, true);
        assert.equal((error as BrokerError).errorClass, "AUDIT_UNAVAILABLE");
        assert.equal((error as BrokerError).retryable, true);
        return true;
      }
    );
    assert.equal((await readdir(directory)).some((name) => name.includes(".tmp-")), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore fails closed on an insufficient backup-capacity preflight", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-backup-capacity-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  try {
    await assert.rejects(
      store.backupTo(directory, { keySource: testBackupKeySource, capacityProbe: async () => 0 }),
      (error: unknown) => {
        assert.equal(error instanceof BrokerError, true);
        assert.equal((error as BrokerError).errorClass, "AUDIT_UNAVAILABLE");
        assert.equal((error as BrokerError).retryable, true);
        return true;
      }
    );
    assert.equal((await readdir(directory)).some((name) => name.includes(".tmp-")), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore restore rejects a backup whose audit chain was modified", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-backup-corruption-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  let storeOpen = true;
  store.appendAudit({
    requestId: "backup-corruption-request",
    principalId: "principal-1",
    tool: "mac_health",
    eventType: "completion",
    decision: "allow",
    resultClass: "SUCCEEDED",
    targetRef: "host:broker",
    policyVersion: "policy-0.1",
    evidence: {},
    timestampMs: 1
  });
  try {
    const manifest = await store.backupTo(directory, { keySource: testBackupKeySource, nowMs: 400, retainCount: 2 });
    store.close();
    storeOpen = false;
    const tampered = await readFile(manifest.path);
    tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 0xff;
    await writeFile(manifest.path, tampered, { mode: 0o600 });
    await assert.rejects(
      BrokerStore.restoreBackup(manifest.path, join(directory, "corrupt-restored.sqlite"), testBackupKeySource),
      /(?:decrypted|integrity)/u
    );
  } finally {
    if (storeOpen) store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("request admission atomically reserves replay identity and creates RECEIVED state", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-request-admission-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const admitted = store.admitRequest(requestInput("request-admit", "nonce-admit", false));
    assert.equal(admitted.state, "RECEIVED");
    assert.equal(admitted.revision, 0);
    assert.throws(
      () => store.admitRequest(requestInput("request-other", "nonce-admit", false)),
      /already accepted/u
    );
    assert.equal(store.requestRecord("request-other"), undefined);
    assert.throws(
      () => store.admitRequest(requestInput("request-admit", "nonce-other", false)),
      /already accepted/u
    );
    assert.equal(store.requestRecord("request-admit")?.state, "RECEIVED");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore enforces durable global and session request capacity across handles", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-request-capacity-"));
  const databasePath = join(directory, "broker.sqlite");
  const firstStore = new BrokerStore(databasePath);
  const secondStore = new BrokerStore(databasePath);
  const limits = { maxActiveRequestsGlobal: 2, maxActiveRequestsPerSession: 1 } as const;
  try {
    firstStore.admitRequest(requestInput("request-capacity-a", "nonce-capacity-a", false), limits);
    secondStore.admitRequest({
      ...requestInput("request-capacity-b", "nonce-capacity-b", false),
      principalId: "principal-2",
      sessionId: "session-2"
    }, limits);
    assert.throws(
      () => secondStore.admitRequest({
        ...requestInput("request-capacity-c", "nonce-capacity-c", false),
        principalId: "principal-2",
        sessionId: "session-2"
      }, limits),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT" && error.retryable
    );
    assert.throws(
      () => secondStore.admitRequest({
        ...requestInput("request-capacity-d", "nonce-capacity-d", false),
        principalId: "principal-3",
        sessionId: "session-3"
      }, limits),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT" && error.retryable
    );
    assert.equal(secondStore.requestRecord("request-capacity-c"), undefined);
    assert.equal(secondStore.requestRecord("request-capacity-d"), undefined);

    firstStore.failRequest({
      requestId: "request-capacity-a",
      principalId: "principal-1",
      tool: "mac_health",
      eventType: "decision",
      decision: "deny",
      resultClass: "SCOPE_DENIED",
      targetRef: "unresolved",
      policyVersion: "policy-0.1",
      evidence: {},
      timestampMs: 2
    });
    assert.equal(secondStore.admitRequest({
      ...requestInput("request-capacity-d", "nonce-capacity-d", false),
      principalId: "principal-3",
      sessionId: "session-3"
    }, limits).state, "RECEIVED");
  } finally {
    secondStore.close();
    firstStore.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore enforces independent capability-family capacity across handles", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-family-capacity-"));
  const databasePath = join(directory, "broker.sqlite");
  const firstStore = new BrokerStore(databasePath);
  const secondStore = new BrokerStore(databasePath);
  const limits = {
    maxActiveRequestsGlobal: 8,
    maxActiveRequestsPerSession: 8,
    maxActiveRequestsByFamily: { read: 1, write: 1 }
  } as const;
  try {
    firstStore.admitRequest({
      ...requestInput("request-family-read", "nonce-family-read", false),
      capabilityFamilies: ["read"]
    }, limits);
    assert.throws(
      () => secondStore.admitRequest({
        ...requestInput("request-family-read-2", "nonce-family-read-2", false),
        capabilityFamilies: ["read"]
      }, limits),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT" && error.retryable
    );
    const write = secondStore.admitRequest({
      ...requestInput("request-family-write", "nonce-family-write", true),
      capabilityFamilies: ["write"]
    }, limits);
    assert.equal(write.state, "RECEIVED");
    assert.equal(secondStore.requestRecord("request-family-read-2"), undefined);
    assert.deepEqual(secondStore.requestRecord("request-family-read")?.capabilityFamilies, ["read"]);

    firstStore.failRequest({
      requestId: "request-family-read",
      principalId: "principal-1",
      tool: "mac_health",
      eventType: "decision",
      decision: "deny",
      resultClass: "SCOPE_DENIED",
      targetRef: "unresolved",
      policyVersion: "policy-0.1",
      evidence: {},
      timestampMs: 2
    });
    const released = secondStore.admitRequest({
      ...requestInput("request-family-read-3", "nonce-family-read-3", false),
      capabilityFamilies: ["read"]
    }, limits);
    assert.equal(released.state, "RECEIVED");
  } finally {
    secondStore.close();
    firstStore.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore rejects inherited or accessor admission limits before reading them", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-admission-limit-shape-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const inherited = Object.create({ maxActiveRequestsGlobal: 1 }) as Record<string, unknown>;
    assert.throws(
      () => store.admitRequest(requestInput("request-limit-inherited", "nonce-limit-inherited", false), inherited),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
    );

    const accessor = {} as Record<string, unknown>;
    Object.defineProperty(accessor, "maxActiveRequestsByFamily", {
      enumerable: true,
      get: () => ({ read: 1 })
    });
    assert.throws(
      () => store.admitRequest(requestInput("request-limit-accessor", "nonce-limit-accessor", false), accessor),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
    );
    assert.equal(store.requestRecord("request-limit-inherited"), undefined);
    assert.equal(store.requestRecord("request-limit-accessor"), undefined);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore fails closed when a persisted capability-family marker is malformed", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-family-corruption-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  const limits = { maxActiveRequestsByFamily: { read: 2 } } as const;
  try {
    store.admitRequest({
      ...requestInput("request-family-corrupt", "nonce-family-corrupt", false),
      capabilityFamilies: ["read"]
    }, limits);
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare("UPDATE requests SET capability_families = ? WHERE request_id = ?")
        .run("|unsupported|", "request-family-corrupt");
    } finally {
      database.close();
    }
    assert.throws(
      () => store.requestRecord("request-family-corrupt"),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    assert.throws(
      () => store.admitRequest({
        ...requestInput("request-family-corrupt-2", "nonce-family-corrupt-2", false),
        capabilityFamilies: ["read"]
      }, limits),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    assert.equal(store.requestRecord("request-family-corrupt-2"), undefined);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore validates persisted capability-family markers for family-less admissions", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-family-less-corruption-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  try {
    store.admitRequest({
      ...requestInput("request-family-less-corrupt", "nonce-family-less-corrupt", false),
      capabilityFamilies: ["read"]
    }, { maxActiveRequestsByFamily: { read: 4 } });
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare("UPDATE requests SET capability_families = ? WHERE request_id = ?")
        .run("|unsupported|", "request-family-less-corrupt");
    } finally {
      database.close();
    }
    assert.throws(
      () => store.admitRequest(requestInput("request-family-less-corrupt-2", "nonce-family-less-corrupt-2", false), {
        maxActiveRequestsByFamily: { read: 4 }
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    assert.equal(store.requestRecord("request-family-less-corrupt-2"), undefined);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mutation request lifecycle keeps decision, intent, running, and completion ordered", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-request-lifecycle-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    store.admitRequest(requestInput("request-lifecycle", "nonce-lifecycle", true));
    const authorized = store.recordRequestDecision(requestEvent("request-lifecycle", "decision", "AUTHORIZED", 2));
    assert.equal(authorized.state, "AUTHORIZED");
    store.issueApproval(approvalInput("approval:lifecycle"));
    const intent = store.recordRequestIntent(
      requestEvent("request-lifecycle", "intent", "INTENT_RECORDED", 3),
      approvalBinding()
    );
    assert.equal(intent.state, "INTENT_RECORDED");
    assert.equal(intent.approvalId, "approval:lifecycle");
    assert.equal(store.approvalRecord("approval:lifecycle")?.usedCount, 1);
    const running = store.markRequestRunning("request-lifecycle", 4);
    assert.equal(running.state, "RUNNING");
    assert.throws(
      () => store.completeRequest(requestEvent("request-lifecycle", "completion", "FAILED", 5)),
      /malformed/u
    );
    const completed = store.completeRequest(requestEvent("request-lifecycle", "completion", "SUCCEEDED", 5));
    assert.equal(completed.state, "SUCCEEDED");
    assert.equal(completed.revision, 4);
    assert.deepEqual(store.auditRows().filter((row) => row.request_id === "request-lifecycle")
      .map((row) => [row.event_type, row.result_class]), [
      ["decision", "AUTHORIZED"],
      ["intent", "INTENT_RECORDED"],
      ["completion", "SUCCEEDED"]
    ]);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("request denial before authorization is terminal and audited once", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-request-denial-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    store.admitRequest(requestInput("request-denied", "nonce-denied", false));
    const denied = store.failRequest({
      ...requestEvent("request-denied", "decision", "SCOPE_DENIED", 2),
      tool: "mac_health",
      decision: "deny"
    });
    assert.equal(denied.state, "DENIED");
    assert.equal(store.failRequest({
      ...requestEvent("request-denied", "decision", "SCOPE_DENIED", 3),
      tool: "mac_health",
      decision: "deny"
    }).revision, denied.revision);
    assert.deepEqual(store.auditRows().map((row) => [row.event_type, row.decision, row.result_class]), [
      ["decision", "deny", "SCOPE_DENIED"]
    ]);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("restart reconciliation never reports interrupted requests as successful", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-request-reconcile-"));
  const databasePath = join(directory, "broker.sqlite");
  let store = new BrokerStore(databasePath);
  store.admitRequest(requestInput("request-received", "nonce-received", false));
  store.admitRequest(requestInput("request-read", "nonce-read", false));
  store.recordRequestDecision({
    ...requestEvent("request-read", "decision", "AUTHORIZED", 2),
    tool: "mac_health",
    targetRef: "host:broker"
  });
  store.markRequestRunning("request-read", 3);
  store.admitRequest(requestInput("request-intent", "nonce-intent", true));
  store.recordRequestDecision(requestEvent("request-intent", "decision", "AUTHORIZED", 2));
  store.issueApproval(approvalInput("approval:intent"));
  store.recordRequestIntent(
    requestEvent("request-intent", "intent", "INTENT_RECORDED", 3),
    approvalBinding()
  );
  store.admitRequest(requestInput("request-mutation", "nonce-mutation", true));
  store.recordRequestDecision(requestEvent("request-mutation", "decision", "AUTHORIZED", 2));
  store.issueApproval(approvalInput("approval:mutation"));
  store.recordRequestIntent(
    requestEvent("request-mutation", "intent", "INTENT_RECORDED", 3),
    approvalBinding()
  );
  store.markRequestRunning("request-mutation", 4);
  store.close();

  store = new BrokerStore(databasePath);
  try {
    assert.equal(store.requestRecord("request-received")?.state, "FAILED");
    assert.equal(store.requestRecord("request-read")?.state, "FAILED");
    assert.equal(store.requestRecord("request-intent")?.state, "FAILED");
    assert.equal(store.requestRecord("request-mutation")?.state, "UNKNOWN");
    assert.equal(store.auditRows().filter((row) => row.tool === "internal_request_reconcile")
      .some((row) => row.result_class === "SUCCEEDED"), false);
    assert.deepEqual(
      store.auditRows().filter((row) => row.tool === "internal_request_reconcile")
        .map((row) => [row.request_id, row.result_class]),
      [
        ["request-intent", "EXECUTION_FAILED"],
        ["request-mutation", "UNKNOWN_OUTCOME"],
        ["request-read", "EXECUTION_FAILED"],
        ["request-received", "EXECUTION_FAILED"]
      ]
    );
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("approval consumption rejects every bound-field substitution and single-use replay", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-approval-binding-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    assert.throws(
      () => store.issueApproval({ ...approvalInput("approval:batch"), useLimit: 2 }),
      /malformed/u
    );
    store.issueApproval({ ...approvalInput("approval:principal"), requestingPrincipalId: "principal-2" });
    store.issueApproval({ ...approvalInput("approval:contract"), contractVersion: "0.2" });
    store.issueApproval({ ...approvalInput("approval:target"), targetRef: "job:other" });
    store.issueApproval({ ...approvalInput("approval:payload"), payloadDigest: "e".repeat(64) });
    store.issueApproval({ ...approvalInput("approval:policy"), policyVersion: "policy-0.2" });
    store.issueApproval({ ...approvalInput("approval:expired"), expiresAtMs: 3 });
    store.issueApproval({ ...approvalInput("approval:unattended"), unattended: true });
    store.issueApproval(approvalInput("approval:revoked"));
    store.revokeApproval("approval:revoked", "OPERATOR_REVOKED", 2);

    authorizeMutationRequest(store, "request-binding", "nonce-binding");
    assert.throws(
      () => store.recordRequestIntent(
        requestEvent("request-binding", "intent", "INTENT_RECORDED", 3),
        approvalBinding()
      ),
      /No valid approval/u
    );
    assert.equal(store.requestRecord("request-binding")?.state, "AUTHORIZED");
    assert.equal(store.approvalRecord("approval:revoked")?.usedCount, 0);

    store.issueApproval(approvalInput("approval:exact"));
    store.recordRequestIntent(
      requestEvent("request-binding", "intent", "INTENT_RECORDED", 3),
      approvalBinding()
    );
    assert.equal(store.approvalRecord("approval:exact")?.usedCount, 1);

    authorizeMutationRequest(store, "request-replay", "nonce-replay");
    assert.throws(
      () => store.recordRequestIntent(
        requestEvent("request-replay", "intent", "INTENT_RECORDED", 4),
        approvalBinding()
      ),
      /No valid approval/u
    );
    assert.equal(store.requestRecord("request-replay")?.state, "AUTHORIZED");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

for (const mode of ["same-request", "fresh-request", "legacy-issued"] as const) {
test(`approval preview survives restart after ${mode} consumption`, async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-approval-preview-"));
  const databasePath = join(directory, "broker.sqlite");
  let store = new BrokerStore(databasePath);
  try {
    authorizeMutationRequest(store, "request-preview", "nonce-preview");
    assert.throws(
      () => store.recordRequestIntent(
        requestEvent("request-preview", "intent", "INTENT_RECORDED", 3),
        approvalBinding()
      ),
      /No valid approval/u
    );
    const preview = store.createApprovalPreview("request-preview", approvalBinding(), 3);
    assert.deepEqual(preview, {
      requestId: "request-preview",
      requestingPrincipalId: "principal-1",
      tool: "mac_job_cancel",
      contractVersion: "0.1",
      targetKind: "job",
      targetRef: "job:owned",
      payloadDigest: "d".repeat(64),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_write",
      unattended: false,
      status: "pending",
      approvalId: null,
      createdAtMs: 3,
      expiresAtMs: 120_003,
      revision: 0
    });
    assert.equal(store.approvalPreview("request-preview", 120_002)?.requestId, "request-preview");
    assert.equal(store.approvalPreview("request-preview", 120_003), undefined);

    store.issueApproval({
      approvalId: "approval:preview",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_job_cancel",
      contractVersion: "0.1",
      targetKind: "job",
      targetRef: "job:owned",
      payloadDigest: "d".repeat(64),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_write",
      unattended: false,
      issuedAtMs: 4,
      expiresAtMs: 120_002
    });
    assert.equal(store.markApprovalPreviewIssued("request-preview", "approval:preview", 4).status, "issued");
    assert.equal(store.approvalPreview("request-preview", 4), undefined);
    const executionRequestId = mode === "same-request" ? "request-preview" : "request-execution";
    if (executionRequestId !== "request-preview") authorizeMutationRequest(store, executionRequestId, "nonce-execution");
    store.recordRequestIntent(
      requestEvent(executionRequestId, "intent", "INTENT_RECORDED", 5),
      approvalBinding()
    );
    const lifecycleDatabase = new DatabaseSync(databasePath);
    try {
      const lifecycle = lifecycleDatabase.prepare(
        "SELECT status, approval_id FROM approval_previews WHERE request_id = ?"
      ).get("request-preview") as { status?: unknown; approval_id?: unknown };
      assert.equal(lifecycle.status, "consumed");
      assert.equal(lifecycle.approval_id, "approval:preview");
      if (mode === "legacy-issued") lifecycleDatabase.prepare("UPDATE approval_previews SET status = 'issued' WHERE request_id = ?").run("request-preview");
    } finally {
      lifecycleDatabase.close();
    }

    store.close();
    store = new BrokerStore(databasePath);
    assert.equal(store.approvalPreview("request-preview", 4), undefined);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
}

test("competing request admissions cannot consume one approval twice", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-approval-race-"));
  const databasePath = join(directory, "broker.sqlite");
  const firstStore = new BrokerStore(databasePath);
  const secondStore = new BrokerStore(databasePath);
  try {
    firstStore.issueApproval(approvalInput("approval:race"));
    authorizeMutationRequest(firstStore, "request-race-a", "nonce-race-a");
    authorizeMutationRequest(secondStore, "request-race-b", "nonce-race-b");
    const attempt = (store: BrokerStore, requestId: string) => new Promise<boolean>((resolve) => {
      setImmediate(() => {
        try {
          store.recordRequestIntent(requestEvent(requestId, "intent", "INTENT_RECORDED", 3), approvalBinding());
          resolve(true);
        } catch {
          resolve(false);
        }
      });
    });
    const outcomes = await Promise.all([
      attempt(firstStore, "request-race-a"),
      attempt(secondStore, "request-race-b")
    ]);
    assert.equal(outcomes.filter(Boolean).length, 1);
    assert.equal(firstStore.approvalRecord("approval:race")?.usedCount, 1);
    assert.equal([
      firstStore.requestRecord("request-race-a")?.state,
      firstStore.requestRecord("request-race-b")?.state
    ].filter((state) => state === "INTENT_RECORDED").length, 1);
  } finally {
    secondStore.close();
    firstStore.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("approval revocation after intent prevents mutation dispatch", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-approval-revoke-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    store.issueApproval(approvalInput("approval:pre-dispatch"));
    authorizeMutationRequest(store, "request-pre-dispatch", "nonce-pre-dispatch");
    store.recordRequestIntent(
      requestEvent("request-pre-dispatch", "intent", "INTENT_RECORDED", 3),
      approvalBinding()
    );
    store.revokeApproval("approval:pre-dispatch", "OPERATOR_REVOKED", 4);
    assert.throws(() => store.markRequestRunning("request-pre-dispatch", 5), /not active/u);
    assert.equal(store.requestRecord("request-pre-dispatch")?.state, "INTENT_RECORDED");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("atomic approved job admission links request, approval, intent, and idempotency", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-atomic-job-admission-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    store.issueApproval({
      approvalId: "approval:atomic",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_task_run",
      contractVersion: "0.1",
      targetKind: "task_profile",
      targetRef: "task_profile:test",
      payloadDigest: "b".repeat(64),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_profile",
      unattended: false,
      issuedAtMs: 1,
      expiresAtMs: 100
    });
    const first = atomicJobAdmissionInput("request-atomic", "nonce-atomic", "job:atomic", "task:test", "task_profile:test");
    const admitted = store.admitApprovedJob(first);
    assert.equal(admitted.reused, false);
    assert.equal(admitted.request.state, "INTENT_RECORDED");
    assert.equal(admitted.request.jobId, "job:atomic");
    assert.equal(admitted.request.approvalId, "approval:atomic");
    assert.equal(admitted.request.edgeKeyId, "edge-1:edge-key-1");
    assert.equal(admitted.job.state, "queued");
    const mismatchedKey = atomicJobAdmissionInput(
      "request-atomic-key-mismatch", "nonce-atomic-key-mismatch", "job:atomic-key-mismatch",
      "task:test", "task_profile:test"
    );
    mismatchedKey.job.edgeKeyId = "edge-1:edge-key-other";
    assert.throws(() => store.admitApprovedJob(mismatchedKey));
    assert.equal(store.requestRecord("request-atomic-key-mismatch"), undefined);
    assert.equal(store.approvalRecord("approval:atomic")?.usedCount, 1);
    assert.throws(
      () => store.admitApprovedJob({
        ...atomicJobAdmissionInput("request-atomic-replay", "nonce-atomic", "job:ignored", "task:test", "task_profile:test"),
        approval: first.approval
      }),
      /identity was already accepted/u
    );

    assert.throws(
      () => store.admitApprovedJob({
        ...atomicJobAdmissionInput("request-atomic-retry", "nonce-atomic-retry", "job:ignored", "task:test", "task_profile:test"),
        approval: first.approval
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT"
    );
    assert.equal(store.requestRecord("request-atomic-retry"), undefined);
    const started = store.startJob("job:atomic", "principal-1", admitted.job.revision, 4);
    store.finishJob("job:atomic", "principal-1", started.revision, {
      state: "completed", resultClass: "success", finishedAtMs: 5
    });
    const crossSessionRetry = atomicJobAdmissionInput(
      "request-atomic-cross-session",
      "nonce-atomic-cross-session",
      "job:ignored-cross-session",
      "task:test",
      "task_profile:test"
    );
    crossSessionRetry.request.sessionId = "session-2";
    crossSessionRetry.job.ownerSessionId = "session-2";
    assert.throws(
      () => store.admitApprovedJob({ ...crossSessionRetry, approval: first.approval }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT"
    );
    assert.equal(store.requestRecord("request-atomic-cross-session"), undefined);
    const retry = store.admitApprovedJob({
      ...atomicJobAdmissionInput("request-atomic-retry", "nonce-atomic-retry-2", "job:ignored", "task:test", "task_profile:test"),
      approval: first.approval
    });
    assert.equal(retry.reused, true);
    assert.equal(retry.request.state, "SUCCEEDED");
    assert.equal(retry.request.resultClass, "IDEMPOTENT_REUSE");
    assert.equal(retry.job.jobId, "job:atomic");
    assert.equal(store.approvalRecord("approval:atomic")?.usedCount, 1);

    const conflict = atomicJobAdmissionInput("request-atomic-conflict", "nonce-atomic-conflict", "job:conflict", "task:other", "task_profile:other");
    store.issueApproval({
      ...approvalInput("approval:atomic-conflict"),
      tool: "mac_task_run",
      targetKind: "task_profile",
      targetRef: "task_profile:other",
      payloadDigest: "b".repeat(64),
      approvalClass: "trusted_profile"
    });
    const differsInTarget = conflictMatching(/^IDEMPOTENCY_KEY_IN_USE: .*job:atomic \(mac_task_run, completed, created .*\), but the new request differs in target\. Use a new idempotency_key\.$/u);
    assert.throws(() => store.admitApprovedJob({ ...conflict, approval: { ...conflict.approval, approvalClass: "trusted_profile" } }), differsInTarget);
    assert.equal(store.requestRecord("request-atomic-conflict"), undefined);
    assert.equal(store.ownedJob("job:conflict", "principal-1"), undefined);
    assert.equal(store.approvalRecord("approval:atomic-conflict")?.usedCount, 0);
    assert.throws(() => store.admitApprovedJob(conflict), differsInTarget);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

/** Admit a task Request with its Job, then finish the Job as `failed` while the Request stays in INTENT_RECORDED. */
function admitFailedTaskJob(store: BrokerStore, name: string): { requestId: string; jobId: string } {
  store.issueApproval({
    approvalId: `approval:outcome-${name}`, approverPrincipalId: "operator-1", requestingPrincipalId: "principal-1",
    tool: "mac_task_run", contractVersion: "0.1", targetKind: "task_profile", targetRef: "task_profile:test",
    payloadDigest: "b".repeat(64), policyVersion: "policy-0.1", approvalClass: "trusted_profile", unattended: false,
    issuedAtMs: 1, expiresAtMs: 100
  });
  const input = atomicJobAdmissionInput(`request-outcome-${name}`, `nonce-outcome-${name}`, `job:outcome-${name}`, "task:test", "task_profile:test");
  store.admitApprovedJob({ ...input, job: { ...input.job, idempotencyKey: `outcome-${name}` } });
  store.startJob(input.job.jobId, "principal-1", 0, 4);
  store.finishJob(input.job.jobId, "principal-1", 1, { state: "failed", resultClass: "failed", finishedAtMs: 5, exitCode: 1 });
  return { requestId: input.request.requestId, jobId: input.job.jobId };
}

function failTaskRequest(store: BrokerStore, requestId: string, resultClass: string): void {
  store.markRequestRunning(requestId, 6);
  store.failRequest({ ...requestEvent(requestId, "completion", resultClass, 7), tool: "mac_task_run", targetRef: "task_profile:test" });
}

test("ownedJobOutcomeClass reports only the failure class recorded by the failed Job's own Request", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-job-outcome-class-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    for (const [name, resultClass] of [
      ["timeout", "TIMEOUT"], ["output", "OUTPUT_LIMIT"], ["verification", "VERIFICATION_FAILED"], ["execution", "EXECUTION_FAILED"]
    ] as const) {
      const { requestId, jobId } = admitFailedTaskJob(store, name);
      failTaskRequest(store, requestId, resultClass);
      assert.equal(store.ownedJobOutcomeClass(jobId, "principal-1"), resultClass);
      assert.equal(store.ownedJobOutcomeClass(jobId, "principal-2"), undefined);
    }

    // The Job commits before its Request completion row, so a Request that has not completed yet yields nothing.
    const pending = admitFailedTaskJob(store, "pending");
    assert.equal(store.requestRecord(pending.requestId)?.state, "INTENT_RECORDED");
    assert.equal(store.ownedJobOutcomeClass(pending.jobId, "principal-1"), undefined);
    store.markRequestRunning(pending.requestId, 6);
    assert.equal(store.requestRecord(pending.requestId)?.state, "RUNNING");
    assert.equal(store.ownedJobOutcomeClass(pending.jobId, "principal-1"), undefined);

    // A Request reconciled after a restart to UNKNOWN_OUTCOME is not a failure class.
    assert.deepEqual(store.reconcileInterruptedRequests(8), { failed: 0, unknown: 1 });
    assert.equal(store.requestRecord(pending.requestId)?.resultClass, "UNKNOWN_OUTCOME");
    assert.equal(store.ownedJobOutcomeClass(pending.jobId, "principal-1"), undefined);

    assert.equal(store.ownedJobOutcomeClass("job:outcome-missing", "principal-1"), undefined);
    for (const [jobId, principalId] of [
      ["outcome-timeout", "principal-1"], ["job:", "principal-1"], ["job:outcome timeout", "principal-1"],
      ["job:outcome-timeout", ""], ["job:outcome-timeout", "principal 1"], ["job:outcome-timeout", "p".repeat(129)]
    ]) {
      assert.throws(() => store.ownedJobOutcomeClass(jobId!, principalId!), /Job record is malformed/u, `${jobId} ${principalId}`);
    }
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("ownedJobOutcomeClass still finds the class in the request tombstone after ledger rotation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-job-outcome-tombstone-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath, { runtimeFence: true });
  try {
    const { requestId, jobId } = admitFailedTaskJob(store, "tombstone");
    failTaskRequest(store, requestId, "TIMEOUT");
    await store.rotateLedgerArchive(directory, { keySource: testBackupKeySource, nowMs: 100_000, retainRequestCount: 0, retainJobCount: 0, minAgeMs: 1_000 });
    assert.equal(store.requestRecord(requestId), undefined);
    assert.equal(store.ownedJob(jobId, "principal-1"), undefined);
    assert.equal(store.ownedJobStatus(jobId, "principal-1").archived?.state, "failed");
    assert.equal(store.ownedJobOutcomeClass(jobId, "principal-1"), "TIMEOUT");
    assert.equal(store.ownedJobOutcomeClass(jobId, "principal-2"), undefined);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("atomic approved job admission rolls back every injected failure point", async () => {
  const faultPoints = [
    "admit_approved_job.after_request",
    "admit_approved_job.after_authorization",
    "admit_approved_job.after_approval",
    "admit_approved_job.after_job"
  ] as const;

  for (const [index, faultPoint] of faultPoints.entries()) {
    const directory = await mkdtemp(join(tmpdir(), `mac-operator-atomic-fault-${index}-`));
    const databasePath = join(directory, "broker.sqlite");
    let store = new BrokerStore(databasePath, {
      faultInjector: (actualPoint) => {
        if (actualPoint === faultPoint) throw new Error(`fault injection: ${actualPoint}`);
      }
    });
    try {
      const approvalId = `approval:fault-${index}`;
      const input = atomicJobAdmissionInput(
        `request-fault-${index}`,
        `nonce-fault-${index}`,
        `job:fault-${index}`,
        "task:test",
        "task_profile:test"
      );
      store.issueApproval({
        approvalId,
        approverPrincipalId: "operator-1",
        requestingPrincipalId: "principal-1",
        tool: "mac_task_run",
        contractVersion: "0.1",
        targetKind: "task_profile",
        targetRef: "task_profile:test",
        payloadDigest: "b".repeat(64),
        policyVersion: "policy-0.1",
        approvalClass: "trusted_profile",
        unattended: false,
        issuedAtMs: 1,
        expiresAtMs: 100
      });

      assert.throws(
        () => store.admitApprovedJob(input),
        /Atomic job admission could not be persisted/u
      );
      store.close();
      store = new BrokerStore(databasePath);
      assert.equal(store.requestRecord(input.request.requestId), undefined);
      assert.equal(store.ownedJob(input.job.jobId, input.job.ownerPrincipalId), undefined);
      assert.equal(store.approvalRecord(approvalId)?.usedCount, 0);
      assert.equal(store.auditRows().some((row) => row.request_id === input.request.requestId), false);

      const recovered = store.admitApprovedJob(input);
      assert.equal(recovered.reused, false);
      assert.equal(recovered.request.state, "INTENT_RECORDED");
      assert.equal(recovered.job.state, "queued");
      assert.equal(store.approvalRecord(approvalId)?.usedCount, 1);
    } finally {
      store.close();
      await rm(directory, { recursive: true, force: true });
    }
  }
});

test("approved Job after-decision admission rejects a mismatched Request Edge key", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-approved-edge-key-mismatch-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const input = atomicJobAdmissionInput(
      "request-approved-edge-key-mismatch", "nonce-approved-edge-key-mismatch",
      "job:approved-edge-key-mismatch", "task_profile:test", "task_profile:test"
    );
    store.issueApproval({
      approvalId: "approval:approved-edge-key-mismatch",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_task_run",
      contractVersion: "0.1",
      targetKind: "task_profile",
      targetRef: "task_profile:test",
      payloadDigest: "b".repeat(64),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_profile",
      unattended: false,
      issuedAtMs: 1,
      expiresAtMs: 100
    });
    store.admitRequest(input.request);
    store.recordRequestDecision(input.decision);
    input.job.edgeKeyId = "edge-1:edge-key-other";
    assert.throws(
      () => store.admitApprovedJobAfterDecision({ intent: input.intent, approval: input.approval, job: input.job }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT"
    );
    assert.equal(store.requestRecord(input.request.requestId)?.state, "AUTHORIZED");
    assert.equal(store.ownedJob(input.job.jobId, input.job.ownerPrincipalId), undefined);
    assert.equal(store.approvalRecord("approval:approved-edge-key-mismatch")?.usedCount, 0);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("approved task admission after authorization rolls back approval, intent, and Job together", async () => {
  const faultPoints = [
    "admit_approved_job_after_decision.after_approval",
    "admit_approved_job_after_decision.after_job"
  ] as const;

  for (const [index, faultPoint] of faultPoints.entries()) {
    const directory = await mkdtemp(join(tmpdir(), `mac-operator-approved-task-fault-${index}-`));
    const databasePath = join(directory, "broker.sqlite");
    let store = new BrokerStore(databasePath, {
      faultInjector: (actualPoint) => {
        if (actualPoint === faultPoint) throw new Error(`fault injection: ${actualPoint}`);
      }
    });
    try {
      const input = atomicJobAdmissionInput(
        `request-approved-fault-${index}`,
        `nonce-approved-fault-${index}`,
        `job:approved-fault-${index}`,
        "task_profile:test",
        "task_profile:test"
      );
      store.issueApproval({
        approvalId: `approval:approved-fault-${index}`,
        approverPrincipalId: "operator-1",
        requestingPrincipalId: "principal-1",
        tool: "mac_task_run",
        contractVersion: "0.1",
        targetKind: "task_profile",
        targetRef: "task_profile:test",
        payloadDigest: "b".repeat(64),
        policyVersion: "policy-0.1",
        approvalClass: "trusted_profile",
        unattended: false,
        issuedAtMs: 1,
        expiresAtMs: 100
      });
      store.admitRequest(input.request);
      store.recordRequestDecision(input.decision);

      assert.throws(
        () => store.admitApprovedJobAfterDecision({ intent: input.intent, approval: input.approval, job: input.job }),
        /could not be persisted/u
      );
      assert.equal(store.requestRecord(input.request.requestId)?.state, "AUTHORIZED");
      assert.equal(store.requestRecord(input.request.requestId)?.jobId, null);
      assert.equal(store.ownedJob(input.job.jobId, input.job.ownerPrincipalId), undefined);
      assert.equal(store.approvalRecord(`approval:approved-fault-${index}`)?.usedCount, 0);
      assert.deepEqual(store.auditRows().filter((row) => row.request_id === input.request.requestId).map((row) => row.event_type), ["decision"]);

      store.close();
      store = new BrokerStore(databasePath);
      const recovered = store.requestRecord(input.request.requestId);
      assert.equal(recovered?.state, "FAILED");
      assert.equal(recovered?.resultClass, "EXECUTION_FAILED");
      assert.equal(recovered?.jobId, null);
      assert.equal(store.ownedJob(input.job.jobId, input.job.ownerPrincipalId), undefined);
      assert.equal(store.approvalRecord(`approval:approved-fault-${index}`)?.usedCount, 0);
    } finally {
      store.close();
      await rm(directory, { recursive: true, force: true });
    }
  }
});

test("job creation is principal-scoped and payload-bound idempotent", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-job-idempotency-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const first = store.createJob({ ...jobInput("job:first", "idem-1"), edgeId: "edge-1" });
    assert.equal(first.reused, false);
    assert.equal(first.job.state, "queued");
    assert.throws(
      () => store.createJob({ ...jobInput("job:ignored", "idem-1") }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT"
    );
    const started = store.startJob("job:first", "principal-1", first.job.revision, 2);
    store.finishJob("job:first", "principal-1", started.revision, {
      state: "completed", resultClass: "success", finishedAtMs: 3
    });
    const repeated = store.createJob({ ...jobInput("job:ignored", "idem-1"), edgeId: "edge-1" });
    assert.equal(repeated.reused, true);
    assert.equal(repeated.job.jobId, "job:first");
    assert.throws(
      () => store.createJob({ ...jobInput("job:cross-session", "idem-1"), edgeId: "edge-1", ownerSessionId: "session-2" }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT"
    );
    assert.equal(store.ownedJob("job:cross-session", "principal-1"), undefined);
    assert.throws(
      () => store.createJob({ ...jobInput("job:different", "idem-1"), payloadDigest: "b".repeat(64) }),
      conflictMatching(/^IDEMPOTENCY_KEY_IN_USE: .*job:first \(mac_task_run, completed, .*differs in arguments\./u)
    );
    assert.throws(
      () => store.createJob({ ...jobInput("job:policy-different", "idem-1"), policyVersion: "policy-0.2" }),
      conflictMatching(/^IDEMPOTENCY_KEY_IN_USE: .*job:first \(mac_task_run, completed, .*differs in policy version\./u)
    );
    const otherPrincipal = store.createJob({
      ...jobInput("job:other", "idem-1"),
      edgeId: "edge-1",
      ownerPrincipalId: "principal-2"
    });
    assert.equal(otherPrincipal.reused, false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("a held idempotency key names the holder Job and the first differing binding without leaking identifiers", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-idempotency-binding-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const holder = { ...jobInput("job:holder", "idem-binding"), edgeId: "edge-1", edgeKeyId: "edge-1:edge-key-1" };
    store.createJob(holder);
    const cases: Array<[Partial<CreateJobInput>, string]> = [
      [{ tool: "mac_test_run" }, "tool"],
      [{ payloadDigest: "c".repeat(64) }, "arguments"],
      [{ targetRef: "task:other" }, "target"],
      [{ policyVersion: "policy-0.2" }, "policy version"],
      [{ ownerSessionId: "session-2" }, "OAuth login"],
      [{ edgeKeyId: "edge-1:edge-key-2" }, "Edge connection"],
      [{ edgeId: "edge-2", edgeKeyId: "edge-2:edge-key-1" }, "Edge connection"],
      // The first differing binding wins, in the order tool, arguments, target, policy version, login, Edge.
      [{ tool: "mac_build_run", payloadDigest: "c".repeat(64), ownerSessionId: "session-2" }, "tool"],
      [{ targetRef: "task:other", ownerSessionId: "session-2" }, "target"]
    ];
    for (const [change, label] of cases) {
      const message = conflictMessage(() => store.createJob({ ...holder, jobId: "job:attempt", ...change }));
      assert.ok(message.startsWith("IDEMPOTENCY_KEY_IN_USE: this idempotency_key already belongs to job job:holder (mac_task_run, queued, created 1970-01-01T00:00:00.001Z), "), message);
      assert.ok(message.includes(`, but the new request differs in ${label}. `), message);
      assert.ok(message.endsWith(label === "OAuth login"
        ? "Repeat the identical request from the original OAuth login, or use a new idempotency_key."
        : "Use a new idempotency_key."), message);
      assert.ok(message.length < 512, `${message.length}`);
      for (const hidden of ["a".repeat(64), "c".repeat(64), "session-1", "session-2", "edge-1", "edge-2", "edge-key", "idem-binding", "task:test", "task:other"]) {
        assert.ok(!message.includes(hidden), `${hidden}: ${message}`);
      }
    }
    assert.equal(store.ownedJob("job:attempt", "principal-1"), undefined);

    // An identical request meets a Job that has not finished: the Job is named so its state can be read.
    const active = conflictMessage(() => store.createJob({ ...holder, jobId: "job:attempt" }));
    assert.ok(active.includes("job:holder (mac_task_run, queued, "), active);
    assert.ok(active.endsWith("It has not finished: check it with mac_job_status, then repeat the identical request to replay its outcome."), active);

    // A finished Job is replayed, never re-run: a repeat from another login is told to use the original login or a new key.
    const started = store.startJob("job:holder", "principal-1", 0, 2);
    store.finishJob("job:holder", "principal-1", started.revision, { state: "failed", resultClass: "failed", finishedAtMs: 3, exitCode: 1 });
    assert.equal(store.createJob({ ...holder, jobId: "job:attempt" }).reused, true);
    const failedLogin = conflictMessage(() => store.createJob({ ...holder, jobId: "job:attempt", ownerSessionId: "session-2" }));
    assert.ok(failedLogin.endsWith("Repeat the identical request from the original OAuth login (the failed job is never re-run, only replayed as failed), or use a new idempotency_key."), failedLogin);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("an atomic admission that meets a Job without a successful outcome names it and says it is never re-run", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-idempotency-failed-holder-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const failed = admitFailedTaskJob(store, "replay");
    const retry = atomicJobAdmissionInput("request-replay-retry", "nonce-replay-retry", "job:ignored-replay", "task:test", "task_profile:test");
    const message = conflictMessage(() => store.admitApprovedJob({ ...retry, job: { ...retry.job, idempotencyKey: "outcome-replay" } }));
    assert.ok(message.startsWith(`IDEMPOTENCY_KEY_IN_USE: this idempotency_key already belongs to job ${failed.jobId} (mac_task_run, failed, created `), message);
    assert.ok(message.endsWith("A failed or cancelled job is never re-run under its key: use a new idempotency_key to run the request again."), message);
    assert.equal(store.requestRecord("request-replay-retry"), undefined);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("an archived Job holding a key is named only to its own principal", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-idempotency-tombstone-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"), { runtimeFence: true });
  try {
    const { requestId, jobId } = admitFailedTaskJob(store, "tombstone-own");
    failTaskRequest(store, requestId, "TIMEOUT");
    await store.rotateLedgerArchive(directory, { keySource: testBackupKeySource, nowMs: 100_000, retainRequestCount: 0, retainJobCount: 0, minAgeMs: 1_000 });
    assert.equal(store.ownedJob(jobId, "principal-1"), undefined);

    const own = conflictMessage(() => store.createJob(jobInput("job:fresh-after-rotation", "outcome-tombstone-own")));
    assert.equal(own, `IDEMPOTENCY_KEY_IN_USE: this idempotency_key or Job id belongs to archived job ${jobId} ` +
      "(mac_task_run, failed, finished 1970-01-01T00:00:00.005Z). Archived keys are never released: inspect it with mac_job_status, or use a new idempotency_key.");
    assert.ok(own.length < 512);

    // The Job id barrier is global: another principal reusing the id is refused without learning whose Job it was.
    const generic = "Job identity or idempotency key refers to archived history; inspect its status before reuse";
    const other = conflictMessage(() => store.createJob({ ...jobInput(jobId, "other-principal-key"), ownerPrincipalId: "principal-2" }));
    assert.equal(other, generic);
    assert.ok(!other.includes("mac_task_run") && !other.includes("failed") && !other.includes("IDEMPOTENCY_KEY_IN_USE"), other);

    // The key itself is principal-scoped: the same text is free for another principal.
    const independent = store.createJob({ ...jobInput("job:principal-2-fresh", "outcome-tombstone-own"), ownerPrincipalId: "principal-2" });
    assert.equal(independent.reused, false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("privileged helper payload descriptors persist across BrokerStore restart", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-privileged-payload-"));
  const databasePath = join(directory, "broker.sqlite");
  const privilegedPayload = { operation: "service_control" as const, service_id: "system/com.example.test", action: "start" as const };
  const payloadDigest = sha256(canonicalJson(privilegedPayload));
  let store = new BrokerStore(databasePath);
  try {
    const created = store.createJob({
      jobId: "job:privileged-payload",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_priv_service_control",
      targetRef: "service:system/com.example.test",
      policyVersion: "policy-0.1",
      payloadDigest,
      idempotencyKey: "privileged-payload",
      createdAtMs: 1,
      privilegedPayload
    });
    assert.deepEqual(created.job.privilegedPayload, privilegedPayload);
    store.startJob(created.job.jobId, "principal-1", created.job.revision, 2);
    store.close();
    store = new BrokerStore(databasePath);
    const recovered = store.ownedJob("job:privileged-payload", "principal-1");
    assert.deepEqual(recovered?.privilegedPayload, privilegedPayload);
    assert.equal(recovered?.state, "unknown");
    assert.deepEqual(store.restartUnknownPrivilegedJobs().map((job) => job.jobId), ["job:privileged-payload"]);
    assert.throws(() => store.createJob({
      jobId: "job:privileged-payload-invalid",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_priv_service_control",
      targetRef: "service:system/com.example.test",
      policyVersion: "policy-0.1",
      payloadDigest: "a".repeat(64),
      idempotencyKey: "privileged-payload-invalid",
      createdAtMs: 1,
      privilegedPayload: { operation: "service_control", service_id: "system/com.example.test", action: "start" }
    }), /malformed/u);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("job transitions enforce revisions and redact secret-shaped output", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-job-transition-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    store.createJob(jobInput("job:transition", "idem-transition"));
    assert.throws(() => store.startJob("job:transition", "principal-1", 0, 0), /malformed/u);
    const running = store.startJob("job:transition", "principal-1", 0, 2);
    assert.equal(running.state, "running");
    assert.equal(running.revision, 1);
    assert.throws(() => store.startJob("job:transition", "principal-1", 0, 3), /changed concurrently/u);
    assert.throws(() => store.finishJob("job:transition", "principal-1", 1, {
      state: "completed", resultClass: "failed", finishedAtMs: 4
    }), /malformed/u);
    const completed = store.finishJob("job:transition", "principal-1", 1, {
      state: "completed",
      resultClass: "success",
      finishedAtMs: 4,
      exitCode: 0,
      stdout: "api_key=supersecretvalue",
      stderr: "safe"
    });
    assert.equal(completed.state, "completed");
    assert.equal(completed.stdout, "[REDACTED: SECRET CONTENT]");
    assert.equal(completed.truncated, true);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("job leases heartbeat, fence stale completion, and are cleared on restart", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-job-lease-"));
  const databasePath = join(directory, "broker.sqlite");
  let store = new BrokerStore(databasePath);
  try {
    const lease = {
      ownerId: "broker:test",
      token: "lease:token-1234567890",
      expiresAtMs: 30
    };
    store.createJob(jobInput("job:lease", "idem-lease"));
    const running = store.startJob("job:lease", "principal-1", 0, 1, lease);
    assert.equal(running.state, "running");
    store.renewJobLease("job:lease", "principal-1", lease, 10, 1_000);
    assert.equal(lease.expiresAtMs, 1_010);
    const inspected = new DatabaseSync(databasePath);
    try {
      const row = inspected.prepare("SELECT lease_owner_id, lease_token, lease_heartbeat_at_ms, lease_expires_at_ms FROM jobs WHERE job_id = ?").get("job:lease") as {
        lease_owner_id: string;
        lease_token: string;
        lease_heartbeat_at_ms: number;
        lease_expires_at_ms: number;
      };
      assert.deepEqual({ ...row }, {
        lease_owner_id: lease.ownerId,
        lease_token: lease.token,
        lease_heartbeat_at_ms: 10,
        lease_expires_at_ms: 1_010
      });
    } finally {
      inspected.close();
    }
    assert.throws(
      () => store.finishJob("job:lease", "principal-1", 1, {
        state: "completed", resultClass: "success", finishedAtMs: 20
      }, { ...lease, token: "lease:stale-token-123456" }, 20),
      /Job lease is no longer active/u
    );
    assert.throws(
      () => store.finishJob("job:lease", "principal-1", 1, {
        state: "completed", resultClass: "success", finishedAtMs: 1_011
      }, lease, 1_011),
      /Job lease is no longer active/u
    );
    const unknown = store.finishJob("job:lease", "principal-1", 1, {
      state: "unknown", resultClass: "unknown", finishedAtMs: 1_011
    }, lease, 1_011);
    assert.equal(unknown.state, "unknown");

    const restartLease = {
      ownerId: "broker:test",
      token: "lease:restart-token-1234",
      expiresAtMs: 30
    };
    store.createJob(jobInput("job:restart-lease", "idem-restart-lease"));
    store.startJob("job:restart-lease", "principal-1", 0, 1, restartLease);
    store.close();
    store = new BrokerStore(databasePath);
    assert.equal(store.ownedJob("job:restart-lease", "principal-1")?.state, "unknown");
    assert.throws(
      () => store.finishJob("job:restart-lease", "principal-1", 1, {
        state: "completed", resultClass: "success", finishedAtMs: 2
      }, restartLease, 2),
      /state or revision changed concurrently/u
    );
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("queued cancellation is immediate, owner-bound, and idempotent", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-job-cancel-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    store.createJob(jobInput("job:cancel", "idem-cancel"));
    assert.throws(() => store.requestJobCancellation("job:cancel", "principal-2", "test", 2), /not found/u);
    const cancelled = store.requestJobCancellation("job:cancel", "principal-1", "test", 2);
    assert.equal(cancelled.priorState, "queued");
    assert.equal(cancelled.job.state, "cancelled");
    assert.equal(cancelled.terminationObserved, true);
    const repeated = store.requestJobCancellation("job:cancel", "principal-1", "again", 3);
    assert.equal(repeated.priorState, "cancelled");
    assert.equal(repeated.job.revision, cancelled.job.revision);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("kill switches and revocations cancel queued jobs in the same persistence transaction", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-job-authority-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    store.createJob({
      ...jobInput("job:queued-read", "idem-queued-read"),
      tool: "mac_health",
      targetRef: "host:broker"
    });
    store.createJob({
      ...jobInput("job:queued-unknown", "idem-queued-unknown"),
      tool: "mac_future_mutation",
      targetRef: "host:broker"
    });
    store.createJob(jobInput("job:queued-task", "idem-queued-task"));
    store.createJob({
      ...jobInput("job:queued-write", "idem-queued-write"),
      tool: "mac_write_file_atomic",
      targetRef: "path:test-root"
    });
    store.setSwitch("mutations", true, "test", 2);
    assert.equal(store.ownedJob("job:queued-read", "principal-1")?.state, "queued");
    assert.equal(store.ownedJob("job:queued-unknown", "principal-1")?.state, "cancelled");
    assert.equal(store.ownedJob("job:queued-task", "principal-1")?.state, "cancelled");
    assert.equal(store.ownedJob("job:queued-write", "principal-1")?.state, "cancelled");
    assert.equal(store.ownedJob("job:queued-task", "principal-1")?.cancelRequested, true);
    assert.equal(store.auditRows().filter((row) => row.tool === "internal_job_authority_reconcile").length, 3);

    store.setSwitch("mutations", false, "test", 3);
    store.createJob(jobInput("job:queued-process", "idem-queued-process"));
    store.createJob({
      ...jobInput("job:queued-process-write", "idem-queued-process-write"),
      tool: "mac_write_file_atomic",
      targetRef: "path:test-root"
    });
    store.setSwitch("process", true, "test", 3);
    assert.equal(store.ownedJob("job:queued-process", "principal-1")?.state, "cancelled");
    assert.equal(store.ownedJob("job:queued-process-write", "principal-1")?.state, "queued");
    store.setSwitch("process", false, "test", 3);
    store.createJob({
      ...jobInput("job:queued-app-open", "idem-queued-app-open"),
      tool: "mac_app_open",
      targetRef: "app:bundle:com.example.Editor"
    });
    store.createJob({
      ...jobInput("job:queued-app-other", "idem-queued-app-other"),
      tool: "mac_task_run",
      targetRef: "task:test"
    });
    store.setSwitch("gui", true, "test", 3);
    assert.equal(store.ownedJob("job:queued-app-open", "principal-1")?.state, "cancelled");
    assert.equal(store.ownedJob("job:queued-app-other", "principal-1")?.state, "queued");
    store.createJob({
      ...jobInput("job:queued-other-principal", "idem-queued-other"),
      ownerPrincipalId: "principal-2",
      ownerSessionId: "session-2"
    });
    store.createJob(jobInput("job:queued-session", "idem-queued-session"));
    store.revoke("session", "session-1", "test", 4);
    assert.equal(store.ownedJob("job:queued-session", "principal-1")?.state, "cancelled");
    assert.equal(store.ownedJob("job:queued-other-principal", "principal-2")?.state, "queued");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Edge revocation cancels matching and unknown-provenance queued Jobs only", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-edge-revocation-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    store.createJob({ ...jobInput("job:edge-one", "idem-edge-one"), edgeId: "edge-1" });
    store.createJob({ ...jobInput("job:edge-two", "idem-edge-two"), edgeId: "edge-2" });
    store.createJob(jobInput("job:edge-legacy", "idem-edge-legacy"));

    store.revoke("edge", "edge-1", "EDGE_REVOKED", 2);

    assert.equal(store.ownedJob("job:edge-one", "principal-1")?.state, "cancelled");
    assert.equal(store.ownedJob("job:edge-two", "principal-1")?.state, "queued");
    assert.equal(store.ownedJob("job:edge-legacy", "principal-1")?.state, "cancelled");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Edge-key revocation cancels matching and unknown-provenance queued Jobs only", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-edge-key-revocation-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    store.createJob({ ...jobInput("job:key-one", "idem-key-one"), edgeId: "edge-1", edgeKeyId: "edge-1:key-old" });
    store.createJob({ ...jobInput("job:key-two", "idem-key-two"), edgeId: "edge-1", edgeKeyId: "edge-1:key-new" });
    store.createJob(jobInput("job:key-legacy", "idem-key-legacy"));

    store.revoke("edge_key", "edge-1:key-old", "EDGE_KEY_REVOKED", 2);

    assert.equal(store.ownedJob("job:key-one", "principal-1")?.state, "cancelled");
    assert.equal(store.ownedJob("job:key-two", "principal-1")?.state, "queued");
    assert.equal(store.ownedJob("job:key-legacy", "principal-1")?.state, "cancelled");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("malformed persisted Job Edge provenance fails closed on readback", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-edge-provenance-corruption-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  store.createJob({ ...jobInput("job:edge-corrupt", "idem-edge-corrupt"), edgeId: "edge-1" });
  store.close();
  try {
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare("UPDATE jobs SET owner_edge_id = ? WHERE job_id = ?").run("edge with spaces", "job:edge-corrupt");
    } finally {
      database.close();
    }
    assert.throws(
      () => new BrokerStore(databasePath),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("authority switches and revocations append redacted intent and completion evidence", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-authority-audit-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    store.setSwitch("network", true, "INCIDENT_RESPONSE", 10);
    store.revoke("session", "session-1", "SESSION_EXPIRED", 11);

    const authorityRows = store.auditRows().filter((row) =>
      row.tool === "internal_authority_switch" || row.tool === "internal_authority_revoke"
    );
    assert.deepEqual(
      authorityRows.map((row) => [row.tool, row.event_type, row.decision, row.result_class]),
      [
        ["internal_authority_switch", "intent", "allow", "INTENT_RECORDED"],
        ["internal_authority_switch", "completion", "allow", "SUCCEEDED"],
        ["internal_authority_revoke", "intent", "allow", "INTENT_RECORDED"],
        ["internal_authority_revoke", "completion", "allow", "SUCCEEDED"]
      ]
    );
    const switchCompletion = authorityRows.find((row) =>
      row.tool === "internal_authority_switch" && row.event_type === "completion"
    );
    const revokeCompletion = authorityRows.find((row) =>
      row.tool === "internal_authority_revoke" && row.event_type === "completion"
    );
    assert.equal(JSON.parse(String(switchCompletion?.evidence_json)).cancelledQueuedJobs, 0);
    assert.equal(JSON.parse(String(revokeCompletion?.evidence_json)).persisted, true);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("deterministic authority state machine preserves job lifecycle invariants", async () => {
  const switchNames: readonly SwitchName[] = ["global", "mutations", "process", "network", "gui", "destructive", "privileged"];
  const switchAffects = (name: SwitchName, tool: string): boolean => {
    if (name === "global" || name === "mutations") return true;
    if (name === "process" || name === "network") return tool === "mac_task_run";
    if (name === "gui") return tool === "mac_app_open" || tool === "mac_app_focus" || tool.startsWith("mac_ui_");
    if (name === "destructive") return tool === "mac_apply_patch";
    return tool.startsWith("mac_priv_");
  };
  const nextRandom = (seed: number): (() => number) => {
    let state = seed >>> 0;
    return () => {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      return (state >>> 0) / 0x1_0000_0000;
    };
  };
  const terminalStates = new Set<JobState>(["completed", "failed", "cancelled", "unknown"]);

  for (let seed = 1; seed <= 16; seed += 1) {
    const directory = await mkdtemp(join(tmpdir(), `mac-operator-authority-state-${seed}-`));
    const store = new BrokerStore(join(directory, "broker.sqlite"));
    const random = nextRandom(0x9e3779b9 ^ seed);
    const disabled = new Set<SwitchName>();
    const revokedPrincipals = new Set<string>();
    const revokedSessions = new Set<string>();
    let upstreamRevoked = false;
    let now = 10;
    const jobs = new Map<string, { ownerPrincipalId: string; ownerSessionId: string; tool: string }>();
    const previous = new Map<string, { state: JobState; revision: number }>();

    const addJob = (input: CreateJobInput) => {
      const ownerPrincipalId = input.ownerPrincipalId ?? "principal-1";
      const ownerSessionId = input.ownerSessionId ?? "session-1";
      const created = store.createJob({ ...input, ownerPrincipalId, ownerSessionId });
      jobs.set(input.jobId, { ownerPrincipalId, ownerSessionId, tool: input.tool });
      previous.set(input.jobId, { state: created.job.state, revision: created.job.revision });
    };

    const privilegedPayload = { operation: "power", action: "reboot" } as const;
    addJob(jobInput(`job:state-${seed}-health`, `idem:state-${seed}-health`));
    addJob({ ...jobInput(`job:state-${seed}-task`, `idem:state-${seed}-task`), targetRef: "task:state" });
    addJob({ ...jobInput(`job:state-${seed}-write`, `idem:state-${seed}-write`), tool: "mac_write_file_atomic", targetRef: "path:state" });
    addJob({ ...jobInput(`job:state-${seed}-gui`, `idem:state-${seed}-gui`), tool: "mac_app_open", targetRef: "app:state" });
    addJob({ ...jobInput(`job:state-${seed}-destructive`, `idem:state-${seed}-destructive`), tool: "mac_apply_patch", targetRef: "path:state" });
    addJob({
      ...jobInput(`job:state-${seed}-privileged`, `idem:state-${seed}-privileged`),
      tool: "mac_priv_power",
      targetRef: "host:local",
      payloadDigest: sha256(canonicalJson(privilegedPayload)),
      privilegedPayload
    });
    addJob({ ...jobInput(`job:state-${seed}-other`, `idem:state-${seed}-other`), ownerPrincipalId: "principal-2", ownerSessionId: "session-2" });

    const blocked = (meta: { ownerPrincipalId: string; ownerSessionId: string; tool: string }): boolean =>
      upstreamRevoked || revokedPrincipals.has(meta.ownerPrincipalId) || revokedSessions.has(meta.ownerSessionId) ||
      [...disabled].some((name) => switchAffects(name, meta.tool));

    const assertInvariants = () => {
      for (const [jobId, meta] of jobs) {
        const job = store.ownedJob(jobId, meta.ownerPrincipalId);
        assert.ok(job, `missing job ${jobId}`);
        if (!job) continue;
        const prior = previous.get(jobId);
        assert.ok(prior);
        if (prior) {
          assert.ok(job.revision >= prior.revision, `revision regressed for ${jobId}`);
          if (terminalStates.has(prior.state)) assert.equal(job.state, prior.state, `terminal job changed ${jobId}`);
        }
        if (job.state === "queued") {
          assert.equal(job.resultClass, "queued");
          assert.equal(job.cancelRequested, false);
          assert.equal(blocked(meta), false, `blocked job remained queued ${jobId}`);
        } else if (job.state === "running") {
          assert.equal(job.resultClass, "accepted");
        } else if (job.state === "cancelled") {
          assert.equal(job.resultClass, "denied");
          assert.equal(job.cancelRequested, true);
          assert.ok(job.finishedAtMs !== null);
        } else if (job.state === "completed") {
          assert.equal(job.resultClass, "success");
          assert.ok(job.finishedAtMs !== null);
        } else if (job.state === "failed") {
          assert.ok(["failed", "denied", "verification_failed"].includes(job.resultClass));
          assert.ok(job.finishedAtMs !== null);
        } else {
          assert.equal(job.resultClass, "unknown");
          assert.ok(job.finishedAtMs !== null);
        }
        previous.set(jobId, { state: job.state, revision: job.revision });
      }
    };

    try {
      for (let step = 0; step < 72; step += 1) {
        now += 1;
        const action = Math.floor(random() * 5);
        const entries = [...jobs.entries()];
        if (action === 0) {
          const name = switchNames[Math.floor(random() * switchNames.length)]!;
          const current = disabled.has(name);
          const expected = random() < 0.2 ? !current : current;
          if (expected !== current) {
            assert.throws(
              () => store.setSwitch(name, !current, "state-machine", now, expected),
              (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT"
            );
          } else {
            const nextDisabled = random() < 0.55;
            store.setSwitch(name, nextDisabled, "state-machine", now, current);
            if (nextDisabled) disabled.add(name);
            else disabled.delete(name);
          }
        } else if (action === 1) {
          const kind = Math.floor(random() * 3);
          if (kind === 0) {
            revokedPrincipals.add("principal-1");
            store.revoke("principal", "principal-1", "state-machine", now);
          } else if (kind === 1) {
            revokedSessions.add("session-1");
            store.revoke("session", "session-1", "state-machine", now);
          } else {
            upstreamRevoked = true;
            store.revoke("edge", "edge-1", "state-machine", now);
          }
        } else if (action === 2) {
          const candidates = entries.filter(([jobId, meta]) => {
            const job = store.ownedJob(jobId, meta.ownerPrincipalId);
            return job?.state === "queued" && !blocked(meta);
          });
          if (candidates.length > 0) {
            const [jobId, meta] = candidates[Math.floor(random() * candidates.length)]!;
            const current = store.ownedJob(jobId, meta.ownerPrincipalId);
            assert.ok(current);
            if (current) store.startJob(jobId, meta.ownerPrincipalId, current.revision, now);
          }
        } else if (action === 3) {
          const candidates = entries.filter(([jobId, meta]) => {
            const job = store.ownedJob(jobId, meta.ownerPrincipalId);
            return job?.state === "queued" || job?.state === "running";
          });
          if (candidates.length > 0) {
            const [jobId, meta] = candidates[Math.floor(random() * candidates.length)]!;
            store.requestJobCancellation(jobId, meta.ownerPrincipalId, "state-machine", now);
          }
        } else {
          const candidates = entries.filter(([jobId, meta]) => store.ownedJob(jobId, meta.ownerPrincipalId)?.state === "running");
          if (candidates.length > 0) {
            const [jobId, meta] = candidates[Math.floor(random() * candidates.length)]!;
            const current = store.ownedJob(jobId, meta.ownerPrincipalId);
            assert.ok(current);
            if (current) {
              const outcome = current.cancelRequested
                ? { state: "cancelled" as const, resultClass: "denied" as const }
                : random() < 0.65
                  ? { state: "completed" as const, resultClass: "success" as const }
                  : { state: "failed" as const, resultClass: "failed" as const };
              store.finishJob(jobId, meta.ownerPrincipalId, current.revision, { ...outcome, finishedAtMs: now });
            }
          }
        }
        assertInvariants();
      }

      const reconciled = store.reconcileInterruptedJobs(now + 100);
      assert.equal(reconciled.queuedCancelled, 0);
      for (const [jobId, meta] of jobs) {
        const job = store.ownedJob(jobId, meta.ownerPrincipalId);
        assert.ok(job);
        if (job?.state === "running") assert.fail(`running job survived reconciliation: ${jobId}`);
        if (job?.state === "queued") assert.fail(`queued job survived reconciliation: ${jobId}`);
      }
      assertInvariants();
    } finally {
      store.close();
      await rm(directory, { recursive: true, force: true });
    }
  }
});

test("restart reconciliation cancels queued jobs and marks running outcomes unknown", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-job-reconcile-"));
  const databasePath = join(directory, "broker.sqlite");
  let store = new BrokerStore(databasePath);
  store.createJob(jobInput("job:queued", "idem-queued"));
  store.createJob(jobInput("job:running", "idem-running"));
  store.startJob("job:running", "principal-1", 0, 2);
  store.close();
  store = new BrokerStore(databasePath);
  try {
    assert.equal(store.ownedJob("job:queued", "principal-1")?.state, "cancelled");
    assert.equal(store.ownedJob("job:running", "principal-1")?.state, "unknown");
    assert.deepEqual(store.auditRows().map((row) => [row.target_ref, row.result_class]), [
      ["job:job:queued", "CANCELLED"],
      ["job:job:running", "UNKNOWN_OUTCOME"]
    ]);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("queued service-control cancellation clears terminal-only recovery metadata", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-queued-service-cancel-"));
  const databasePath = join(directory, "broker.sqlite");
  const serviceMetadata = {
    serviceId: "gui/501/com.mac-operator.edge",
    action: "start" as const,
    expectedState: "running" as const,
    preState: "stopped" as const,
    preSourceRevision: "a".repeat(7),
    bindingSourceRevision: "a".repeat(7)
  };
  const privilegedPayload = { operation: "power" as const, action: "reboot" as const };
  let store = new BrokerStore(databasePath);
  try {
    store.createJob({ ...jobInput("job:queued-service-cancel", "queued-service-cancel"), tool: "mac_service_control", targetRef: "service:gui/501/com.mac-operator.edge", serviceMetadata });
    store.createJob({
      ...jobInput("job:queued-privileged-cancel", "queued-privileged-cancel"),
      tool: "mac_priv_power",
      targetRef: "host:local",
      payloadDigest: sha256(canonicalJson(privilegedPayload)),
      privilegedPayload
    });
    const cancelled = store.requestJobCancellation("job:queued-service-cancel", "principal-1", "OWNER_CANCELLED", 2).job;
    const privilegedCancelled = store.requestJobCancellation("job:queued-privileged-cancel", "principal-1", "OWNER_CANCELLED", 2).job;
    assert.equal(cancelled.state, "cancelled");
    assert.equal(cancelled.serviceMetadata, undefined);
    assert.equal(privilegedCancelled.state, "cancelled");
    assert.equal(privilegedCancelled.privilegedPayload, undefined);
    store.close();
    store = new BrokerStore(databasePath);
    assert.equal(store.ownedJob("job:queued-service-cancel", "principal-1")?.state, "cancelled");
    assert.equal(store.ownedJob("job:queued-service-cancel", "principal-1")?.serviceMetadata, undefined);
    assert.equal(store.ownedJob("job:queued-privileged-cancel", "principal-1")?.privilegedPayload, undefined);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("queued service-control restart recovery clears metadata and remains stable on the next restart", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-queued-service-restart-"));
  const databasePath = join(directory, "broker.sqlite");
  const serviceMetadata = {
    serviceId: "gui/501/com.mac-operator.broker",
    action: "stop" as const,
    expectedState: "stopped" as const,
    preState: "running" as const,
    preSourceRevision: "b".repeat(7),
    bindingSourceRevision: "b".repeat(7)
  };
  let store = new BrokerStore(databasePath);
  try {
    store.createJob({ ...jobInput("job:queued-service-restart", "queued-service-restart"), tool: "mac_service_control", targetRef: "service:gui/501/com.mac-operator.broker", serviceMetadata });
    store.close();
    store = new BrokerStore(databasePath);
    const firstReadback = store.ownedJob("job:queued-service-restart", "principal-1");
    assert.equal(firstReadback?.state, "cancelled");
    assert.equal(firstReadback?.cancelRequested, true);
    assert.equal(firstReadback?.serviceMetadata, undefined);
    const firstRevision = firstReadback?.revision;
    store.close();
    store = new BrokerStore(databasePath);
    const secondReadback = store.ownedJob("job:queued-service-restart", "principal-1");
    assert.equal(secondReadback?.state, "cancelled");
    assert.equal(secondReadback?.revision, firstRevision);
    assert.equal(secondReadback?.serviceMetadata, undefined);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("write job idempotency identity survives restart and unresolved work becomes unknown", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-write-job-reconcile-"));
  const databasePath = join(directory, "broker.sqlite");
  let store = new BrokerStore(databasePath);
  store.createJob({
    ...jobInput("job:write-recovery", "write-recovery"),
    tool: "mac_write_file_atomic",
    targetRef: "path:test-root"
  });
  store.startJob("job:write-recovery", "principal-1", 0, 2);
  assert.equal(store.ownedJobByIdempotencyKey("write-recovery", "principal-1")?.state, "running");
  store.close();
  store = new BrokerStore(databasePath);
  try {
    const recovered = store.ownedJobByIdempotencyKey("write-recovery", "principal-1");
    assert.equal(recovered?.tool, "mac_write_file_atomic");
    assert.equal(recovered?.state, "unknown");
    assert.equal(recovered?.resultClass, "unknown");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("unresolved write metadata survives restart without storing content", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-write-metadata-"));
  const databasePath = join(directory, "broker.sqlite");
  const metadata = {
    rootId: "test-root",
    path: join(directory, "target.txt"),
    bytes: 4,
    desiredSha256: "a".repeat(64),
    expectedSha256: null,
    createOnly: true,
    temporaryName: ".mac-operator-write-restart"
  } as const;
  let store = new BrokerStore(databasePath);
  store.createJob({
    ...jobInput("job:write-metadata", "write-metadata"),
    tool: "mac_write_file_atomic",
    targetRef: "path:test-root",
    writeMetadata: metadata
  });
  store.startJob("job:write-metadata", "principal-1", 0, 2);
  store.close();
  store = new BrokerStore(databasePath);
  try {
    const recovered = store.ownedJob("job:write-metadata", "principal-1");
    assert.deepEqual(recovered?.writeMetadata, metadata);
    assert.deepEqual(store.restartUnknownWriteJobs().map((job) => job.jobId), ["job:write-metadata"]);
    assert.equal(recovered?.stdout, "");
    assert.equal(recovered?.state, "unknown");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("unresolved user-service metadata survives restart without losing the source identity", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-service-metadata-"));
  const databasePath = join(directory, "broker.sqlite");
  const serviceMetadata = {
    serviceId: "gui/501/com.mac-operator.test",
    action: "start" as const,
    expectedState: "running" as const,
    preState: "stopped" as const,
    preSourceRevision: "abcdef1",
    bindingSourceRevision: "abcdef1"
  };
  let store = new BrokerStore(databasePath);
  store.createJob({
    ...jobInput("job:service-metadata", "service-metadata"),
    tool: "mac_service_control",
    targetRef: "service:gui/501/com.mac-operator.test",
    serviceMetadata
  });
  store.startJob("job:service-metadata", "principal-1", 0, 2);
  store.close();
  store = new BrokerStore(databasePath);
  try {
    const recovered = store.ownedJob("job:service-metadata", "principal-1");
    assert.deepEqual(recovered?.serviceMetadata, serviceMetadata);
    assert.deepEqual(store.restartUnknownServiceJobs().map((job) => job.jobId), ["job:service-metadata"]);
    assert.equal(recovered?.stdout, "");
    assert.equal(recovered?.state, "unknown");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("task process ownership metadata survives restart as UNKNOWN", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-task-process-metadata-"));
  const databasePath = join(directory, "broker.sqlite");
  const metadata = {
    pid: 1234,
    processGroupId: 1234,
    startTimeMicros: 987654321,
    recordedAtMs: 2,
    descendants: []
  } as const;
  const lease = {
    ownerId: "broker:test",
    token: "lease:process-metadata-1234",
    expiresAtMs: 30
  };
  let store = new BrokerStore(databasePath);
  try {
    store.createJob(jobInput("job:task-process-metadata", "task-process-metadata"));
    const running = store.startJob("job:task-process-metadata", "principal-1", 0, 1, lease);
    const recorded = store.recordJobProcessOwnership(
      "job:task-process-metadata",
      "principal-1",
      running.revision,
      metadata,
      lease,
      2
    );
    assert.deepEqual(recorded.processMetadata, metadata);
    assert.equal(recorded.revision, 2);
    const extendedMetadata = {
      ...metadata,
      recordedAtMs: 3,
      descendants: [{ pid: 1235, startTimeMicros: 987654322 }]
    } as const;
    const updated = store.updateJobProcessOwnership(
      "job:task-process-metadata",
      "principal-1",
      recorded.revision,
      extendedMetadata,
      lease,
      3
    );
    assert.deepEqual(updated.processMetadata, extendedMetadata);
    assert.equal(updated.revision, recorded.revision);
    store.close();
    store = new BrokerStore(databasePath);
    const recovered = store.ownedJob("job:task-process-metadata", "principal-1");
    assert.equal(recovered?.state, "unknown");
    assert.deepEqual(recovered?.processMetadata, extendedMetadata);
    assert.deepEqual(store.unresolvedTaskProcessJobs().map((job) => job.jobId), ["job:task-process-metadata"]);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("task process no-fork ownership proof survives restart", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-task-process-proof-"));
  const databasePath = join(directory, "broker.sqlite");
  const metadata = {
    pid: 1234,
    processGroupId: 1234,
    startTimeMicros: 987654321,
    recordedAtMs: 2,
    descendants: [],
    ownershipProof: "sandbox-exec-no-fork-v1"
  } as const;
  const lease = {
    ownerId: "broker:test",
    token: "lease:process-proof-1234",
    expiresAtMs: 30
  };
  let store = new BrokerStore(databasePath);
  try {
    store.createJob(jobInput("job:task-process-proof", "task-process-proof"));
    const running = store.startJob("job:task-process-proof", "principal-1", 0, 1, lease);
    const recorded = store.recordJobProcessOwnership(
      "job:task-process-proof",
      "principal-1",
      running.revision,
      metadata,
      lease,
      2
    );
    assert.deepEqual(recorded.processMetadata, metadata);
    store.close();
    store = new BrokerStore(databasePath);
    assert.deepEqual(store.ownedJob("job:task-process-proof", "principal-1")?.processMetadata, metadata);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("unknown host task without process evidence remains quarantined after restart", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-task-quarantine-no-identity-"));
  const databasePath = join(directory, "broker.sqlite");
  const lease = { ownerId: "broker:quarantine", token: "lease:quarantine-123456", expiresAtMs: 30_000 };
  let store = new BrokerStore(databasePath);
  try {
    store.createJob(jobInput("job:quarantine-no-identity", "quarantine-no-identity"));
    const started = store.startJob("job:quarantine-no-identity", "principal-1", 0, 2, lease);
    store.finishJob("job:quarantine-no-identity", "principal-1", started.revision, {
      state: "unknown", resultClass: "unknown", finishedAtMs: 3
    }, lease, 3);
    assert.equal(store.hasUnresolvedHostTaskExecution(), true);
    assert.deepEqual(store.unresolvedTaskProcessJobs(), []);

    store.close();
    store = new BrokerStore(databasePath);
    assert.equal(store.ownedJob("job:quarantine-no-identity", "principal-1")?.state, "unknown");
    assert.equal(store.hasUnresolvedHostTaskExecution(), true);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("process-group recovery cannot clear quarantine without a no-fork proof", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-task-quarantine-observer-"));
  const databasePath = join(directory, "broker.sqlite");
  const lease = { ownerId: "broker:quarantine", token: "lease:quarantine-234567", expiresAtMs: 30_000 };
  const metadata = {
    pid: 4321,
    processGroupId: 4321,
    startTimeMicros: 987654321,
    recordedAtMs: 2,
    descendants: []
  } as const;
  let store = new BrokerStore(databasePath);
  try {
    store.createJob(jobInput("job:quarantine-observer", "quarantine-observer"));
    const started = store.startJob("job:quarantine-observer", "principal-1", 0, 1, lease);
    const recorded = store.recordJobProcessOwnership(
      "job:quarantine-observer", "principal-1", started.revision, metadata, lease, 2
    );
    const unknown = store.finishJob(
      "job:quarantine-observer", "principal-1", recorded.revision,
      { state: "unknown", resultClass: "unknown", finishedAtMs: 3 }, lease, 3
    );
    store.appendAudit({
      requestId: `job-process-recovery-${unknown.jobId}-${unknown.revision}`,
      principalId: "principal-1",
      tool: "internal_task_process_recovery",
      eventType: "intent",
      decision: "allow",
      resultClass: "INTENT_RECORDED",
      targetRef: `job:${unknown.jobId}`,
      policyVersion: unknown.policyVersion,
      evidence: { jobId: unknown.jobId, pid: metadata.pid },
      timestampMs: 4
    });
    store.appendAudit({
      requestId: `job-process-recovery-${unknown.jobId}-${unknown.revision}`,
      principalId: "principal-1",
      tool: "internal_task_process_recovery",
      eventType: "completion",
      decision: "allow",
      resultClass: "PROCESS_DRAINED",
      targetRef: `job:${unknown.jobId}`,
      policyVersion: unknown.policyVersion,
      evidence: { jobId: unknown.jobId, pid: metadata.pid },
      timestampMs: 5
    });
    assert.equal(store.hasUnresolvedHostTaskExecution(), true);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("verified no-fork recovery clears host quarantine without blocking guest Jobs", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-task-quarantine-nofork-"));
  const databasePath = join(directory, "broker.sqlite");
  const lease = { ownerId: "broker:quarantine", token: "lease:quarantine-345678", expiresAtMs: 30_000 };
  const processMetadata = {
    pid: 5432,
    processGroupId: 5432,
    startTimeMicros: 987654322,
    recordedAtMs: 2,
    descendants: [],
    ownershipProof: "sandbox-exec-no-fork-v1"
  } as const;
  const guestMetadata = {
    requestId: "request:guest-quarantine-12345678",
    nonce: "guest-nonce-quarantine-12345678",
    requestDigest: "a".repeat(64),
    guestIdentity: { imageSha256: "b".repeat(64), runtimeVersion: "linux-guest-test" },
    profileDigest: "c".repeat(64),
    taskDigest: "d".repeat(64),
    timeoutMs: 1_000,
    outputCapBytes: 1_024,
    recordedAtMs: 7
  } as const;
  let store = new BrokerStore(databasePath);
  try {
    store.createJob(jobInput("job:quarantine-nofork", "quarantine-nofork"));
    const started = store.startJob("job:quarantine-nofork", "principal-1", 0, 1, lease);
    const recorded = store.recordJobProcessOwnership(
      "job:quarantine-nofork", "principal-1", started.revision, processMetadata, lease, 2
    );
    const unknown = store.finishJob(
      "job:quarantine-nofork", "principal-1", recorded.revision,
      { state: "unknown", resultClass: "unknown", finishedAtMs: 3 }, lease, 3
    );
    assert.equal(store.hasUnresolvedHostTaskExecution(), true);
    const recoveryRequestId = `job-process-recovery-${unknown.jobId}-${unknown.revision}`;
    store.appendAudit({
      requestId: recoveryRequestId,
      principalId: "principal-1",
      tool: "internal_task_process_recovery",
      eventType: "intent",
      decision: "allow",
      resultClass: "INTENT_RECORDED",
      targetRef: `job:${unknown.jobId}`,
      policyVersion: unknown.policyVersion,
      evidence: { jobId: unknown.jobId, pid: processMetadata.pid },
      timestampMs: 4
    });
    store.appendAudit({
      requestId: recoveryRequestId,
      principalId: "principal-1",
      tool: "internal_task_process_recovery",
      eventType: "completion",
      decision: "allow",
      resultClass: "PROCESS_ABSENT",
      targetRef: `job:${unknown.jobId}`,
      policyVersion: unknown.policyVersion,
      evidence: { jobId: unknown.jobId, pid: processMetadata.pid },
      timestampMs: 5
    });
    assert.equal(store.hasUnresolvedHostTaskExecution(), false);

    store.createJob(jobInput("job:quarantine-guest", "quarantine-guest"));
    const guestStarted = store.startJob("job:quarantine-guest", "principal-1", 0, 6, lease);
    const guestRecorded = store.recordJobGuestRequest(
      "job:quarantine-guest", "principal-1", guestStarted.revision, guestMetadata, lease, 7
    );
    store.finishJob(
      "job:quarantine-guest", "principal-1", guestRecorded.revision,
      { state: "unknown", resultClass: "unknown", finishedAtMs: 8 }, lease, 8
    );
    assert.equal(store.hasUnresolvedHostTaskExecution(), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Virtualization guest request identity survives restart and terminal recovery clears it", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-guest-task-metadata-"));
  const databasePath = join(directory, "broker.sqlite");
  const metadata = {
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
  const lease = {
    ownerId: "broker:test",
    token: "lease:guest-task-metadata-1234",
    expiresAtMs: 30
  };
  let store = new BrokerStore(databasePath);
  try {
    store.createJob(jobInput("job:guest-task-metadata", "guest-task-metadata"));
    const running = store.startJob("job:guest-task-metadata", "principal-1", 0, 1, lease);
    const recorded = store.recordJobGuestRequest(
      "job:guest-task-metadata",
      "principal-1",
      running.revision,
      metadata,
      lease,
      2
    );
    assert.deepEqual(recorded.guestMetadata, metadata);
    assert.equal(recorded.revision, 2);
    store.close();
    store = new BrokerStore(databasePath);
    const recovered = store.ownedJob("job:guest-task-metadata", "principal-1");
    assert.equal(recovered?.state, "unknown");
    assert.deepEqual(recovered?.guestMetadata, metadata);
    assert.deepEqual(store.restartUnknownGuestJobs().map((job) => job.jobId), ["job:guest-task-metadata"]);
    const reconciled = store.reconcileUnknownGuestTask(
      "job:guest-task-metadata",
      "principal-1",
      recovered?.revision ?? -1,
      {
        state: "completed",
        resultClass: "success",
        finishedAtMs: 4,
        exitCode: 0,
        stdout: "verified",
        verificationStatus: "verified"
      }
    );
    assert.equal(reconciled.state, "completed");
    assert.equal(reconciled.guestMetadata, undefined);
    assert.deepEqual(store.restartUnknownGuestJobs(), []);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("authenticated guest result journal survives restart, is audit-bound, and clears on reconciliation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-guest-result-journal-"));
  const databasePath = join(directory, "broker.sqlite");
  const metadata = {
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
  const lease = {
    ownerId: "broker:guest-result-journal",
    token: "lease:guest-result-journal-1234",
    expiresAtMs: 30
  };
  let store = new BrokerStore(databasePath);
  try {
    store.createJob(jobInput("job:guest-result-journal", "guest-result-journal"));
    const started = store.startJob("job:guest-result-journal", "principal-1", 0, 1, lease);
    const admitted = store.recordJobGuestRequest(
      "job:guest-result-journal", "principal-1", started.revision, metadata, lease, 2
    );
    const journaled = store.recordJobGuestResult(
      "job:guest-result-journal", "principal-1", admitted.revision,
      {
        state: "completed",
        resultClass: "SUCCEEDED",
        exitCode: 0,
        stdout: "verified guest output",
        stderr: "",
        truncated: false,
        durationMs: 4,
        verification: { status: "verified", summary: "guest response authenticated" }
      },
      lease,
      3
    );
    assert.equal(journaled.guestResultJournal?.result.stdout, "verified guest output");
    assert.equal(store.auditEventResult(`guest-result-${sha256("job:guest-result-journal").slice(0, 16)}-${metadata.requestDigest.slice(0, 16)}`, "completion"), "GUEST_RESULT_JOURNALED");
    store.close();

    store = new BrokerStore(databasePath);
    const recovered = store.ownedJob("job:guest-result-journal", "principal-1");
    assert.equal(recovered?.state, "unknown");
    assert.deepEqual(recovered?.guestResultJournal?.result.stdout, "verified guest output");
    assert.deepEqual(store.restartUnknownGuestJobs().map((job) => job.jobId), ["job:guest-result-journal"]);
    const reconciled = store.reconcileUnknownGuestTask(
      "job:guest-result-journal", "principal-1", recovered?.revision ?? -1,
      { state: "completed", resultClass: "success", finishedAtMs: 4, exitCode: 0, stdout: "verified guest output", verificationStatus: "verified" }
    );
    assert.equal(reconciled.state, "completed");
    assert.equal(reconciled.guestMetadata, undefined);
    assert.equal(reconciled.guestResultJournal, undefined);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("BrokerStore rejects a guest result journal changed independently of its audit evidence", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-guest-result-tamper-"));
  const databasePath = join(directory, "broker.sqlite");
  const metadata = {
    requestId: "request:guest-tamper-123456789",
    nonce: "guest-nonce-tamper-123456789",
    requestDigest: "b".repeat(64),
    guestIdentity: { imageSha256: "c".repeat(64), runtimeVersion: "macos-guest-1" },
    profileDigest: "d".repeat(64),
    taskDigest: "e".repeat(64),
    timeoutMs: 10_000,
    outputCapBytes: 4_096,
    recordedAtMs: 2
  } as const;
  const lease = { ownerId: "broker:guest-result-tamper", token: "lease:guest-result-tamper-1234", expiresAtMs: 30 };
  const store = new BrokerStore(databasePath);
  store.createJob(jobInput("job:guest-result-tamper", "guest-result-tamper"));
  const started = store.startJob("job:guest-result-tamper", "principal-1", 0, 1, lease);
  const admitted = store.recordJobGuestRequest("job:guest-result-tamper", "principal-1", started.revision, metadata, lease, 2);
  store.recordJobGuestResult(
    "job:guest-result-tamper", "principal-1", admitted.revision,
    {
      state: "completed", resultClass: "SUCCEEDED", exitCode: 0, stdout: "original",
      stderr: "", truncated: false, durationMs: 4, verification: { status: "verified" }
    },
    lease,
    3
  );
  store.close();
  try {
    const database = new DatabaseSync(databasePath);
    try {
      const row = database.prepare("SELECT guest_result_json FROM jobs WHERE job_id = ?").get("job:guest-result-tamper") as { guest_result_json: string };
      const journal = JSON.parse(row.guest_result_json) as { result: { stdout: string } };
      journal.result.stdout = "altered without audit update";
      database.prepare("UPDATE jobs SET guest_result_json = ? WHERE job_id = ?").run(canonicalJson(journal), "job:guest-result-tamper");
    } finally {
      database.close();
    }
    assert.throws(
      () => new BrokerStore(databasePath),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

function jobInput(jobId: string, idempotencyKey: string) {
  return {
    jobId,
    ownerPrincipalId: "principal-1",
    ownerSessionId: "session-1",
    tool: "mac_task_run",
    targetRef: "task:test",
    policyVersion: "policy-0.1",
    payloadDigest: "a".repeat(64),
    idempotencyKey,
    createdAtMs: 1
  };
}

function requestInput(requestId: string, nonce: string, mutation: boolean) {
  return {
    requestId,
    edgeId: "edge-1",
    nonce,
    nonceExpiresAtMs: 10_000,
    principalId: "principal-1",
    sessionId: "session-1",
    tool: mutation ? "mac_job_cancel" : "mac_health",
    policyVersion: "policy-0.1",
    payloadDigest: "c".repeat(64),
    mutation,
    receivedAtMs: 1
  };
}

function requestEvent(
  requestId: string,
  eventType: "decision" | "intent" | "completion",
  resultClass: string,
  timestampMs: number
) {
  return {
    requestId,
    principalId: "principal-1",
    tool: "mac_job_cancel",
    eventType,
    decision: "allow" as const,
    resultClass,
    targetRef: "job:owned",
    policyVersion: "policy-0.1",
    evidence: {},
    timestampMs
  };
}

function waitForChild(child: ReturnType<typeof spawn>): Promise<{
  code: number | null;
  signal: NodeJS.Signals | null;
  stderr: string;
}> {
  return new Promise((resolve, reject) => {
    const stderr: Buffer[] = [];
    child.stderr?.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({
      code,
      signal,
      stderr: Buffer.concat(stderr).toString("utf8")
    }));
  });
}

function approvalInput(approvalId: string) {
  return {
    approvalId,
    approverPrincipalId: "operator-1",
    requestingPrincipalId: "principal-1",
    tool: "mac_job_cancel",
    contractVersion: "0.1",
    targetKind: "job",
    targetRef: "job:owned",
    payloadDigest: "d".repeat(64),
    policyVersion: "policy-0.1",
    approvalClass: "trusted_write" as const,
    unattended: false,
    issuedAtMs: 2,
    expiresAtMs: 10
  };
}

function authorizeMutationRequest(store: BrokerStore, requestId: string, nonce: string): void {
  store.admitRequest(requestInput(requestId, nonce, true));
  store.recordRequestDecision(requestEvent(requestId, "decision", "AUTHORIZED", 2));
}

function approvalBinding() {
  return {
    contractVersion: "0.1",
    targetKind: "job",
    targetRef: "job:owned",
    payloadDigest: "d".repeat(64),
    approvalClass: "trusted_write" as const,
    unattended: false
  };
}

function atomicJobAdmissionInput(
  requestId: string,
  nonce: string,
  jobId: string,
  jobTarget: string,
  approvalTarget: string
) {
  const decisionTarget = approvalTarget;
  return {
    request: {
      requestId,
      edgeId: "edge-1",
      edgeKeyId: "edge-1:edge-key-1",
      nonce,
      nonceExpiresAtMs: 10_000,
      principalId: "principal-1",
      sessionId: "session-1",
      tool: "mac_task_run",
      policyVersion: "policy-0.1",
      payloadDigest: "a".repeat(64),
      mutation: true,
      receivedAtMs: 1
    },
    decision: {
      requestId,
      principalId: "principal-1",
      tool: "mac_task_run",
      eventType: "decision" as const,
      decision: "allow" as const,
      resultClass: "AUTHORIZED",
      targetRef: decisionTarget,
      policyVersion: "policy-0.1",
      evidence: {},
      timestampMs: 2
    },
    intent: {
      requestId,
      principalId: "principal-1",
      tool: "mac_task_run",
      eventType: "intent" as const,
      decision: "allow" as const,
      resultClass: "INTENT_RECORDED",
      targetRef: decisionTarget,
      policyVersion: "policy-0.1",
      evidence: { argumentDigest: "b".repeat(64) },
      timestampMs: 3
    },
    approval: {
      contractVersion: "0.1",
      targetKind: "task_profile",
      targetRef: decisionTarget,
      payloadDigest: "b".repeat(64),
      approvalClass: "trusted_profile" as const,
      unattended: false
    },
    job: {
      jobId,
      edgeId: "edge-1",
      edgeKeyId: "edge-1:edge-key-1",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_task_run",
      targetRef: jobTarget,
      policyVersion: "policy-0.1",
      payloadDigest: "b".repeat(64),
      idempotencyKey: "atomic-task",
      createdAtMs: 3
    }
  };
}


test("session-delegated approvals cannot be consumed by an identical competing request", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mop-session-request-binding-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    authorizeMutationRequest(store, "intended-request", "nonce-intended");
    authorizeMutationRequest(store, "competing-request", "nonce-competing");
    const id = guiSessionApprovalId("intended-request");
    store.issueApproval(approvalInput(id));
    assert.throws(() => store.recordRequestIntent(requestEvent("competing-request", "intent", "INTENT_RECORDED", 3), approvalBinding()), /No valid approval/u);
    assert.equal(store.approvalRecord(id)?.usedCount, 0);
    store.recordRequestIntent(requestEvent("intended-request", "intent", "INTENT_RECORDED", 3), approvalBinding());
    assert.equal(store.approvalRecord(id)?.lastRequestId, "intended-request");
  } finally { store.close(); await rm(directory, { recursive: true, force: true }); }
});
