import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { lstat, mkdtemp, readFile, readdir, rm, symlink, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import { BROKER_SCHEMA_VERSION, BrokerStore } from "./persistence.js";

const testBackupKeySource = {
  keyId: "backup-test-1",
  loadKey: () => Buffer.from("0123456789abcdef0123456789abcdef", "ascii")
};

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
        { version: 6, name: "virtualization-guest-replay-ledger" }
      ]);
    } finally {
      database.close();
    }
  } finally {
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
  } finally {
    store.close();
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
      for (const name of ["lease_owner_id", "lease_token", "lease_acquired_at_ms", "lease_heartbeat_at_ms", "lease_expires_at_ms", "process_metadata_json", "privileged_payload_json"]) {
        assert.equal(names.has(name), true, `expected migrated Job lease column ${name}`);
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
    assert.equal(admitted.job.state, "queued");
    assert.equal(store.approvalRecord("approval:atomic")?.usedCount, 1);
    assert.throws(
      () => store.admitApprovedJob({
        ...atomicJobAdmissionInput("request-atomic-replay", "nonce-atomic", "job:ignored", "task:test", "task_profile:test"),
        approval: first.approval
      }),
      /identity was already accepted/u
    );

    const retry = store.admitApprovedJob({
      ...atomicJobAdmissionInput("request-atomic-retry", "nonce-atomic-retry", "job:ignored", "task:test", "task_profile:test"),
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
    assert.throws(() => store.admitApprovedJob({ ...conflict, approval: { ...conflict.approval, approvalClass: "trusted_profile" } }), /different job payload/u);
    assert.equal(store.requestRecord("request-atomic-conflict"), undefined);
    assert.equal(store.ownedJob("job:conflict", "principal-1"), undefined);
    assert.equal(store.approvalRecord("approval:atomic-conflict")?.usedCount, 0);
    assert.throws(() => store.admitApprovedJob(conflict), /different job payload/u);
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
    const first = store.createJob(jobInput("job:first", "idem-1"));
    assert.equal(first.reused, false);
    assert.equal(first.job.state, "queued");
    const repeated = store.createJob({ ...jobInput("job:ignored", "idem-1") });
    assert.equal(repeated.reused, true);
    assert.equal(repeated.job.jobId, "job:first");
    assert.throws(
      () => store.createJob({ ...jobInput("job:different", "idem-1"), payloadDigest: "b".repeat(64) }),
      /different job payload/u
    );
    const otherPrincipal = store.createJob({
      ...jobInput("job:other", "idem-1"),
      ownerPrincipalId: "principal-2"
    });
    assert.equal(otherPrincipal.reused, false);
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
    store.close();
    store = new BrokerStore(databasePath);
    assert.deepEqual(store.ownedJob("job:privileged-payload", "principal-1")?.privilegedPayload, privilegedPayload);
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
    store.createJob(jobInput("job:queued-task", "idem-queued-task"));
    store.createJob({
      ...jobInput("job:queued-write", "idem-queued-write"),
      tool: "mac_write_file_atomic",
      targetRef: "path:test-root"
    });
    store.setSwitch("mutations", true, "test", 2);
    assert.equal(store.ownedJob("job:queued-task", "principal-1")?.state, "cancelled");
    assert.equal(store.ownedJob("job:queued-write", "principal-1")?.state, "cancelled");
    assert.equal(store.ownedJob("job:queued-task", "principal-1")?.cancelRequested, true);
    assert.equal(store.auditRows().filter((row) => row.tool === "internal_job_authority_reconcile").length, 2);

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
    assert.deepEqual(store.restartUnknownProcessJobs().map((job) => job.jobId), ["job:task-process-metadata"]);
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
