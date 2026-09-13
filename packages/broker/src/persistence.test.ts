import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { BrokerStore } from "./persistence.js";

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
    createOnly: true
  } as const;
  let store = new BrokerStore(databasePath);
  store.createJob({ ...jobInput("job:write-metadata", "write-metadata"), writeMetadata: metadata });
  store.startJob("job:write-metadata", "principal-1", 0, 2);
  store.close();
  store = new BrokerStore(databasePath);
  try {
    const recovered = store.ownedJob("job:write-metadata", "principal-1");
    assert.deepEqual(recovered?.writeMetadata, metadata);
    assert.equal(recovered?.stdout, "");
    assert.equal(recovered?.state, "unknown");
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
