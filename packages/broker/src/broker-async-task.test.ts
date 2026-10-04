import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { canonicalJson, sha256, signRequest, type Scope, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { BrokerStore } from "./persistence.js";
import { TaskProfileRegistry, type TaskProfile } from "./task-profile.js";
import type { TaskExecutionControl, TaskExecutionResult, TaskIsolationProof, TaskRunner } from "./task-runner.js";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020").default;
const ajv = new Ajv2020({ strict: true, allErrors: true });
require("ajv-formats").default(ajv);
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
let jobStatusValidator: ReturnType<typeof ajv.compile> | undefined;

const NOW = 1_700_000_000_000;
const archiveKeySource = { keyId: "async-task-test-1", loadKey: () => Buffer.from("0123456789abcdef0123456789abcdef", "ascii") };
const isolationProof: TaskIsolationProof = {
  schemaVersion: "0.1",
  sandboxMechanism: "sandbox-exec",
  sandboxProfile: "deny-default-v0.1",
  filesystem: "enforced",
  network: "enforced",
  credentials: "isolated",
  persistence: "isolated",
  credentialIsolation: "sandbox-exec-empty-env-deny-secret-zones-v1",
  processTree: "owned",
  processTreePolicy: "single_process",
  evidenceRef: "test://async-task-isolation"
};

function terminal(overrides: Partial<TaskExecutionResult> = {}): TaskExecutionResult {
  return {
    state: "completed", resultClass: "SUCCEEDED", exitCode: 0,
    stdout: "finished safely", stderr: "", truncated: false,
    durationMs: 1, verification: { status: "verified" }, ...overrides
  };
}

function latch() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => { release = resolve; });
  return { promise, release };
}

async function setup(run: TaskRunner["run"], closeRunner?: () => Promise<void>, storeOptions?: ConstructorParameters<typeof BrokerStore>[1]) {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-async-task-"));
  const root = await realpath(directory);
  const key = randomBytes(32);
  let store = new BrokerStore(join(root, "broker.sqlite"), storeOptions);
  const scopes: Scope[] = ["mac.task.run", "mac.control.read", "mac.job.read", "mac.job.cancel"];
  const basePolicy = createDefaultPolicy("edge-1", true, scopes, ["edge-key-1"],
    [{ rootId: "task-root", path: root, metadata: true, contentRead: true, denyRelativePaths: [] }],
    [], [], [], [], ["tests.echo"]);
  const policy = { ...basePolicy, tools: new Map(basePolicy.tools).set("mac_task_run", { ...basePolicy.tools.get("mac_task_run")!, enabled: true }) };
  const profile: TaskProfile = {
    schemaVersion: "0.1", profile: "tests.echo", executable: "/bin/echo",
    allowedCwdRoots: [root], allowedArgumentPattern: "^[a-z]{1,32}$", maxArguments: 1,
    environment: { LANG: "C" }, filesystemRoots: [root], networkPolicy: "none",
    sandboxProfile: "deny-default-v0.1", timeoutMs: 1_000, outputCapBytes: 1_024,
    verificationStrategy: "exit_status_and_declared_task_verification", enabled: true
  };
  const runner: TaskRunner = {
    available: true, publicEnablement: "production", mechanism: "sandbox-exec", isolationProof, run,
    ...(closeRunner === undefined ? {} : { close: closeRunner })
  };
  const broker = new Broker({
    store, policy, taskRunner: runner, taskProfileRegistry: new TaskProfileRegistry([profile]),
    edgeAuthenticationKeys: new EdgeKeyring([{ edgeId: "edge-1", keyId: "edge-key-1", key, notBeforeMs: NOW - 60_000, expiresAtMs: NOW + 120_000 }]), now: () => NOW
  });
  const argumentsValue = { profile: "tests.echo", cwd: root, args: ["safe"], async: true, idempotency_key: "async-key", task_id: "synthetic-task", max_runtime: 500 };
  function request(id: string, tool = "mac_task_run", args: Record<string, unknown> = argumentsValue): UnsignedBrokerRequest {
    return {
      protocolVersion: "0.1", requestId: id, contractVersion: "0.1", tool, arguments: args,
      principal: {
        principalId: "principal-1", sessionId: "session-1", issuer: "test-issuer", audience: "mac-operator-broker",
        scopes, issuedAtMs: NOW - 1_000, expiresAtMs: NOW + 60_000, edgeId: "edge-1"
      },
      timestampMs: NOW, nonce: `nonce-${id}`, policyAudience: "mac-operator-broker", policyVersion: "policy-0.1", authenticationKeyId: "edge-key-1"
    };
  }
  function approve(args: Record<string, unknown> = argumentsValue, id = "approval:async-first") {
    store.issueApproval({
      approvalId: id, approverPrincipalId: "operator-1", requestingPrincipalId: "principal-1",
      tool: "mac_task_run", contractVersion: "0.1", targetKind: "task_profile", targetRef: "task_profile:tests.echo",
      payloadDigest: sha256(canonicalJson(args)), policyVersion: "policy-0.1", approvalClass: "trusted_profile",
      unattended: false, issuedAtMs: NOW - 1_000, expiresAtMs: NOW + 60_000
    });
  }
  return {
    root, broker, key, argumentsValue, request, approve,
    get store() { return store; },
    handle: (id: string, tool?: string, args?: Record<string, unknown>) => broker.handle(signRequest(request(id, tool, args), key)),
    reopen: () => { store.close(); store = new BrokerStore(join(root, "broker.sqlite")); return store; },
    close: async () => { await broker.close(); store.close(); await rm(root, { recursive: true, force: true }); }
  };
}

type JobStatusData = { state: string; result_class: string; outcome_class?: string };

/** Read mac_job_status through the Broker and require the result to satisfy the published output schema. */
async function jobStatus(fixture: Awaited<ReturnType<typeof setup>>, requestId: string, jobId: string): Promise<JobStatusData> {
  const result = await fixture.handle(requestId, "mac_job_status", { job_id: jobId, tail_bytes: 1_024 });
  assert.ok(result.ok, JSON.stringify(result));
  jobStatusValidator ??= ajv.compile(JSON.parse(await readFile(join(repositoryRoot, "tool-contracts", "mac_job_status.json"), "utf8")).output_schema);
  assert.equal(jobStatusValidator(result), true, ajv.errorsText(jobStatusValidator.errors));
  return result.data as JobStatusData;
}

async function settle(fixture: Awaited<ReturnType<typeof setup>>, requestId: string): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (fixture.store.requestRecord(requestId)?.state !== "RUNNING") return;
    await new Promise<void>((resolve) => setTimeout(resolve, 5));
  }
  assert.fail("Managed task did not settle");
}

test("async task returns a bounded job receipt while its runner is pending", async () => {
  const started = latch();
  const finish = latch();
  const fixture = await setup(async (profile, control) => {
    assert.equal(profile.cwd, fixture.root);
    assert.equal(profile.process.timeoutMs, 500);
    assert.equal(control.timeoutMs, 500);
    started.release(); await finish.promise; return terminal();
  }, async () => { finish.release(); });
  try {
    fixture.approve();
    const result = await fixture.handle("async-first");
    assert.equal(result.ok, true, JSON.stringify(result));
    await started.promise;
    if (!result.ok) return;
    assert.deepEqual(result.data, {
      profile: "tests.echo", cwd: fixture.root, state: "running",
      job_id: fixture.store.requestRecord("async-first")?.jobId,
      accepted: true, reused: false, task_id: "synthetic-task"
    });
    assert.equal(JSON.stringify(result).includes("stdout"), false);
    assert.equal(result.verification.status, "accepted");
    assert.equal(fixture.store.requestRecord("async-first")?.state, "RUNNING");
    finish.release(); await settle(fixture, "async-first");
    const jobId = (result.data as { job_id: string }).job_id;
    assert.equal(fixture.store.ownedJob(jobId, "principal-1")?.state, "completed");
    const status = await fixture.handle("async-status", "mac_job_status", { job_id: jobId, tail_bytes: 1_024 });
    assert.equal(status.ok, true, JSON.stringify(status));
    if (status.ok) assert.equal((status.data as { stdout: string }).stdout, "finished safely");
    assert.deepEqual(fixture.store.executionAudit("principal-1", { requestId: "async-first" }).map((event) => event.result_class), ["SUCCEEDED", "INTENT_RECORDED", "AUTHORIZED"]);
    assert.equal(fixture.store.executionAudit("other-owner").length, 0);
  } finally { finish.release(); await fixture.close(); }
});

test("pending and completed task retries reuse one Job and one approval", async () => {
  const started = latch(); const finish = latch(); let calls = 0;
  const fixture = await setup(async () => { calls += 1; started.release(); await finish.promise; return terminal(); }, async () => { finish.release(); });
  try {
    fixture.approve();
    const first = await fixture.handle("retry-first"); await started.promise;
    const pending = await fixture.handle("retry-pending");
    assert.equal(first.ok, true, JSON.stringify(first)); assert.equal(pending.ok, true, JSON.stringify(pending));
    if (!first.ok || !pending.ok) return;
    assert.equal((pending.data as { reused: boolean }).reused, true);
    assert.equal((pending.data as { job_id: string }).job_id, (first.data as { job_id: string }).job_id);
    assert.equal(calls, 1);
    assert.equal(fixture.store.approvalRecord("approval:async-first")?.usedCount, 1);
    finish.release(); await settle(fixture, "retry-first");
    const completed = await fixture.handle("retry-completed");
    assert.equal(completed.ok, true, JSON.stringify(completed));
    if (completed.ok) assert.equal((completed.data as { state: string }).state, "completed");
    assert.equal(calls, 1);
    assert.equal(fixture.store.requestRecord("retry-pending")?.resultClass, "IDEMPOTENT_REUSE");
    await fixture.broker.close();
    const reopened = fixture.reopen();
    assert.equal(reopened.requestRecord("retry-pending")?.resultClass, "IDEMPOTENT_REUSE");
    assert.equal(reopened.ownedJob((first.data as { job_id: string }).job_id, "principal-1")?.state, "completed");
  } finally { finish.release(); await fixture.close(); }
});

test("task retries reject changed payload without consuming another approval", async () => {
  const started = latch(); const finish = latch(); let calls = 0;
  const fixture = await setup(async () => { calls += 1; started.release(); await finish.promise; return terminal(); }, async () => { finish.release(); });
  try {
    fixture.approve(); await fixture.handle("conflict-first"); await started.promise;
    const changed = { ...fixture.argumentsValue, args: ["changed"] };
    fixture.approve(changed, "approval:async-conflict");
    const conflict = await fixture.handle("conflict-second", "mac_task_run", changed);
    assert.equal(conflict.ok, false); assert.equal(conflict.result_class, "CONFLICT");
    assert.equal(fixture.store.approvalRecord("approval:async-conflict")?.usedCount, 0);
    assert.equal(calls, 1);
  } finally { finish.release(); await fixture.close(); }
});

test("async task cancellation uses Broker Job control and verified terminal readback", async () => {
  const started = latch(); const finish = latch(); let taskControl: TaskExecutionControl | undefined;
  const fixture = await setup(async (_profile, control) => {
    taskControl = control; started.release(); await finish.promise;
    assert.equal(control.shouldCancel(), true);
    return terminal({ state: "cancelled", resultClass: "CANCELLED", exitCode: null, stdout: "", verification: { status: "unknown" } });
  }, async () => { finish.release(); });
  try {
    fixture.approve(); const first = await fixture.handle("cancel-first"); await started.promise;
    assert.equal(first.ok, true, JSON.stringify(first)); if (!first.ok) return;
    const jobId = (first.data as { job_id: string }).job_id;
    const cancellationArguments = { job_id: jobId, reason: "synthetic-task-stop" };
    fixture.store.issueApproval({
      approvalId: "approval:async-cancel", approverPrincipalId: "operator-1", requestingPrincipalId: "principal-1",
      tool: "mac_job_cancel", contractVersion: "0.1", targetKind: "job", targetRef: `job:${jobId}`,
      payloadDigest: sha256(canonicalJson(cancellationArguments)), policyVersion: "policy-0.1", approvalClass: "trusted_write",
      unattended: false, issuedAtMs: NOW - 1_000, expiresAtMs: NOW + 60_000
    });
    const cancellation = await fixture.handle("cancel-job", "mac_job_cancel", cancellationArguments);
    assert.equal(cancellation.ok, true, JSON.stringify(cancellation));
    assert.equal(taskControl?.shouldCancel(), true);
    finish.release(); await settle(fixture, "cancel-first");
    assert.equal(fixture.store.ownedJob(jobId, "principal-1")?.state, "cancelled");
    assert.equal(fixture.store.requestRecord("cancel-first")?.state, "CANCELLED");
  } finally { finish.release(); await fixture.close(); }
});

test("Broker close drains admitted async tasks before the store can be closed", async () => {
  const started = latch(); const finish = latch(); let runnerSettled = false;
  const fixture = await setup(async (_profile, control) => {
    started.release(); await finish.promise;
    assert.equal(control.shouldCancel(), true); runnerSettled = true;
    return terminal({ state: "cancelled", resultClass: "CANCELLED", exitCode: null, verification: { status: "unknown" } });
  }, async () => { finish.release(); });
  try {
    fixture.approve(); await fixture.handle("close-first"); await started.promise;
    await fixture.broker.close();
    assert.equal(runnerSettled, true);
    assert.notEqual(fixture.store.requestRecord("close-first")?.state, "RUNNING");
    const jobId = fixture.store.requestRecord("close-first")?.jobId;
    assert.ok(jobId); assert.notEqual(fixture.store.ownedJob(jobId, "principal-1")?.state, "running");
  } finally { finish.release(); await fixture.close(); }
});

for (const scenario of [
  { name: "failure", result: terminal({ state: "failed", resultClass: "EXECUTION_FAILED", exitCode: 1, verification: { status: "verified" } }),
    expected: "FAILED", outcome: "EXECUTION_FAILED", jobResultClass: "failed" },
  { name: "timeout", result: terminal({ state: "timed_out", resultClass: "TIMEOUT", exitCode: null, durationMs: 501, verification: { status: "unknown" } }),
    expected: "TIMED_OUT", outcome: "TIMEOUT", jobResultClass: "failed" },
  { name: "output-limit", result: terminal({ state: "failed", resultClass: "OUTPUT_LIMIT", exitCode: null, truncated: true, verification: { status: "unknown" } }),
    expected: "FAILED", outcome: "OUTPUT_LIMIT", jobResultClass: "failed" },
  { name: "verification-failed", result: terminal({ verification: { status: "failed" } }),
    expected: "VERIFICATION_FAILED", outcome: "VERIFICATION_FAILED", jobResultClass: "verification_failed" }
]) {
  test(`async task ${scenario.name} is persisted and remains inspectable`, async () => {
    const fixture = await setup(async () => scenario.result);
    try {
      fixture.approve(); const result = await fixture.handle(`async-${scenario.name}`);
      assert.equal(result.ok, true, JSON.stringify(result)); await settle(fixture, `async-${scenario.name}`);
      assert.equal(fixture.store.requestRecord(`async-${scenario.name}`)?.state, scenario.expected);
      const jobId = fixture.store.requestRecord(`async-${scenario.name}`)?.jobId;
      assert.ok(jobId); assert.equal(fixture.store.ownedJob(jobId, "principal-1")?.state, "failed");
      const status = await jobStatus(fixture, `async-${scenario.name}-status`, jobId);
      assert.equal(status.state, "failed"); assert.equal(status.result_class, scenario.jobResultClass);
      assert.equal(status.outcome_class, scenario.outcome);
      const retry = await fixture.handle(`async-${scenario.name}-retry`);
      assert.equal(retry.ok, true, JSON.stringify(retry));
      if (retry.ok) assert.equal((retry.data as { state: string }).state, "failed");
      assert.equal((await jobStatus(fixture, `async-${scenario.name}-status-retry`, jobId)).outcome_class, scenario.outcome);
      await fixture.broker.close(); fixture.reopen();
      assert.equal(fixture.store.requestRecord(`async-${scenario.name}-retry`)?.resultClass, "IDEMPOTENT_REUSE");
    } finally { await fixture.close(); }
  });
}

test("an archived failed task Job still reports its outcome_class from the request tombstone", async () => {
  const timedOut = terminal({ state: "timed_out", resultClass: "TIMEOUT", exitCode: null, durationMs: 501, verification: { status: "unknown" } });
  const fixture = await setup(async () => timedOut, undefined, { runtimeFence: true });
  try {
    fixture.approve(); const result = await fixture.handle("archive-timeout");
    assert.equal(result.ok, true, JSON.stringify(result)); await settle(fixture, "archive-timeout");
    const jobId = fixture.store.requestRecord("archive-timeout")?.jobId;
    assert.ok(jobId);
    await fixture.store.rotateLedgerArchive(fixture.root, { keySource: archiveKeySource, nowMs: NOW + 10_000, retainRequestCount: 0, retainJobCount: 0, minAgeMs: 0 });
    assert.equal(fixture.store.ownedJob(jobId, "principal-1"), undefined);
    assert.equal(fixture.store.requestRecord("archive-timeout"), undefined);
    const status = await jobStatus(fixture, "archive-timeout-status", jobId);
    assert.equal(status.state, "failed"); assert.equal(status.result_class, "failed"); assert.equal(status.outcome_class, "TIMEOUT");
  } finally { await fixture.close(); }
});

test("mac_job_status reports no outcome_class for Jobs that did not fail", async () => {
  const fixture = await setup(async () => terminal());
  try {
    fixture.approve(); await fixture.handle("plain-success"); await settle(fixture, "plain-success");
    const create = (name: string) => fixture.store.createJob({
      jobId: `job:plain-${name}`, ownerPrincipalId: "principal-1", ownerSessionId: "session-1", tool: "mac_task_run",
      targetRef: "task_profile:tests.echo", policyVersion: "policy-0.1", payloadDigest: "a".repeat(64),
      idempotencyKey: `plain-${name}`, createdAtMs: NOW - 5_000
    });
    create("queued");
    create("cancelled"); fixture.store.requestJobCancellation("job:plain-cancelled", "principal-1", "setup", NOW - 4_000);
    create("unknown"); fixture.store.startJob("job:plain-unknown", "principal-1", 0, NOW - 4_000);
    fixture.store.finishJob("job:plain-unknown", "principal-1", 1, { state: "unknown", resultClass: "unknown", finishedAtMs: NOW - 3_000 });
    for (const [state, jobId] of [
      ["completed", fixture.store.requestRecord("plain-success")?.jobId], ["queued", "job:plain-queued"],
      ["cancelled", "job:plain-cancelled"], ["unknown", "job:plain-unknown"]
    ] as const) {
      assert.ok(jobId);
      const status = await jobStatus(fixture, `plain-status-${state}`, jobId);
      assert.equal(status.state, state); assert.equal("outcome_class" in status, false, state);
    }
  } finally { await fixture.close(); }
});

test("task and audit inputs reject malformed limits and caller shell fields", async () => {
  let calls = 0;
  const fixture = await setup(async () => { calls += 1; return terminal(); });
  try {
    for (const [index, overrides] of [
      { max_runtime: 0 }, { max_runtime: 600_001 }, { max_runtime: 1.5 },
      { task_id: "../escape" }, { idempotency_key: "" }, { command: "sudo sh" }
    ].entries()) {
      const result = await fixture.handle(`malformed-${index}`, "mac_task_run", { ...fixture.argumentsValue, ...overrides });
      assert.equal(result.ok, false); assert.equal(result.result_class, "PRECONDITION_FAILED");
    }
    assert.equal(calls, 0);
    assert.throws(() => fixture.store.executionAudit("principal-1", { limit: 101 }), /malformed/u);
    assert.throws(() => fixture.store.executionAudit("principal-1", { project: "/tmp/../escape" }), /malformed/u);
    let accessed = false;
    const accessorFilters = Object.defineProperty({}, "limit", { enumerable: true, get: () => { accessed = true; return 50; } });
    assert.throws(() => fixture.store.executionAudit("principal-1", accessorFilters), /malformed/u);
    assert.equal(accessed, false);
    assert.throws(() => fixture.store.executionAudit("principal-1", { requestId: { toString() { accessed = true; return "request"; } } } as never), /malformed/u);
    assert.equal(accessed, false);
  } finally { await fixture.close(); }
});

test("all development task tools retain process ownership, restart recovery, and quarantine", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-task-alias-recovery-"));
  const databasePath = join(directory, "broker.sqlite");
  let store = new BrokerStore(databasePath);
  try {
    for (const [index, tool] of ["mac_task_run", "mac_test_run", "mac_build_run", "mac_codex_run"].entries()) {
      const jobId = `job:alias-process-${index}`;
      store.createJob({
        jobId, ownerPrincipalId: "principal-1", ownerSessionId: "session-1", tool,
        targetRef: "task_profile:tests.echo", policyVersion: "policy-0.1", payloadDigest: "a".repeat(64),
        idempotencyKey: `alias-process-${index}`, createdAtMs: NOW
      });
      const lease = { ownerId: "broker:alias-recovery", token: `lease:alias-recovery-${index}`, expiresAtMs: NOW + 30_000 };
      const running = store.startJob(jobId, "principal-1", 0, NOW + 1, lease);
      store.recordJobProcessOwnership(jobId, "principal-1", running.revision, {
        pid: 10_000 + index, processGroupId: 10_000 + index, startTimeMicros: 987654321 + index,
        taskDescriptorDigest: "b".repeat(64), recordedAtMs: NOW + 2, descendants: []
      }, lease, NOW + 2);
    }
    store.close(); store = new BrokerStore(databasePath);
    const recovered = store.unresolvedTaskProcessJobs();
    assert.equal(recovered.length, 4);
    assert.ok(recovered.every((job) => job.state === "unknown" && job.cancelRequested === true && job.processMetadata !== undefined));
    assert.equal(store.hasUnresolvedHostTaskExecution(), true);
  } finally { store.close(); await rm(directory, { recursive: true, force: true }); }
});

test("task aliases share kill-switch cancellation and authenticated guest recovery classification", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-task-alias-guest-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    for (const [index, tool] of ["mac_task_run", "mac_test_run", "mac_build_run", "mac_codex_run"].entries()) {
      for (const kind of ["queued", "guest"]) {
        const jobId = `job:alias-${kind}-${index}`;
        store.createJob({
          jobId, ownerPrincipalId: "principal-1", ownerSessionId: "session-1", tool,
          targetRef: "task_profile:tests.echo", policyVersion: "policy-0.1", payloadDigest: "a".repeat(64),
          idempotencyKey: `alias-${kind}-${index}`, createdAtMs: NOW
        });
        if (kind === "guest") {
          const lease = { ownerId: "broker:alias-guest", token: `lease:alias-guest-identity-${index}`, expiresAtMs: NOW + 30_000 };
          const running = store.startJob(jobId, "principal-1", 0, NOW + 1, lease);
          store.recordJobGuestRequest(jobId, "principal-1", running.revision, {
            requestId: `request:guest-${index}-1234567890abcdef`, nonce: `guest-nonce-${index}-1234567890abcdef`,
            requestDigest: "b".repeat(64), guestIdentity: { imageSha256: "c".repeat(64), runtimeVersion: "macos-guest-1" },
            profileDigest: "d".repeat(64), taskDigest: "e".repeat(64), timeoutMs: 500, outputCapBytes: 1_024, recordedAtMs: NOW + 2
          }, lease, NOW + 2);
        }
      }
    }
    store.setSwitch("process", true, "synthetic-stop", NOW + 3);
    for (let index = 0; index < 4; index += 1) assert.equal(store.ownedJob(`job:alias-queued-${index}`, "principal-1")?.state, "cancelled");
    assert.equal(store.reconcileInterruptedJobs(NOW + 4).runningUnknown, 4);
    assert.equal(store.restartUnknownGuestJobs().length, 4);
    assert.equal(store.hasUnresolvedHostTaskExecution(), false);
  } finally { store.close(); await rm(directory, { recursive: true, force: true }); }
});

test("project Job pinning checks every owner and audit lookup includes prior project records", async () => {
  const fixture = await setup(async () => terminal());
  try {
    fixture.store.createJob({
      jobId: "job:other-owner-project", ownerPrincipalId: "another-owner", ownerSessionId: "other-session",
      tool: "mac_test_run", targetRef: `project:${fixture.root}`, policyVersion: "policy-0.1",
      payloadDigest: "a".repeat(64), idempotencyKey: "other-owner-project", createdAtMs: NOW
    });
    assert.equal(fixture.store.hasActiveProjectJobs(fixture.root), true);
    assert.equal(fixture.store.hasActiveProjectJobs(`${fixture.root}-other`), false);
    fixture.store.requestJobCancellation("job:other-owner-project", "another-owner", "synthetic-stop", NOW);
    assert.equal(fixture.store.hasActiveProjectJobs(fixture.root), false);
    fixture.store.createJob({
      jobId: "job:unknown-project", ownerPrincipalId: "another-owner", ownerSessionId: "other-session",
      tool: "mac_build_run", targetRef: `project:${fixture.root}`, policyVersion: "policy-0.1",
      payloadDigest: "a".repeat(64), idempotencyKey: "unknown-project", createdAtMs: NOW
    });
    fixture.store.startJob("job:unknown-project", "another-owner", 0, NOW);
    fixture.store.reconcileInterruptedJobs(NOW);
    assert.equal(fixture.store.hasActiveProjectJobs(fixture.root), true);
    fixture.store.appendAudit({
      requestId: "old-project-status", principalId: "principal-1", tool: "mac_git_status",
      eventType: "completion", decision: "allow", resultClass: "SUCCEEDED",
      targetRef: `project:${fixture.root}`, policyVersion: "policy-0.1", evidence: {}, timestampMs: NOW
    });
    assert.equal(fixture.store.executionAudit("principal-1", { project: fixture.root })[0]?.request_id, "old-project-status");
    assert.throws(() => fixture.store.hasActiveProjectJobs(`${fixture.root}/../escape`), /malformed/u);
  } finally { await fixture.close(); }
});

test("project pinning Jobs name only the caller's own Jobs, worst first, and only count the rest", async () => {
  const fixture = await setup(async () => terminal());
  try {
    const pin = (jobId: string, owner: string, createdAtMs: number) => fixture.store.createJob({
      jobId, ownerPrincipalId: owner, ownerSessionId: `${owner}-session`, tool: "mac_test_run", targetRef: `project:${fixture.root}`,
      policyVersion: "policy-0.1", payloadDigest: "a".repeat(64), idempotencyKey: jobId, createdAtMs
    });
    assert.deepEqual(fixture.store.projectPinningJobs([fixture.root], "principal-1"), { own: [], others: 0 });
    pin("job:other", "another-owner", NOW);
    assert.deepEqual(fixture.store.projectPinningJobs([fixture.root], "principal-1"), { own: [], others: 1 });
    fixture.store.requestJobCancellation("job:other", "another-owner", "synthetic-stop", NOW);
    pin("job:unknown", "principal-1", NOW + 1);
    fixture.store.startJob("job:unknown", "principal-1", 0, NOW + 1);
    fixture.store.reconcileInterruptedJobs(NOW + 1);
    pin("job:running", "principal-1", NOW + 2);
    fixture.store.startJob("job:running", "principal-1", 0, NOW + 2);
    pin("job:queued-1", "principal-1", NOW + 3);
    pin("job:queued-2", "principal-1", NOW + 4);
    pin("job:another", "another-owner", NOW + 5);
    const pinning = fixture.store.projectPinningJobs([fixture.root], "principal-1");
    assert.deepEqual(pinning, { own: [
      { jobId: "job:unknown", tool: "mac_test_run", state: "unknown" },
      { jobId: "job:running", tool: "mac_test_run", state: "running" },
      { jobId: "job:queued-1", tool: "mac_test_run", state: "queued" }], others: 2 });
    assert.deepEqual(fixture.store.projectPinningJobs([fixture.root, fixture.root, `${fixture.root}-other`], "principal-1"), pinning);
    assert.deepEqual(fixture.store.projectPinningJobs([`${fixture.root}-other`], "principal-1"), { own: [], others: 0 });
    assert.equal(fixture.store.hasActiveProjectJobs(fixture.root), true);
    assert.throws(() => fixture.store.projectPinningJobs([`${fixture.root}/../escape`], "principal-1"), /malformed/u);
  } finally { await fixture.close(); }
});
