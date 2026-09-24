import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  Broker,
  BrokerStore,
  EdgeKeyring,
  ProcessSupervisor,
  SandboxExecTaskRunner,
  TaskProfileRegistry,
  createDefaultPolicy,
  taskDescriptorDigest
} from "@mac-operator/broker";

async function executableDigest(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

async function waitForPersistedProcess(store, jobId) {
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const job = store.ownedJob(jobId, "principal-1");
    if (job?.state === "running" && job.processMetadata?.pid !== undefined) return job;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("Task process ownership was not persisted before the recovery handoff");
}

const taskDirectory = await mkdtemp(join(tmpdir(), "mac-operator-d1-task-recovery-root-"));
const taskRoot = await realpath(taskDirectory);
const storeDirectory = await mkdtemp(join(tmpdir(), "mac-operator-d1-task-recovery-store-"));
const databasePath = join(storeDirectory, "broker.sqlite");
const sleepExecutable = "/bin/sleep";
const now = Date.now();
const profile = {
  schemaVersion: "0.1",
  profile: "d1.recovery.sleep",
  executable: sleepExecutable,
  executableContentSha256: await executableDigest(sleepExecutable),
  fixedArgs: ["30"],
  allowedCwdRoots: [taskRoot],
  maxArguments: 0,
  environment: { LANG: "C" },
  filesystemRoots: [taskRoot],
  networkPolicy: "none",
  networkAllowlist: [],
  credentialPolicy: "none",
  processTreePolicy: "single_process",
  sandboxProfile: "deny-default-v0.1",
  timeoutMs: 60_000,
  outputCapBytes: 1_024,
  verificationStrategy: "exit_status_and_declared_task_verification",
  enabled: true
};
const policy = createDefaultPolicy("edge-1", true, ["mac.control.read"]);
const edgeKey = randomBytes(32);
const recoverySupervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
const runner = new SandboxExecTaskRunner({
  enabled: true,
  hostEvidenceAccepted: true,
  executionBoundary: "system-published",
  systemPublishedExecutableAllowlist: [sleepExecutable],
  systemPublishedExecutablePathAccepted: true,
  allowedEnvironmentKeys: ["LANG"],
  protectedFilesystemRoots: [storeDirectory],
  isolationProof: {
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
    evidenceRef: "evidence://2026-09-21-d1-task-recovery-boundary",
    executableSelection: "system-published-root-owned-v1"
  }
});
let store = new BrokerStore(databasePath);
let recoveryBroker;
let running;
try {
  if (process.platform !== "darwin" || !runner.available) {
    throw new Error("The physical system-published task runner is not available");
  }
  const registry = new TaskProfileRegistry([profile]);
  const resolved = await registry.resolve({ profile: profile.profile, cwd: taskRoot, args: [] });
  const jobId = "job:d1-task-recovery";
  const lease = {
    ownerId: "broker:d1-recovery-probe",
    token: "lease:d1-recovery-probe-1234",
    expiresAtMs: now + 30_000
  };
  store.createJob({
    jobId,
    ownerPrincipalId: "principal-1",
    ownerSessionId: "session-1",
    tool: "mac_task_run",
    targetRef: `task_profile:${profile.profile}`,
    policyVersion: policy.version,
    payloadDigest: "a".repeat(64),
    idempotencyKey: "d1-task-recovery",
    createdAtMs: now
  });
  const started = store.startJob(jobId, "principal-1", 0, now, lease);
  running = runner.run(resolved, {
    timeoutMs: profile.timeoutMs,
    shouldCancel: () => false,
    onProcessStarted: (snapshot) => {
      const recordedAtMs = Date.now();
      store.recordJobProcessOwnership(
        jobId,
        "principal-1",
        started.revision,
        {
          ...snapshot.identity,
          recordedAtMs,
          taskDescriptorDigest: taskDescriptorDigest(resolved),
          ...(snapshot.ownershipProof === undefined ? {} : { ownershipProof: snapshot.ownershipProof }),
          descendants: snapshot.descendants.map((descendant) => ({ ...descendant }))
        },
        lease,
        recordedAtMs
      );
    }
  });
  const runningJob = await waitForPersistedProcess(store, jobId);
  const capturedPid = runningJob.processMetadata?.pid;
  const capturedStartTime = runningJob.processMetadata?.startTimeMicros;
  store.close();
  store = new BrokerStore(databasePath);
  const restartedJob = store.ownedJob(jobId, "principal-1");
  if (restartedJob?.state !== "unknown" || restartedJob.processMetadata?.pid !== capturedPid) {
    throw new Error("Broker restart did not preserve the exact unknown task process identity");
  }
  recoveryBroker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: new EdgeKeyring([{
      edgeId: "edge-1",
      keyId: "edge-key-1",
      key: edgeKey,
      notBeforeMs: now - 60_000,
      expiresAtMs: now + 120_000
    }]),
    processSupervisor: recoverySupervisor,
    now: () => Date.now()
  });
  const recovery = await recoveryBroker.reconcileRestartedTaskProcesses();
  if (recovery.inspected !== 1 || recovery.drained !== 1 || recovery.absent !== 0 ||
      recovery.identityMismatch !== 0 || recovery.unknown !== 0) {
    throw new Error(`Unexpected process recovery result: ${JSON.stringify(recovery)}`);
  }
  const afterRecovery = store.ownedJob(jobId, "principal-1");
  if (afterRecovery?.state !== "unknown" || afterRecovery.processMetadata?.pid !== capturedPid ||
      afterRecovery.processMetadata?.startTimeMicros !== capturedStartTime) {
    throw new Error("Task recovery changed the unresolved Job or lost the persisted process identity");
  }
  const auditResult = store.auditEventResult(`job-process-recovery-${jobId}-${afterRecovery.revision}`, "completion");
  if (auditResult !== "PROCESS_DRAINED") {
    throw new Error(`Task recovery audit readback was not PROCESS_DRAINED: ${auditResult ?? "missing"}`);
  }
  const taskResult = await running;
  if (taskResult.state !== "unknown" && taskResult.state !== "cancelled") {
    throw new Error(`Original task did not observe the external recovery termination: ${taskResult.state}`);
  }
  console.log(JSON.stringify({
    schema_version: "0.1",
    probe: "d1-task-recovery-boundary",
    platform: process.platform,
    arch: process.arch,
    physical_system_published_runner: true,
    broker_restart_readback: "verified",
    exact_pid_start_time_binding: "verified",
    recovery: {
      inspected: recovery.inspected,
      drained: recovery.drained,
      identity_mismatch: recovery.identityMismatch,
      unknown: recovery.unknown
    },
    job_after_recovery: "unknown",
    task_was_not_replayed: true,
    audit_result: auditResult,
    public_task_scope: "disabled"
  }, null, 2));
} finally {
  await recoveryBroker?.close().catch(() => undefined);
  await runner.close().catch(() => undefined);
  await running?.catch(() => undefined);
  edgeKey.fill(0);
  store.close();
  await rm(taskDirectory, { recursive: true, force: true });
  await rm(storeDirectory, { recursive: true, force: true });
}
