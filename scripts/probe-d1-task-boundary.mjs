import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import {
  ApprovalAuthority,
  Broker,
  BrokerStore,
  EdgeKeyring,
  SandboxExecTaskRunner,
  TaskProfileRegistry,
  approvalPreviewDigest,
  createDefaultPolicy,
  signApprovalIssuance
} from "@mac-operator/broker";
import { canonicalJson, sha256, signRequest } from "@mac-operator/contracts";

const scopes = ["mac.task.run", "mac.job.read", "mac.job.cancel"];
const edgeKey = randomBytes(32);
const approvalKey = randomBytes(32);
const now = Date.now();

function request(tool, argumentsValue, requestId, nonce) {
  return signRequest({
    protocolVersion: "0.1",
    requestId,
    contractVersion: "0.1",
    tool,
    arguments: argumentsValue,
    principal: {
      principalId: "principal-1",
      sessionId: "d1-task-probe-session",
      issuer: "test-issuer",
      audience: "mac-operator-broker",
      scopes,
      issuedAtMs: now - 1_000,
      expiresAtMs: now + 120_000,
      edgeId: "edge-1"
    },
    timestampMs: now,
    nonce,
    policyAudience: "mac-operator-broker",
    policyVersion: "policy-0.1",
    authenticationKeyId: "edge-key-1"
  }, edgeKey);
}

function issueApproval(authority, approvalId, tool, targetKind, targetRef, approvalClass, argumentsValue) {
  const approval = {
    approvalId,
    approverPrincipalId: "operator-1",
    requestingPrincipalId: "principal-1",
    tool,
    contractVersion: "0.1",
    targetKind,
    targetRef,
    payloadDigest: sha256(canonicalJson(argumentsValue)),
    policyVersion: "policy-0.1",
    approvalClass,
    unattended: false,
    issuedAtMs: now,
    expiresAtMs: now + 120_000
  };
  const suffix = approvalId.replaceAll(":", "-");
  authority.issue(signApprovalIssuance({
    protocolVersion: "0.1",
    requestId: `approval-issue:${suffix}`,
    nonce: `approval-nonce:${suffix}`,
    nonceExpiresAtMs: now + 60_000,
    issuerId: "operator-1",
    keyId: "operator-key-1",
    timestampMs: now,
    approval,
    previewDigest: approvalPreviewDigest(approval)
  }, approvalKey));
}

function expectSuccess(result, label) {
  if (!result.ok) throw new Error(`${label} failed: ${result.result_class}: ${result.error.message}`);
  return result;
}

function expectFailure(result, expectedClass, label) {
  if (result.ok || result.result_class !== expectedClass) {
    throw new Error(`${label} expected ${expectedClass}, received ${result.result_class}`);
  }
}

async function executableDigest(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

async function waitForRunningTask(store, idempotencyKey) {
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const job = store.ownedJobByIdempotencyKey(idempotencyKey, "principal-1");
    if (job?.state === "running" && job.processMetadata?.pid !== undefined) return job;
    await delay(10);
  }
  throw new Error("Task did not expose a running Broker-owned process identity");
}

const directory = await mkdtemp(join(tmpdir(), "mac-operator-d1-task-probe-"));
const taskRoot = await realpath(directory);
const storeDirectory = await mkdtemp(join(tmpdir(), "mac-operator-d1-task-store-"));
const store = new BrokerStore(join(storeDirectory, "broker.sqlite"));
const printfExecutable = "/usr/bin/printf";
const sleepExecutable = "/bin/sleep";
const profiles = [
  {
    schemaVersion: "0.1",
    profile: "d1.printf",
    executable: printfExecutable,
    executableContentSha256: await executableDigest(printfExecutable),
    fixedArgs: ["d1-broker-task"],
    allowedCwdRoots: [taskRoot],
    maxArguments: 0,
    environment: { LANG: "C" },
    filesystemRoots: [taskRoot],
    networkPolicy: "none",
    credentialPolicy: "none",
    processTreePolicy: "single_process",
    sandboxProfile: "deny-default-v0.1",
    timeoutMs: 5_000,
    outputCapBytes: 1_024,
    verificationStrategy: "exit_status_and_declared_task_verification",
    enabled: true
  },
  {
    schemaVersion: "0.1",
    profile: "d1.sleep",
    executable: sleepExecutable,
    executableContentSha256: await executableDigest(sleepExecutable),
    fixedArgs: ["30"],
    allowedCwdRoots: [taskRoot],
    maxArguments: 0,
    environment: { LANG: "C" },
    filesystemRoots: [taskRoot],
    networkPolicy: "none",
    credentialPolicy: "none",
    processTreePolicy: "single_process",
    sandboxProfile: "deny-default-v0.1",
    timeoutMs: 60_000,
    outputCapBytes: 1_024,
    verificationStrategy: "exit_status_and_declared_task_verification",
    enabled: true
  }
];
const taskProfileNames = profiles.map((profile) => profile.profile);
const approvalAuthority = new ApprovalAuthority(store, [{
  issuerId: "operator-1",
  keyId: "operator-key-1",
  key: approvalKey,
  notBeforeMs: now - 60_000,
  expiresAtMs: now + 120_000,
  allowUnattended: false
}], { now: () => now });
const basePolicy = createDefaultPolicy(
  "edge-1",
  true,
  scopes,
  ["edge-key-1"],
  [],
  [],
  [],
  [],
  [],
  taskProfileNames
);
const policy = {
  ...basePolicy,
  tools: new Map(basePolicy.tools)
};
policy.tools.set("mac_task_run", {
  ...policy.tools.get("mac_task_run"),
  enabled: true
});
const runner = new SandboxExecTaskRunner({
  enabled: true,
  hostEvidenceAccepted: true,
  executionBoundary: "system-published",
  systemPublishedExecutableAllowlist: [printfExecutable, sleepExecutable],
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
    evidenceRef: "evidence://2026-09-21-d1-task-boundary",
    executableSelection: "system-published-root-owned-v1"
  }
});
const broker = new Broker({
  store,
  policy,
  taskProfileRegistry: new TaskProfileRegistry(profiles),
  taskRunner: runner,
  edgeAuthenticationKeys: new EdgeKeyring([{
    edgeId: "edge-1",
    keyId: "edge-key-1",
    key: edgeKey,
    notBeforeMs: now - 60_000,
    expiresAtMs: now + 120_000
  }]),
  now: () => now
});

const printfArguments = { profile: "d1.printf", cwd: taskRoot, args: [], async: false };
const sleepArguments = { profile: "d1.sleep", cwd: taskRoot, args: [], async: false };

try {
  if (!runner.available) throw new Error("System-published task runner was not available on the physical host");

  const unapproved = await broker.handle(request(
    "mac_task_run",
    printfArguments,
    "d1-unapproved-task",
    "d1-unapproved-task-nonce"
  ));
  expectFailure(unapproved, "POLICY_DENIED", "unapproved task");

  issueApproval(approvalAuthority, "approval:d1-printf", "mac_task_run", "task_profile", "task_profile:d1.printf", "trusted_profile", printfArguments);
  const printfResult = expectSuccess(await broker.handle(request(
    "mac_task_run",
    printfArguments,
    "d1-printf",
    "d1-printf-nonce"
  )), "approved system-published task");
  if (printfResult.data.stdout !== "d1-broker-task" || printfResult.data.state !== "completed" ||
      printfResult.verification.status !== "verified") {
    throw new Error("Broker task success readback was not verified");
  }
  const printfJob = store.ownedJobByIdempotencyKey("task:d1-printf", "principal-1");
  if (printfJob?.state !== "completed" || printfJob.processMetadata !== undefined) {
    throw new Error("Completed task Job did not clear transient process ownership metadata");
  }

  issueApproval(approvalAuthority, "approval:d1-sleep", "mac_task_run", "task_profile", "task_profile:d1.sleep", "trusted_profile", sleepArguments);
  const sleepPromise = broker.handle(request(
    "mac_task_run",
    sleepArguments,
    "d1-sleep",
    "d1-sleep-nonce"
  ));
  const runningSleepJob = await waitForRunningTask(store, "task:d1-sleep");
  if (runningSleepJob.processMetadata?.ownershipProof !== "sandbox-exec-no-fork-v1") {
    throw new Error("Running task Job did not retain the single-process ownership proof");
  }
  const cancelArguments = { job_id: runningSleepJob.jobId, reason: "d1 physical task cancellation" };
  issueApproval(approvalAuthority, "approval:d1-cancel", "mac_job_cancel", "job", `job:${runningSleepJob.jobId}`, "trusted_write", cancelArguments);
  const cancelResult = expectSuccess(await broker.handle(request(
    "mac_job_cancel",
    cancelArguments,
    "d1-cancel",
    "d1-cancel-nonce"
  )), "task cancellation");
  if (cancelResult.data.new_state !== "running" || cancelResult.data.cancel_requested !== true || cancelResult.data.termination_observed !== false) {
    throw new Error("Task cancellation did not persist the expected active-job cancellation request");
  }
  const sleepResult = await sleepPromise;
  if (sleepResult.ok || !["CANCELLED", "CONFLICT"].includes(sleepResult.result_class)) {
    throw new Error(`Cancelled task request returned an unexpected result: ${JSON.stringify(sleepResult)}`);
  }
  const sleepJob = store.ownedJobByIdempotencyKey("task:d1-sleep", "principal-1");
  if (sleepJob?.state !== "cancelled" || sleepJob.processMetadata !== undefined) {
    throw new Error(`Cancelled task Job did not reach terminal state and clear transient process metadata: ${JSON.stringify({ sleepResult, sleepJob })}`);
  }
  const status = expectSuccess(await broker.handle(request(
    "mac_job_status",
    { job_id: sleepJob.jobId, tail_bytes: 1_024 },
    "d1-sleep-status",
    "d1-sleep-status-nonce"
  )), "cancelled task status");
  if (status.data.state !== "cancelled" || status.data.result_class !== "denied") {
    throw new Error("Cancelled task status readback was not terminal");
  }

  const auditText = JSON.stringify(store.auditRows());
  if (auditText.includes("d1-broker-task") || auditText.includes("d1 physical task cancellation")) {
    throw new Error("Task audit contains raw task output or cancellation reason");
  }

  console.log(JSON.stringify({
    schema_version: "0.1",
    probe: "d1-task-boundary",
    platform: process.platform,
    arch: process.arch,
    physical_system_published_runner: true,
    approval_issuer: "verified",
    unapproved_task: "POLICY_DENIED",
    task_success: {
      result: printfResult.result_class,
      verification: printfResult.verification.status,
      stdout_readback: "verified",
      process_tree_policy: runner.isolationProof.processTreePolicy,
      job_state: printfJob.state
    },
    cancellation: {
      request_result: sleepResult.result_class,
      cancel_result: cancelResult.result_class,
      cancel_requested: cancelResult.data.cancel_requested,
      termination_observed: status.data.state === "cancelled",
      process_identity_recorded: runningSleepJob.processMetadata.pid !== undefined,
      job_state: status.data.state
    },
    sandbox_network: "none",
    protected_persistence_root: "denied-by-default",
    audit_raw_content: false,
    public_task_scope: "disabled"
  }, null, 2));
} finally {
  await broker.close();
  approvalAuthority.dispose();
  approvalKey.fill(0);
  edgeKey.fill(0);
  store.close();
  await rm(directory, { recursive: true, force: true });
  await rm(storeDirectory, { recursive: true, force: true });
}
