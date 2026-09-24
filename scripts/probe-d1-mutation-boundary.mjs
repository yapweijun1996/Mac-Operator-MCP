import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ApprovalAuthority,
  Broker,
  BrokerStore,
  EdgeKeyring,
  WorkerFilesystemExecutor,
  approvalPreviewDigest,
  createDefaultPolicy,
  signApprovalIssuance
} from "@mac-operator/broker";
import { canonicalJson, sha256, signRequest } from "@mac-operator/contracts";

const scopes = ["mac.files.write", "mac.project.write", "mac.job.read"];
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
      sessionId: "d1-probe-session",
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

function issueApproval(authority, approvalId, tool, targetKind, targetRef, argumentsValue) {
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
    approvalClass: "trusted_write",
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
    throw new Error(`${label} expected ${expectedClass}`);
  }
}

const directory = await mkdtemp(join(tmpdir(), "mac-operator-d1-mutation-probe-"));
const projectRoot = await realpath(directory);
const databasePath = join(projectRoot, "broker.sqlite");
const writePath = join(projectRoot, "write.txt");
const patchPath = join(projectRoot, "README.txt");
await writeFile(patchPath, "before\n", { mode: 0o600 });
const writeArguments = {
  path: writePath,
  content: "physical-write-content",
  idempotency_key: "d1-atomic-write-1",
  encoding: "utf8",
  create_only: true
};
const patchText = [
  "*** Begin Patch",
  "*** Update File: README.txt",
  "@@",
  "-before",
  "+after",
  "*** End Patch",
  ""
].join("\n");
const patchArguments = { project_root: projectRoot, patch: patchText };
const root = {
  rootId: "d1-probe-root",
  path: projectRoot,
  metadata: true,
  contentRead: true,
  write: true,
  denyRelativePaths: []
};
const store = new BrokerStore(databasePath);
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
  [root],
  [],
  [],
  [projectRoot]
);
const policy = {
  ...basePolicy,
  tools: new Map(basePolicy.tools)
};
policy.tools.set("mac_write_file_atomic", {
  ...policy.tools.get("mac_write_file_atomic"),
  enabled: true
});
policy.tools.set("mac_apply_patch", {
  ...policy.tools.get("mac_apply_patch"),
  enabled: true
});
const filesystemExecutor = new WorkerFilesystemExecutor(4);
const broker = new Broker({
  store,
  policy,
  filesystemExecutor,
  edgeAuthenticationKeys: new EdgeKeyring([{
    edgeId: "edge-1",
    keyId: "edge-key-1",
    key: edgeKey,
    notBeforeMs: now - 60_000,
    expiresAtMs: now + 120_000
  }]),
  now: () => now
});

try {
  const unapproved = await broker.handle(request(
    "mac_write_file_atomic",
    writeArguments,
    "d1-unapproved-write",
    "d1-unapproved-write-nonce"
  ));
  expectFailure(unapproved, "POLICY_DENIED", "unapproved write");

  issueApproval(approvalAuthority, "approval:d1-write", "mac_write_file_atomic", "path", "path:d1-probe-root", writeArguments);
  const writeAttempt = await broker.handle(request(
    "mac_write_file_atomic",
    writeArguments,
    "d1-approved-write",
    "d1-approved-write-nonce"
  ));
  const writeResult = expectSuccess(writeAttempt, "approved write");
  const writeData = writeResult.data;
  if (writeData.created !== true || writeData.sha256 !== sha256(writeArguments.content)) {
    throw new Error("Atomic write readback was not verified");
  }
  const writeJobId = writeData.job_id;

  issueApproval(approvalAuthority, "approval:d1-write-retry", "mac_write_file_atomic", "path", "path:d1-probe-root", writeArguments);
  const retryResult = expectSuccess(await broker.handle(request(
    "mac_write_file_atomic",
    writeArguments,
    "d1-retry-write",
    "d1-retry-write-nonce"
  )), "idempotent write retry");
  if (retryResult.data.job_id !== writeJobId) throw new Error("Write retry did not reuse the existing Job");

  issueApproval(approvalAuthority, "approval:d1-patch", "mac_apply_patch", "project", `project:${projectRoot}`, patchArguments);
  const patchResult = expectSuccess(await broker.handle(request(
    "mac_apply_patch",
    patchArguments,
    "d1-approved-patch",
    "d1-approved-patch-nonce"
  )), "approved patch");
  const patchData = patchResult.data;
  if (patchData.result !== "applied" || JSON.stringify(patchData.changed_paths) !== JSON.stringify(["README.txt"])) {
    throw new Error("Patch readback was not verified");
  }

  const writeStatus = expectSuccess(await broker.handle(request(
    "mac_job_status",
    { job_id: writeJobId, tail_bytes: 1_024 },
    "d1-write-status",
    "d1-write-status-nonce"
  )), "write Job status");
  const patchStatus = expectSuccess(await broker.handle(request(
    "mac_job_status",
    { job_id: patchData.job_id, tail_bytes: 1_024 },
    "d1-patch-status",
    "d1-patch-status-nonce"
  )), "patch Job status");
  if (writeStatus.data.state !== "completed" || patchStatus.data.state !== "completed") {
    throw new Error("Mutation Job status did not reach completed");
  }
  if (await readFile(writePath, "utf8") !== writeArguments.content || await readFile(patchPath, "utf8") !== "after\n") {
    throw new Error("Physical file readback did not match the verified result");
  }

  const auditText = JSON.stringify(store.auditRows());
  if (auditText.includes(writeArguments.content) || auditText.includes(patchText)) {
    throw new Error("Mutation audit contains raw content");
  }
  const temporaryEntries = (await readdir(projectRoot)).filter((entry) => entry.startsWith(".mac-operator-write-"));
  if (temporaryEntries.length !== 0) throw new Error("Atomic mutation temporary files remain");

  console.log(JSON.stringify({
    schema_version: "0.1",
    probe: "d1-mutation-boundary",
    platform: process.platform,
    arch: process.arch,
    physical_temp_root: true,
    approval_issuer: "verified",
    unapproved_write: "POLICY_DENIED",
    atomic_write: { result: writeResult.result_class, verification: writeResult.verification.status, job_state: writeStatus.data.state },
    idempotent_retry_reused_job: true,
    bounded_patch: { result: patchResult.result_class, verification: patchResult.verification.status, job_state: patchStatus.data.state },
    postcondition_readback: "verified",
    audit_raw_content: false,
    temporary_files_remaining: temporaryEntries.length
  }, null, 2));
} finally {
  await broker.close();
  approvalAuthority.dispose();
  approvalKey.fill(0);
  store.close();
  await rm(directory, { recursive: true, force: true });
}
