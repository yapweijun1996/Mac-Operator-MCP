import { execFile as execFileCallback } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { promisify } from "node:util";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ApprovalAuthority,
  Broker,
  BrokerStore,
  EdgeKeyring,
  createDefaultPolicy,
  approvalPreviewDigest,
  signApprovalIssuance
} from "@mac-operator/broker";
import { canonicalJson, sha256, signRequest } from "@mac-operator/contracts";

const execFile = promisify(execFileCallback);
const GIT = "/usr/bin/git";
const scopes = ["mac.git.write", "mac.job.read"];
const edgeKey = randomBytes(32);
const approvalKey = randomBytes(32);
const now = Date.now();
const gitEnvironment = {
  PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
  HOME: "/var/empty",
  LANG: "C",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_NO_REPLACE_OBJECTS: "1",
  GIT_TERMINAL_PROMPT: "0",
  GIT_OPTIONAL_LOCKS: "0"
};

async function runFixtureGit(cwd, args) {
  return execFile(GIT, args, {
    cwd,
    env: gitEnvironment,
    shell: false,
    maxBuffer: 256 * 1024,
    timeout: 5_000,
    windowsHide: true
  });
}

function request(tool, argumentsValue, requestId, nonce) {
  return signRequest({
    protocolVersion: "0.1",
    requestId,
    contractVersion: "0.1",
    tool,
    arguments: argumentsValue,
    principal: {
      principalId: "principal-1",
      sessionId: "d1-git-probe-session",
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

function issueApproval(authority, approvalId, tool, targetRef, argumentsValue) {
  const approval = {
    approvalId,
    approverPrincipalId: "operator-1",
    requestingPrincipalId: "principal-1",
    tool,
    contractVersion: "0.1",
    targetKind: "project",
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
    throw new Error(`${label} expected ${expectedClass}, received ${result.result_class}`);
  }
}

async function jobStatus(broker, jobId, requestId) {
  const result = expectSuccess(await broker.handle(request(
    "mac_job_status",
    { job_id: jobId, tail_bytes: 1_024 },
    requestId,
    `${requestId}-nonce`
  )), `${requestId} Job status`);
  return result.data;
}

const directory = await mkdtemp(join(tmpdir(), "mac-operator-d1-git-probe-"));
const projectRoot = await realpath(directory);
const storeDirectory = await mkdtemp(join(tmpdir(), "mac-operator-d1-git-store-"));
const store = new BrokerStore(join(storeDirectory, "broker.sqlite"));
const approvalAuthority = new ApprovalAuthority(store, [{
  issuerId: "operator-1",
  keyId: "operator-key-1",
  key: approvalKey,
  notBeforeMs: now - 60_000,
  expiresAtMs: now + 120_000,
  allowUnattended: false
}], { now: () => now });
const sourcePath = join(projectRoot, "README.md");

await runFixtureGit(projectRoot, ["init", "-q", "--initial-branch=main"]);
await runFixtureGit(projectRoot, ["config", "user.name", "D1 Probe"]);
await runFixtureGit(projectRoot, ["config", "user.email", "d1-probe@example.invalid"]);
await writeFile(sourcePath, "d1-git-content-before\n", { mode: 0o600 });
await runFixtureGit(projectRoot, ["add", "--", "README.md"]);
await runFixtureGit(projectRoot, ["commit", "--no-verify", "--no-gpg-sign", "-m", "d1 initial"]);
await writeFile(sourcePath, "d1-git-content-after\n", { mode: 0o600 });

const basePolicy = createDefaultPolicy(
  "edge-1",
  true,
  scopes,
  ["edge-key-1"],
  [],
  [],
  [],
  [projectRoot]
);
const policy = {
  ...basePolicy,
  tools: new Map(basePolicy.tools)
};
policy.tools.set("mac_git_stage", {
  ...policy.tools.get("mac_git_stage"),
  enabled: true
});
policy.tools.set("mac_git_commit", {
  ...policy.tools.get("mac_git_commit"),
  enabled: true
});
const broker = new Broker({
  store,
  policy,
  edgeAuthenticationKeys: new EdgeKeyring([{
    edgeId: "edge-1",
    keyId: "edge-key-1",
    key: edgeKey,
    notBeforeMs: now - 60_000,
    expiresAtMs: now + 120_000
  }]),
  now: () => now
});

const stageArguments = { project_root: projectRoot, paths: ["README.md"] };
const mismatchCommitArguments = {
  project_root: projectRoot,
  message: "d1 mismatched commit must not run",
  expected_staged_diff_sha256: "0".repeat(64)
};

try {
  const unapprovedStage = await broker.handle(request(
    "mac_git_stage",
    stageArguments,
    "d1-unapproved-stage",
    "d1-unapproved-stage-nonce"
  ));
  expectFailure(unapprovedStage, "POLICY_DENIED", "unapproved stage");

  issueApproval(approvalAuthority, "approval:d1-stage", "mac_git_stage", `project:${projectRoot}`, stageArguments);
  const stageResult = expectSuccess(await broker.handle(request(
    "mac_git_stage",
    stageArguments,
    "d1-stage",
    "d1-stage-nonce"
  )), "approved stage");
  const stageJob = store.ownedJobByIdempotencyKey("git:mac_git_stage:d1-stage", "principal-1");
  if (stageJob?.state !== "completed") throw new Error("Git stage Job did not complete");
  if (stageResult.data.staged_paths.length !== 1 || stageResult.data.staged_paths[0] !== "README.md" ||
      !/^[a-f0-9]{64}$/u.test(stageResult.data.staged_diff_sha256)) {
    throw new Error("Git stage result was not bounded and verified");
  }
  const stagedNames = (await runFixtureGit(projectRoot, ["diff", "--cached", "--name-only"])).stdout.trim().split("\n").filter(Boolean);
  if (JSON.stringify(stagedNames) !== JSON.stringify(["README.md"])) throw new Error("Physical staged-path readback failed");

  const headBeforeMismatch = (await runFixtureGit(projectRoot, ["rev-parse", "HEAD"])).stdout.trim();
  issueApproval(approvalAuthority, "approval:d1-mismatch", "mac_git_commit", `project:${projectRoot}`, mismatchCommitArguments);
  const mismatchResult = await broker.handle(request(
    "mac_git_commit",
    mismatchCommitArguments,
    "d1-mismatch",
    "d1-mismatch-nonce"
  ));
  expectFailure(mismatchResult, "PRECONDITION_FAILED", "staged digest mismatch");
  const mismatchJob = store.ownedJobByIdempotencyKey("git:mac_git_commit:d1-mismatch", "principal-1");
  if (mismatchJob?.state !== "unknown") throw new Error("Mismatched commit did not become UNKNOWN");
  if ((await runFixtureGit(projectRoot, ["rev-parse", "HEAD"])).stdout.trim() !== headBeforeMismatch) throw new Error("Mismatched commit advanced Git HEAD");
  if ((await runFixtureGit(projectRoot, ["diff", "--cached", "--name-only"])).stdout.trim() !== "README.md") {
    throw new Error("Mismatched commit unexpectedly changed the index");
  }

  const commitArguments = {
    project_root: projectRoot,
    message: "d1 verified local commit",
    expected_staged_diff_sha256: stageResult.data.staged_diff_sha256
  };
  issueApproval(approvalAuthority, "approval:d1-commit", "mac_git_commit", `project:${projectRoot}`, commitArguments);
  const commitResult = expectSuccess(await broker.handle(request(
    "mac_git_commit",
    commitArguments,
    "d1-commit",
    "d1-commit-nonce"
  )), "approved commit");
  const commitJob = store.ownedJobByIdempotencyKey("git:mac_git_commit:d1-commit", "principal-1");
  if (commitJob?.state !== "completed") throw new Error("Git commit Job did not complete");
  if (!/^[a-f0-9]{40,64}$/u.test(commitResult.data.commit_id) || commitResult.data.precondition.matched !== true) {
    throw new Error("Git commit result was not verified");
  }
  if ((await runFixtureGit(projectRoot, ["rev-parse", "HEAD"])).stdout.trim() !== commitResult.data.commit_id) {
    throw new Error("Git commit HEAD readback did not match Broker result");
  }
  if ((await runFixtureGit(projectRoot, ["diff", "--cached", "--name-only"])).stdout.trim() !== "") {
    throw new Error("Git commit left staged content behind");
  }
  if ((await runFixtureGit(projectRoot, ["status", "--porcelain"])).stdout.trim() !== "") {
    throw new Error("Git commit working tree was not clean");
  }
  if ((await runFixtureGit(projectRoot, ["remote"])).stdout.trim() !== "") {
    throw new Error("D1 Git probe unexpectedly configured a remote");
  }
  if ((await readFile(sourcePath, "utf8")) !== "d1-git-content-after\n") throw new Error("Committed file readback failed");

  const stageStatus = await jobStatus(broker, stageJob.jobId, "d1-stage-status");
  const mismatchStatus = await jobStatus(broker, mismatchJob.jobId, "d1-mismatch-status");
  const commitStatus = await jobStatus(broker, commitJob.jobId, "d1-commit-status");
  if (stageStatus.state !== "completed" || mismatchStatus.state !== "unknown" || commitStatus.state !== "completed") {
    throw new Error("Git Job status readback did not preserve completed/unknown states");
  }

  const auditText = JSON.stringify(store.auditRows());
  if (auditText.includes("d1-git-content-after") || auditText.includes("d1 verified local commit")) {
    throw new Error("Git audit contains raw source content or commit message");
  }

  console.log(JSON.stringify({
    schema_version: "0.1",
    probe: "d1-git-boundary",
    platform: process.platform,
    arch: process.arch,
    physical_temp_git_repo: true,
    approval_issuer: "verified",
    unapproved_stage: "POLICY_DENIED",
    explicit_stage: {
      result: stageResult.result_class,
      verification: stageResult.verification.status,
      staged_paths: stageResult.data.staged_paths,
      job_state: stageStatus.state
    },
    staged_digest_precondition: {
      result: mismatchResult.result_class,
      job_state: mismatchStatus.state,
      index_preserved: true
    },
    local_commit: {
      result: commitResult.result_class,
      verification: commitResult.verification.status,
      precondition: commitResult.data.precondition.matched,
      head_readback: "verified",
      staged_index_empty: true,
      working_tree_clean: true,
      job_state: commitStatus.state
    },
    remote_operations: "not configured",
    audit_raw_content: false
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
