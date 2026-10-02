import assert from "node:assert/strict";
import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { sha256 } from "@mac-operator/contracts";
import { ApprovalIssuerKeyManager, approvalPreviewDigest, BrokerStore, createApprovalIssuerRuntime, provisionAuthenticationKey, signApprovalIssuance, writeApprovalIssuerKeyConfig,
  type DevelopmentOperation, type ManagedWorktreeRecord, type ManagedWorktrees } from "@mac-operator/broker";
import { createPersonalDevelopmentApprover } from "./personal-development-approval.js";
import { createPersonalTerminalApprover } from "./personal-terminal-approval.js";

const NOW = 1_700_000_000_000;
const PRINCIPAL = "owner-1";
const DEVELOPMENT_ISSUER = `development-approver-${sha256(PRINCIPAL).slice(0, 32)}`;
const TERMINAL_ISSUER = `terminal-approver-${sha256(PRINCIPAL).slice(0, 32)}`;

async function fixture(overrides: { developmentIssuer?: string; developmentKeyId?: string; terminalIssuer?: string; developmentExpiry?: number } = {}) {
  const root = await mkdtemp(join(await realpath(tmpdir()), "mop-dev-approval-"));
  const dataRoot = join(root, "data"); const runtimeRoot = join(root, "run");
  await mkdir(dataRoot, { mode: 0o700 }); await mkdir(runtimeRoot, { mode: 0o700 });
  const store = new BrokerStore(join(dataRoot, "broker.sqlite"));
  const paths = ["attended", "terminal", "development"].map(name => join(dataRoot, `${name}.key`));
  for (const path of paths) await provisionAuthenticationKey(path);
  const keyConfigPath = join(dataRoot, "approval-keys.json");
  const window = { notBeforeMs: NOW - 1000, expiresAtMs: NOW + 3_600_000 };
  await writeApprovalIssuerKeyConfig(keyConfigPath, { schemaVersion: "0.1", revision: 1, keys: [
    { issuerId: "owner-browser-issuer", keyId: "owner-browser-key", path: paths[0]!, ...window, allowUnattended: false },
    { issuerId: overrides.terminalIssuer ?? TERMINAL_ISSUER, keyId: "personal-terminal-1", path: paths[1]!, ...window, allowUnattended: true },
    { issuerId: overrides.developmentIssuer ?? DEVELOPMENT_ISSUER, keyId: overrides.developmentKeyId ?? "personal-development-1",
      path: paths[2]!, ...window, expiresAtMs: overrides.developmentExpiry ?? window.expiresAtMs, allowUnattended: true }
  ] });
  const activated = new ApprovalIssuerKeyManager(keyConfigPath, store, () => NOW);
  await activated.activate(); activated.dispose();
  const socketPath = join(runtimeRoot, "approval.sock");
  const runtime = await createApprovalIssuerRuntime({ store, startup: { enabled: true, keyConfigPath, socketPath,
    peerCredentialVerifier: { verify: () => undefined } }, now: () => NOW });
  assert.ok(runtime); await runtime.channel.listen();
  const project = join(root, "project"); const worktree = join(root, "managed-worktree");
  await mkdir(project); await mkdir(worktree);
  // The issuer unit fixture supplies only the trusted provenance lookup; ManagedWorktrees has separate physical tests.
  const provenance = { require(cwd: string, projectRoot: string, owner: string, taskId?: string): ManagedWorktreeRecord {
    if (cwd !== worktree || projectRoot !== project || owner !== PRINCIPAL || taskId !== undefined && taskId !== "task-1") throw new Error("Unowned worktree");
    return { projectRoot: project, worktree, owner: PRINCIPAL, taskId: "task-1", state: "active" } as ManagedWorktreeRecord;
  } } as unknown as ManagedWorktrees;
  const options = { principalId: PRINCIPAL, runtime, socketPath, worktrees: provenance, developmentProjects: [project], taskProfiles: ["approved.test"], now: () => NOW };
  const operation = (tool = "mac_codex_run", requestId = "development-request-1"): DevelopmentOperation => ({
    requestId, principalId: PRINCIPAL, sessionId: "session-1", tool, contractVersion: "0.1", policyVersion: "policy-0.1",
    targetKind: tool === "mac_task_run" ? "task_profile" : "project", targetRef: tool === "mac_task_run" ? "task_profile:approved.test" : `project:${["mac_git_stage", "mac_git_commit"].includes(tool) ? worktree : project}`,
    payloadDigest: "b".repeat(64), approvalClass: ["mac_codex_run", "mac_test_run", "mac_build_run", "mac_task_run"].includes(tool) ? "trusted_profile" : "trusted_write",
    expiresAtMs: NOW + 1_000_000, projectRoot: project,
    ...(["mac_git_worktree_create", "mac_git_branch_create"].includes(tool) ? {} : { worktree }), taskId: "task-1"
  });
  return { root, store, runtime, socketPath, project, worktree, options, operation, auditBaseline: store.auditRows().length,
    close: async () => { await runtime.close(); store.close(); await rm(root, { recursive: true, force: true }); } };
}

test("delegated development issuer creates exact single-use approvals for coding and local Git only", async () => {
  const f = await fixture();
  try {
    const approve = createPersonalDevelopmentApprover(f.options);
    const tools = ["mac_git_worktree_create", "mac_git_branch_create", "mac_git_worktree_remove", "mac_codex_run",
      "mac_test_run", "mac_build_run", "mac_task_run", "mac_git_stage", "mac_git_commit"];
    for (const [index, tool] of tools.entries()) {
      const operation = f.operation(tool, `development-request-${index}`);
      assert.equal(await approve(operation), true);
      const approval = f.store.approvalRecord(`approval:development-${sha256(operation.requestId).slice(0, 48)}`)!;
      assert.equal(approval.approverPrincipalId, DEVELOPMENT_ISSUER); assert.equal(approval.requestingPrincipalId, PRINCIPAL);
      assert.equal(approval.tool, tool); assert.equal(approval.targetRef, operation.targetRef);
      assert.equal(approval.payloadDigest, operation.payloadDigest); assert.equal(approval.policyVersion, operation.policyVersion);
      assert.equal(approval.approvalClass, operation.approvalClass); assert.equal(approval.unattended, true);
      assert.equal(approval.useLimit, 1); assert.equal(approval.expiresAtMs, NOW + 630_000);
    }
    const git = f.operation("mac_git_stage", "git-derived-task"); delete git.taskId;
    assert.equal(await approve(git), true);
  } finally { await f.close(); }
});

test("coding delegation never approves Tier4, terminal, arbitrary file or host operations", async () => {
  const f = await fixture();
  try {
    const approve = createPersonalDevelopmentApprover(f.options);
    for (const tool of ["mac_git_push", "mac_terminal_exec", "mac_service_control", "mac_priv_package_install", "mac_priv_power",
      "mac_write_file_atomic", "mac_apply_patch", "sudo", "mac_job_cancel"]) assert.equal(await approve(f.operation(tool)), false);
    assert.equal(f.store.auditRows().length, f.auditBaseline);
  } finally { await f.close(); }
});

test("principal, project, target and operation shape are checked before any approval issuance", async () => {
  const f = await fixture();
  try {
    const approve = createPersonalDevelopmentApprover(f.options);
    const operation = f.operation();
    const accessor = Object.defineProperty({ ...operation }, "targetRef", { get() { throw new Error("Accessor must not execute"); }, enumerable: true });
    const maliciousString = { toString() { throw new Error("Coercion must not execute"); } };
    for (const value of [{ ...operation, principalId: "other-owner" }, { ...operation, projectRoot: "/unapproved/project" },
      { ...operation, targetKind: "host" }, { ...operation, targetRef: "project:/unapproved/project" },
      { ...operation, targetRef: `project:${f.project}\nproject:/other` }, { ...operation, payloadDigest: "short" },
      { ...operation, contractVersion: "future" }, { ...operation, policyVersion: "invalid" },
      { ...operation, requestId: maliciousString }, { ...operation, command: "arbitrary shell" }, Object.create(operation), accessor]) {
      assert.equal(await approve(value as DevelopmentOperation), false);
    }
    assert.equal(f.store.auditRows().length, f.auditBaseline);
  } finally { await f.close(); }
});

test("execution, removal and Git need owned task worktrees while creation cannot splice one", async () => {
  const f = await fixture();
  try {
    const approve = createPersonalDevelopmentApprover(f.options);
    for (const tool of ["mac_codex_run", "mac_test_run", "mac_build_run", "mac_task_run", "mac_git_worktree_remove", "mac_git_stage", "mac_git_commit"]) {
      const value = f.operation(tool);
      for (const worktree of [undefined, f.project, join(f.root, "unowned"), `${f.worktree}/../managed-worktree`]) {
        const { worktree: _worktree, ...withoutWorktree } = value;
        const input = worktree === undefined ? withoutWorktree : { ...withoutWorktree, worktree };
        assert.equal(await approve(input), false);
      }
      assert.equal(await approve({ ...value, taskId: "wrong-task" }), false);
      if (!["mac_git_stage", "mac_git_commit"].includes(tool)) {
        const { taskId: _taskId, ...withoutTask } = value;
        assert.equal(await approve(withoutTask), false);
      }
    }
    for (const tool of ["mac_git_worktree_create", "mac_git_branch_create"]) {
      const value = f.operation(tool);
      assert.equal(await approve({ ...value, worktree: f.worktree }), false);
      const { taskId: _taskId, ...withoutTask } = value;
      assert.equal(await approve(withoutTask), false);
    }
    assert.equal(f.store.auditRows().length, f.auditBaseline);
  } finally { await f.close(); }
});

test("development approvals enforce registered profiles, exact class, expiration and issuer lifetime", async () => {
  const f = await fixture({ developmentExpiry: NOW + 300_000 });
  try {
    const approve = createPersonalDevelopmentApprover(f.options);
    const task = f.operation("mac_task_run");
    assert.equal(await approve({ ...task, targetRef: "task_profile:unapproved.shell" }), false);
    assert.equal(await approve({ ...task, targetKind: "project", targetRef: `project:${f.project}` }), false);
    assert.equal(await approve({ ...f.operation(), approvalClass: "trusted_write" }), false);
    assert.equal(await approve({ ...f.operation("mac_git_stage"), approvalClass: "trusted_profile" }), false);
    assert.equal(await approve({ ...f.operation(), expiresAtMs: NOW }), false);
    assert.equal(await approve({ ...f.operation(), expiresAtMs: Number.MAX_SAFE_INTEGER + 1 }), false);
    assert.equal(await approve(f.operation()), true);
    assert.equal(f.store.approvalRecord(`approval:development-${sha256("development-request-1").slice(0, 48)}`)?.expiresAtMs, NOW + 300_000);
    await assert.rejects(approve(f.operation()), /already|exist/u);
  } finally { await f.close(); }
});

test("development delegation selects exact key identity and rejects cross-issuer key substitution", async () => {
  for (const overrides of [{ developmentIssuer: TERMINAL_ISSUER }, { developmentKeyId: "generic-unattended-key" }]) {
    const f = await fixture(overrides);
    try {
      const approve = createPersonalDevelopmentApprover(f.options);
      await assert.rejects(approve(f.operation()), /separate delegated issuer/u);
      assert.equal(f.store.auditRows().length, f.auditBaseline);
    } finally { await f.close(); }
  }
});

test("terminal and coding approvals remain separate when both unattended issuers are installed", async () => {
  const f = await fixture();
  try {
    const approve = createPersonalDevelopmentApprover(f.options);
    assert.equal(await approve(f.operation()), true);
    const terminal = createPersonalTerminalApprover({ principalId: PRINCIPAL, runtime: f.runtime, socketPath: f.socketPath, now: () => NOW });
    const operation = { requestId: "terminal-request", principalId: PRINCIPAL, sessionId: "session-1", tool: "mac_terminal_exec",
      contractVersion: "0.1", policyVersion: "policy-0.1", targetKind: "host", targetRef: "host:owner-terminal",
      payloadDigest: "c".repeat(64), expiresAtMs: NOW + 300_000, timeoutMs: 120_000 };
    assert.equal(await terminal(operation), true);
    assert.equal(f.store.approvalRecord(`approval:owner-terminal-${sha256(operation.requestId).slice(0, 48)}`)?.approverPrincipalId, TERMINAL_ISSUER);
    assert.equal(f.store.approvalRecord(`approval:development-${sha256("development-request-1").slice(0, 48)}`)?.approverPrincipalId, DEVELOPMENT_ISSUER);
    assert.equal(await terminal({ ...operation, tool: "mac_codex_run" }), false);
    // A session start approval must outlive the whole session; only the session tool may ask for it.
    const session = { ...operation, requestId: "session-request", tool: "mac_terminal_session", timeoutMs: 300_000 };
    assert.equal(await terminal(session), true);
    assert.equal(await terminal({ ...session, requestId: "session-request-2", timeoutMs: 600_001 }), false);
    assert.equal(await terminal({ ...operation, requestId: "exec-request-2", timeoutMs: 300_000 }), false);
    assert.equal(await approve({ ...f.operation(), tool: "mac_terminal_exec" }), false);
  } finally { await f.close(); }
});

test("terminal delegation refuses a same-key-id issuer belonging to another principal", async () => {
  const f = await fixture({ terminalIssuer: `terminal-approver-${sha256("another-owner").slice(0, 32)}` });
  try {
    const terminal = createPersonalTerminalApprover({ principalId: PRINCIPAL, runtime: f.runtime, socketPath: f.socketPath, now: () => NOW });
    await assert.rejects(terminal({ requestId: "terminal-request", principalId: PRINCIPAL, sessionId: "session-1", tool: "mac_terminal_exec",
      contractVersion: "0.1", policyVersion: "policy-0.1", targetKind: "host", targetRef: "host:owner-terminal",
      payloadDigest: "c".repeat(64), expiresAtMs: NOW + 300_000, timeoutMs: 120_000 }), /separate delegated issuer/u);
    assert.equal(f.store.auditRows().length, f.auditBaseline);
  } finally { await f.close(); }
});

test("authenticated development key cannot bypass its tool, target, class, principal or unattended boundaries", async () => {
  const f = await fixture();
  try {
    const key = f.runtime.keyManager.current().keys.find(value => value.keyId === "personal-development-1")!;
    const approval = { approvalId: "approval:development-authority-test", approverPrincipalId: DEVELOPMENT_ISSUER,
      requestingPrincipalId: PRINCIPAL, tool: "mac_codex_run", contractVersion: "0.1", targetKind: "project",
      targetRef: `project:${f.project}`, payloadDigest: "d".repeat(64), policyVersion: "policy-0.1",
      approvalClass: "trusted_profile" as const, unattended: true, issuedAtMs: NOW, expiresAtMs: NOW + 60_000, useLimit: 1 };
    const invalid = [
      { ...approval, tool: "mac_terminal_exec", targetKind: "host", targetRef: "host:owner-terminal" },
      { ...approval, tool: "mac_git_push" }, { ...approval, tool: "mac_service_control" },
      { ...approval, tool: "mac_priv_package_install", targetKind: "package", targetRef: "package:unapproved" },
      { ...approval, tool: "mac_write_file_atomic", targetKind: "path", targetRef: "path:/unapproved" },
      { ...approval, targetKind: "host", targetRef: "host:broker" },
      { ...approval, targetKind: "path", targetRef: "path:/unapproved" },
      { ...approval, approvalClass: "trusted_write" as const }, { ...approval, unattended: false },
      { ...approval, requestingPrincipalId: "other-owner" }, { ...approval, expiresAtMs: NOW + 630_001 }
    ];
    for (const [index, value] of invalid.entries()) {
      const signed = signApprovalIssuance({ protocolVersion: "0.1", requestId: `approval-issue:boundary-test-${index}`,
        nonce: `approval-nonce:boundary-test-${index}`, nonceExpiresAtMs: NOW + 60_000, issuerId: DEVELOPMENT_ISSUER,
        keyId: key.keyId, timestampMs: NOW, approval: value, previewDigest: approvalPreviewDigest(value) }, key.key);
      assert.throws(() => f.runtime.authority.issue(signed), /development|delegat|profile issuer/u);
    }
    assert.equal(f.store.auditRows().length, f.auditBaseline);
  } finally { await f.close(); }
});
