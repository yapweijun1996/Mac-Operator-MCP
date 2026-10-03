import assert from "node:assert/strict";
import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { sha256 } from "@mac-operator/contracts";
import {
  guiSessionApprovalId,
  ApprovalIssuerKeyManager,
  BrokerStore,
  createApprovalIssuerRuntime,
  provisionAuthenticationKey,
  writeApprovalIssuerKeyConfig
} from "@mac-operator/broker";
import { createPersonalTerminalApprover } from "./personal-terminal-approval.js";
import { createPersonalApprovalBrowserController } from "./personal-approval-browser-controller.js";
import { AuthStore } from "./store.js";

const NOW = 1_700_000_000_000;

test("personal browser approval controller binds a real preview through owner IPC", async () => {
  const root = await realpath(await mkdtemp(join("/tmp", "mop-abc-")));
  const dataRoot = join(root, "data");
  const runtimeRoot = join(root, "runtime");
  await mkdir(dataRoot, { mode: 0o700 });
  await mkdir(runtimeRoot, { mode: 0o700 });
  const store = new BrokerStore(join(dataRoot, "broker.sqlite"));
  const keyPath = join(dataRoot, "approval.key");
  const keyConfigPath = join(dataRoot, "approval-keys.json");
  const socketPath = join(runtimeRoot, "approval.sock");
  let keyManager: ApprovalIssuerKeyManager | undefined;
  let runtime: Awaited<ReturnType<typeof createApprovalIssuerRuntime>> | undefined;
  let authStore: AuthStore | undefined;
  try {
    await provisionAuthenticationKey(keyPath);
    const terminalKeyPath = join(dataRoot, "terminal.key");
    await provisionAuthenticationKey(terminalKeyPath);
    await writeApprovalIssuerKeyConfig(keyConfigPath, {
      schemaVersion: "0.1",
      revision: 1,
      keys: [{
        issuerId: "owner-browser-issuer",
        keyId: "owner-browser-key",
        path: keyPath,
        notBeforeMs: NOW - 1_000,
        expiresAtMs: NOW + 60_000,
        allowUnattended: false
      }, { issuerId: `terminal-approver-${sha256("owner-1").slice(0, 32)}`, keyId: "personal-terminal-1", path: terminalKeyPath,
        notBeforeMs: NOW - 1000, expiresAtMs: NOW + 60000, allowUnattended: true }]
    });
    keyManager = new ApprovalIssuerKeyManager(keyConfigPath, store, () => NOW);
    await keyManager.activate();
    keyManager.dispose();
    keyManager = undefined;
    runtime = await createApprovalIssuerRuntime({
      store,
      startup: {
        enabled: true,
        keyConfigPath,
        socketPath,
        peerCredentialVerifier: { verify: () => undefined }
      },
      now: () => NOW
    });
    assert.ok(runtime);
    await runtime.channel.listen();

    const requestId = "browser-controller-preview";
    const targetRef = "service:gui/501/com.mac-operator.browser-canary";
    store.admitRequest({
      requestId,
      edgeId: "edge-1",
      nonce: "browser-controller-nonce",
      nonceExpiresAtMs: NOW + 60_000,
      principalId: "owner-1",
      sessionId: "session-1",
      tool: "mac_service_control",
      policyVersion: "policy-0.1",
      payloadDigest: "a".repeat(64),
      mutation: true,
      receivedAtMs: NOW
    });
    store.recordRequestDecision({
      requestId,
      principalId: "owner-1",
      tool: "mac_service_control",
      eventType: "decision",
      decision: "allow",
      resultClass: "AUTHORIZED",
      targetRef,
      policyVersion: "policy-0.1",
      evidence: {},
      timestampMs: NOW + 1
    });
    store.createApprovalPreview(requestId, {
      contractVersion: "0.1",
      targetKind: "service",
      targetRef,
      payloadDigest: "a".repeat(64),
      approvalClass: "trusted_write",
      unattended: false
    }, NOW + 2, NOW + 60_000);

    const terminal = createPersonalTerminalApprover({ principalId: "owner-1", runtime, socketPath, now: () => NOW + 3 });
    const operation = { requestId: "terminal-delegation", principalId: "owner-1", sessionId: "session-1",
      tool: "mac_terminal_exec", contractVersion: "0.1", policyVersion: "policy-0.1", targetKind: "host",
      targetRef: "host:owner-terminal", payloadDigest: "b".repeat(64), expiresAtMs: NOW + 300000, timeoutMs: 120000 };
    assert.equal(await terminal({ ...operation, principalId: "other-owner" }), false);
    assert.equal(await terminal({ ...operation, tool: "mac_task_run" }), false);
    assert.equal(await terminal(operation), true);
    const terminalApproval = store.approvalRecord(`approval:owner-terminal-${(await import("@mac-operator/contracts")).sha256(operation.requestId).slice(0, 48)}`);
    assert.ok(terminalApproval);
    assert.equal(terminalApproval.expiresAtMs, NOW + 150003);
    assert.equal(terminalApproval.unattended, true);
    const controller = createPersonalApprovalBrowserController({ store, approvalIssuerRuntime: runtime, socketPath, now: () => NOW + 3 });
    const preview = controller.preview(requestId);
    assert.equal(preview?.requestId, requestId);
    assert.equal(preview?.targetRef, targetRef);
    assert.equal(preview?.payloadDigest, "a".repeat(64));
    const issued = await controller.issue(requestId);
    assert.match(issued.approvalId, /^approval:owner-preview-[a-f0-9]{48}$/u);
    assert.equal(issued.expiresAtMs, NOW + 60_000);
    assert.equal(store.approvalRecord(issued.approvalId)?.approverPrincipalId, "owner-browser-issuer");
    assert.equal(controller.preview(requestId), undefined);
    await assert.rejects(controller.issue(requestId), /no longer pending/u);
    const focusTarget = "app_window:window:bundle:com.google.Chrome";
    store.admitRequest({ requestId: "focus-consent", edgeId: "edge-1", nonce: "focus-nonce", nonceExpiresAtMs: NOW + 60000,
      principalId: "owner-1", sessionId: "session-1", tool: "mac_app_focus", policyVersion: "policy-0.1",
      payloadDigest: "a".repeat(64), mutation: true, receivedAtMs: NOW });
    store.recordRequestDecision({ requestId: "focus-consent", principalId: "owner-1", tool: "mac_app_focus", eventType: "decision",
      decision: "allow", resultClass: "AUTHORIZED", targetRef: focusTarget, policyVersion: "policy-0.1", evidence: {}, timestampMs: NOW + 1 });
    store.createApprovalPreview("focus-consent", { contractVersion: "0.1", targetKind: "app_window", targetRef: focusTarget,
      payloadDigest: "a".repeat(64), approvalClass: "trusted_gui", unattended: false }, NOW + 2, NOW + 600000);
    assert.equal(controller.preview("focus-consent")?.sessionEligible, true);
    const grant = controller.sessions.start("focus-consent");
    assert.equal(await controller.authorizeGuiSession({ requestId: "session-focus", principalId: "owner-1", sessionId: "session-1",
      appId: "bundle:com.google.Chrome", tool: "mac_app_focus", contractVersion: "0.1", policyVersion: "policy-0.1",
      targetKind: "app_window", targetRef: focusTarget, payloadDigest: "a".repeat(64), expiresAtMs: NOW + 60000 }), true);
    const childId = guiSessionApprovalId("session-focus");
    assert.equal(store.approvalRecord(childId)?.approverPrincipalId, "owner-browser-issuer");
    controller.sessions.revoke(grant.id);
    assert.notEqual(store.approvalRecord(childId)?.revokedAtMs, null);
    authStore = new AuthStore(dataRoot, true);
    const desktopId = "gui-session:12345678-1234-1234-1234-123456789abc";
    authStore.put("desktop_grant", desktopId, { id: desktopId, principalId: "owner-1", policyVersion: "policy-0.1",
      consentRequestId: "explicit-owner-desktop-opt-in", createdAt: NOW, revoked: false });
    const desktopOperation = { requestId: "desktop-focus", principalId: "owner-1", sessionId: "session-1",
      appId: "bundle:com.apple.finder", tool: "mac_app_focus", contractVersion: "0.1", policyVersion: "policy-0.1",
      targetKind: "app_window", targetRef: "app_window:window:bundle:com.apple.finder", payloadDigest: "c".repeat(64), expiresAtMs: NOW + 60000 };
    const disabled = createPersonalApprovalBrowserController({ store, authStore, approvalIssuerRuntime: runtime, socketPath, now: () => NOW + 3 });
    assert.equal(await disabled.authorizeGuiSession(desktopOperation), false);
    const desktop = createPersonalApprovalBrowserController({ store, authStore, allowDesktop: true,
      approvalIssuerRuntime: runtime, socketPath, now: () => NOW + 3 });
    assert.equal(await desktop.authorizeGuiSession(desktopOperation), true);
    const desktopChild = guiSessionApprovalId(desktopOperation.requestId);
    assert.equal(store.approvalRecord(desktopChild)?.approverPrincipalId, "owner-browser-issuer");
    assert.equal(store.approvalRecord(desktopChild)?.approvalClass, "trusted_gui");
    assert.equal(store.approvalRecord(desktopChild)?.unattended, false);
    assert.equal(store.approvalRecord(desktopChild)?.payloadDigest, desktopOperation.payloadDigest);
    assert.equal(store.approvalRecord(desktopChild)?.useLimit, 1);
    desktop.sessions.revoke(desktopId);
    assert.equal(authStore.desktopGrants()[0]?.revoked, true);
    assert.notEqual(store.approvalRecord(desktopChild)?.revokedAtMs, null);
  } finally {
    await runtime?.close().catch(() => undefined);
    keyManager?.dispose();
    authStore?.close();
    store.close();
    await rm(root, { recursive: true, force: true });
  }
});
