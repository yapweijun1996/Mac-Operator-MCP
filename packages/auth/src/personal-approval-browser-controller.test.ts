import assert from "node:assert/strict";
import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  guiSessionApprovalId,
  ApprovalIssuerKeyManager,
  BrokerStore,
  createApprovalIssuerRuntime,
  provisionAuthenticationKey,
  writeApprovalIssuerKeyConfig
} from "@mac-operator/broker";
import { createPersonalApprovalBrowserController } from "./personal-approval-browser-controller.js";

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
  try {
    await provisionAuthenticationKey(keyPath);
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
      }]
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
  } finally {
    await runtime?.close().catch(() => undefined);
    keyManager?.dispose();
    store.close();
    await rm(root, { recursive: true, force: true });
  }
});
