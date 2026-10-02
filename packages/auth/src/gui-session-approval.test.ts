import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { BrokerStore, type GuiSessionOperation } from "@mac-operator/broker";
import { AuthStore } from "./store.js";
import { GUI_SESSION_MS, GuiSessionApprovals } from "./gui-session-approval.js";

const NOW = 1_700_000_000_000;
async function fixture(t: import("node:test").TestContext) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mop-gui-session-")));
  let auth = new AuthStore(root, true);
  const store = new BrokerStore(join(root, "broker.sqlite"));
  t.after(async () => { auth.close(); store.close(); await rm(root, { recursive: true, force: true }); });
  let now = NOW;
  const targetRef = "app_window:window:bundle:com.google.Chrome";
  const operation: GuiSessionOperation = { requestId: "operation-1", principalId: "owner-1", sessionId: "session-1",
    appId: "bundle:com.google.Chrome", tool: "mac_app_focus", contractVersion: "0.1", policyVersion: "policy-1",
    targetKind: "app_window", targetRef, payloadDigest: "a".repeat(64), expiresAtMs: NOW + GUI_SESSION_MS * 2 };
  const pending = (id: string, tool = "mac_app_focus") => {
    store.admitRequest({ requestId: id, edgeId: "edge-1", nonce: `nonce-${id}`, nonceExpiresAtMs: now + 60000,
      principalId: "owner-1", sessionId: "session-1", tool, policyVersion: "policy-1", payloadDigest: "a".repeat(64), mutation: true, receivedAtMs: now });
    store.recordRequestDecision({ requestId: id, principalId: "owner-1", tool, eventType: "decision", decision: "allow",
      resultClass: "AUTHORIZED", targetRef, policyVersion: "policy-1", evidence: {}, timestampMs: now });
    store.createApprovalPreview(id, { contractVersion: "0.1", targetKind: "app_window", targetRef,
      payloadDigest: "a".repeat(64), approvalClass: "trusted_gui", unattended: false }, now, now + (tool === "mac_app_focus" ? 600000 : 120000));
  };
  const issued: string[] = [];
  const sessions = new GuiSessionApprovals(store, async approval => {
    store.issueApproval({ ...approval, approverPrincipalId: "browser-owner" }); issued.push(approval.approvalId);
  }, () => now);
  return { store, operation, pending, issued, sessions,
    persistent: () => new GuiSessionApprovals(store, async approval => {
      store.issueApproval({ ...approval, approverPrincipalId: "browser-owner" }); issued.push(approval.approvalId);
    }, () => now, auth),
    auth: () => auth,
    reopen: () => { auth.close(); auth = new AuthStore(root); }, setNow: (value: number) => { now = value; } };
}

test("GUI session is explicit, scope-bound, finite and revocable", async t => {
  const f = await fixture(t);
  assert.equal(await f.sessions.authorize(f.operation), false);
  f.pending("focus-preview");
  const grant = f.sessions.start("focus-preview");
  assert.equal(grant.expiresAtMs, NOW + GUI_SESSION_MS);
  assert.deepEqual(f.sessions.start("focus-preview"), grant);
  for (const changed of [{ principalId: "other" }, { sessionId: "other" }, { appId: "bundle:com.apple.Safari" },
    { policyVersion: "policy-2" }, { tool: "mac_write_file_atomic" }, { expiresAtMs: NOW }]) {
    assert.equal(await f.sessions.authorize({ ...f.operation, ...changed }), false);
  }
  for (const tool of ["mac_app_focus", "mac_ui_action", "mac_ui_type"]) {
    assert.equal(await f.sessions.authorize({ ...f.operation, tool, requestId: `operation-${tool}`,
      ...(tool === "mac_app_focus" ? {} : { targetKind: "ui_element", targetRef: `ui_element:element:${"b".repeat(48)}` }) }), true);
  }
  assert.equal(f.sessions.status(grant.id)?.remainingOperations, 497);
  for (const id of f.issued) {
    assert.equal(f.store.approvalRecord(id)?.payloadDigest, f.operation.payloadDigest);
    assert.equal(f.store.approvalRecord(id)?.expiresAtMs, NOW + 30000);
  }
  f.sessions.revoke(grant.id);
  assert.equal(await f.sessions.authorize(f.operation), false);
  assert.equal(f.sessions.status(grant.id), undefined);
  assert.throws(() => f.sessions.start("focus-preview"), /already been used/u);
  for (const id of f.issued) assert.equal(f.store.approvalRecord(id)?.revokedAtMs, NOW);
});

test("Chrome delegation rejects unapproved apps, target mismatch and sensitive operations", async t => {
  const f = await fixture(t);
  f.pending("focus-preview");
  f.sessions.start("focus-preview");
  for (const changed of [
    { appId: "bundle:com.apple.finder" }, { targetKind: "app" },
    { targetRef: "app_window:window:bundle:com.apple.Safari" },
    { requiresExplicitApproval: true },
    { tool: "mac_ui_type", targetKind: "ui_element", targetRef: "ui_element:invalid" }
  ]) assert.equal(await f.sessions.authorize({ ...f.operation, ...changed }), false);
  assert.equal(f.issued.length, 0);
});

test("GUI session ends on expiry or OAuth revocation and cannot originate from other tools", async t => {
  const f = await fixture(t);
  f.pending("wrong-preview", "mac_ui_action");
  assert.throws(() => f.sessions.start("wrong-preview"), /browser focus preview/u);
  f.pending("focus-preview");
  const grant = f.sessions.start("focus-preview");
  f.setNow(NOW + GUI_SESSION_MS);
  assert.equal(f.sessions.status(grant.id), undefined);
  assert.equal(await f.sessions.authorize(f.operation), false);
  f.setNow(NOW + 1000);
  f.store.revoke("session", "session-1", "OWNER_REVOKED", NOW + 1000);
  assert.equal(await f.sessions.authorize(f.operation), false);
});

test("revocation during GUI approval issuance revokes the committed child approval", async t => {
  const f = await fixture(t);
  f.pending("focus-preview");
  let finish!: () => void;
  const gate = new Promise<void>(resolve => { finish = resolve; });
  let id = "";
  const sessions = new GuiSessionApprovals(f.store, async approval => {
    id = approval.approvalId;
    await gate;
    f.store.issueApproval({ ...approval, approverPrincipalId: "browser-owner" });
  }, () => NOW);
  const grant = sessions.start("focus-preview");
  const flight = sessions.authorize(f.operation);
  sessions.revoke(grant.id);
  finish();
  await assert.rejects(flight, /ended during issuance/u);
  assert.equal(f.store.approvalRecord(id)?.revokedAtMs, NOW);
});

test("GUI session use limit cannot be extended by replaying consent", async t => {
  const f = await fixture(t);
  f.pending("focus-preview");
  const grant = f.sessions.start("focus-preview");
  for (let index = 0; index < 500; index++) {
    assert.equal(await f.sessions.authorize({ ...f.operation, requestId: `bounded-${index}` }), true);
  }
  assert.equal(await f.sessions.authorize({ ...f.operation, requestId: "over-limit" }), false);
  assert.equal(f.sessions.status(grant.id), undefined);
  assert.throws(() => f.sessions.start("focus-preview"), /already been used/u);
});


test("persistent browser access survives database reopen, time and more than 500 operations", async t => {
  const f = await fixture(t);
  f.pending("persistent-preview");
  const before = f.persistent();
  const grant = before.start("persistent-preview", true);
  assert.equal(grant.persistent, true);
  assert.equal(await before.authorize(f.operation), true);
  before.close();
  f.reopen();
  const after = f.persistent();
  assert.deepEqual(after.status(grant.id), grant);
  assert.deepEqual(after.start("persistent-preview", true), grant);
  f.setNow(NOW + 365 * 86400000);
  f.auth().prune();
  const renewed = { ...f.operation, sessionId: "renewed-owner-session", expiresAtMs: NOW + 366 * 86400000 };
  for (let index = 0; index < 501; index++) {
    assert.equal(await after.authorize({ ...renewed, requestId: `persistent-${index}` }), true);
  }
  assert.deepEqual(after.status(grant.id), grant);
  for (const changed of [{ principalId: "other" }, { appId: "bundle:com.apple.Safari" },
    { policyVersion: "policy-2" }, { tool: "mac_write_file_atomic" }, { expiresAtMs: NOW }]) {
    assert.equal(await after.authorize({ ...renewed, ...changed }), false);
  }
  f.store.revoke("session", renewed.sessionId, "OWNER_REVOKED", NOW + 365 * 86400000);
  assert.equal(await after.authorize(renewed), false);
  assert.equal(await after.authorize({ ...renewed, sessionId: "valid-session", requestId: "valid-renewal" }), true);
  after.revoke(grant.id);
  after.close();
  f.reopen();
  const revoked = f.persistent();
  assert.equal(revoked.status(grant.id), undefined);
  assert.equal(await revoked.authorize({ ...renewed, sessionId: "valid-session" }), false);
  assert.throws(() => revoked.start("persistent-preview", true), /already been used/u);
});

test("temporary consent is never upgraded and global reset revokes persistent authority", async t => {
  const f = await fixture(t);
  f.pending("temporary-preview");
  const sessions = f.persistent();
  const temporary = sessions.start("temporary-preview");
  assert.equal(temporary.persistent, undefined);
  assert.throws(() => sessions.start("temporary-preview", true), /already been used/u);
  assert.equal(f.auth().browserGrants().length, 0);
  f.pending("persistent-preview");
  const permanent = sessions.start("persistent-preview", true);
  f.auth().revokeAll();
  assert.equal(sessions.status(permanent.id), undefined);
  sessions.close();
  f.reopen();
  const restarted = f.persistent();
  assert.equal(restarted.status(temporary.id), undefined);
  assert.equal(restarted.list("owner-1").length, 0);
  assert.throws(() => restarted.start("persistent-preview", true), /already been used/u);
});

test("persistent revocation during issuance rejects the committed operation", async t => {
  const f = await fixture(t);
  f.pending("persistent-preview");
  let finish!: () => void;
  const gate = new Promise<void>(resolve => { finish = resolve; });
  let approvalId = "";
  const sessions = new GuiSessionApprovals(f.store, async approval => {
    approvalId = approval.approvalId;
    await gate;
    f.store.issueApproval({ ...approval, approverPrincipalId: "browser-owner" });
  }, () => NOW, f.auth());
  sessions.start("persistent-preview", true);
  const operation = sessions.authorize(f.operation);
  f.auth().revokeAll();
  finish();
  await assert.rejects(operation, /ended during issuance/u);
  assert.equal(f.store.approvalRecord(approvalId)?.revokedAtMs, NOW);
});
