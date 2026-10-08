import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { BrokerStore, type GuiSessionOperation } from "@mac-operator/broker";
import { AuthStore } from "./store.js";
import { GUI_SESSION_MS, GuiSessionApprovals } from "./gui-session-approval.js";
import { configSchema, recordSchemas } from "./contracts.js";

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
      resultClass: "AUTHORIZED", targetRef: tool === "mac_app_open" ? "app:bundle:com.google.Chrome" : targetRef, policyVersion: "policy-1", evidence: {}, timestampMs: now });
    store.createApprovalPreview(id, { contractVersion: "0.1", targetKind: tool === "mac_app_open" ? "app" : "app_window", targetRef: tool === "mac_app_open" ? "app:bundle:com.google.Chrome" : targetRef,
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
    desktop: (allowDesktop = true) => new GuiSessionApprovals(store, async approval => {
      store.issueApproval({ ...approval, approverPrincipalId: "browser-owner" }); issued.push(approval.approvalId);
    }, () => now, auth, { allowDesktop }),
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

function desktopOperation(operation: GuiSessionOperation, appId = "bundle:com.apple.finder"): GuiSessionOperation {
  return { ...operation, appId, targetRef: `app_window:window:${appId}` };
}

test("desktop configuration and records require explicit opt-in without broadening browser records", () => {
  const config = { version: 1, issuer: "https://mac.example/", resource: "https://mac.example/mcp",
    issuerId: "mac-operator-auth", principalId: "owner-1", keyId: "key-1", port: 3444,
    allowedRedirectUris: ["https://client.example/callback"], grantProfile: "o1" };
  assert.equal(configSchema.parse(config).guiAccess, undefined);
  assert.equal(configSchema.parse({ ...config, guiAccess: "browsers" }).guiAccess, "browsers");
  assert.equal(configSchema.parse({ ...config, guiAccess: "desktop" }).guiAccess, "desktop");
  assert.equal(configSchema.safeParse({ ...config, guiAccess: true }).success, false);
  assert.equal(configSchema.safeParse({ ...config, guiAccess: "desktop", grantProfile: "r1" }).success, false);
  const grant = { id: "gui-session:12345678-1234-1234-1234-123456789abc", principalId: "owner-1",
    policyVersion: "policy-1", consentRequestId: "owner-desktop-opt-in", createdAt: NOW, revoked: false };
  assert.deepEqual(recordSchemas.desktop_grant.parse(grant), grant);
  assert.equal(recordSchemas.desktop_grant.safeParse({ ...grant, appId: "bundle:com.apple.finder" }).success, false);
  assert.equal(recordSchemas.browser_grant.safeParse({ ...grant, sessionId: "session-1", appId: "bundle:com.apple.finder" }).success, false);
});

test("persistent desktop delegation is explicit, survives reopen, and authorizes concrete GUI apps", async t => {
  const f = await fixture(t);
  const before = f.desktop();
  assert.equal(await before.authorize(desktopOperation(f.operation)), false);
  assert.equal(f.auth().desktopGrants().length, 0);
  f.pending("desktop-preview");
  const grant = before.startDesktop("desktop-preview");
  assert.equal(grant.desktop, true);
  assert.equal(grant.persistent, true);
  assert.equal(grant.appId, "desktop");
  assert.equal(f.auth().browserGrants().length, 0);
  assert.equal(f.auth().desktopGrants().length, 1);
  assert.deepEqual(before.startDesktop("desktop-preview"), grant);
  for (const app of ["bundle:com.apple.finder", "bundle:com.apple.TextEdit", "bundle:com.google.Chrome"]) {
    assert.equal(await before.authorize({ ...desktopOperation(f.operation, app), requestId: `desktop-${app}` }), true);
  }
  const finder = desktopOperation(f.operation);
  for (const tool of ["mac_app_open", "mac_ui_action", "mac_ui_type"]) {
    assert.equal(await before.authorize({ ...finder, tool, requestId: `desktop-tool-${tool}`,
      ...(tool === "mac_app_open" ? { targetKind: "app", targetRef: `app:${finder.appId}` }
        : { targetKind: "ui_element", targetRef: `ui_element:element:${"b".repeat(48)}` }) }), true);
  }
  for (const id of f.issued) {
    assert.equal(f.store.approvalRecord(id)?.approvalClass, "trusted_gui");
    assert.equal(f.store.approvalRecord(id)?.payloadDigest, f.operation.payloadDigest);
    assert.equal(f.store.approvalRecord(id)?.useLimit, 1);
    assert.equal(f.store.approvalRecord(id)?.expiresAtMs, NOW + 30_000);
  }
  before.close();
  f.reopen();
  const after = f.desktop();
  assert.deepEqual(after.list("owner-1"), [grant]);
  assert.deepEqual(after.status(grant.id), grant);
  f.setNow(NOW + 365 * 86400000);
  f.auth().prune();
  assert.equal(await after.authorize({ ...finder, requestId: "desktop-renewed", sessionId: "renewed-owner-session",
    expiresAtMs: NOW + 366 * 86400000 }), true);
});

test("desktop delegation is unavailable when config is disabled and mode alone never widens browser grants", async t => {
  const f = await fixture(t);
  f.pending("browser-preview");
  const browser = f.desktop().start("browser-preview", true);
  assert.equal(browser.desktop, undefined);
  assert.equal(f.auth().desktopGrants().length, 0);
  assert.equal(await f.desktop().authorize(desktopOperation(f.operation)), false);
  assert.throws(() => f.desktop().startDesktop("browser-preview"), /already been used/u);
  f.pending("desktop-preview");
  const desktop = f.desktop().startDesktop("desktop-preview");
  const disabled = f.desktop(false);
  assert.equal(disabled.status(desktop.id), undefined);
  assert.deepEqual(disabled.list("owner-1"), [browser]);
  assert.equal(await disabled.authorize(desktopOperation(f.operation)), false);
  assert.throws(() => disabled.startDesktop("desktop-preview"), /not enabled/u);
  assert.equal(await disabled.authorize(f.operation), true);
});

test("desktop delegation rejects wrong principal, policy, scope, target, sensitive apps and explicit-only submissions", async t => {
  const f = await fixture(t);
  f.pending("desktop-preview");
  const sessions = f.desktop(); sessions.startDesktop("desktop-preview");
  const operation = desktopOperation(f.operation);
  for (const changed of [{ principalId: "other" }, { policyVersion: "policy-2" }, { expiresAtMs: NOW },
    { tool: "mac_terminal_exec" }, { tool: "mac_write_file_atomic" }, { tool: "mac_ui_observe" },
    { appId: "bundle:*" }, { appId: "desktop" }, { appId: "bundle:com.apple.SecurityAgent" },
    { appId: "bundle:com.apple.systempreferences" }, { targetKind: "app" },
    { targetRef: "app_window:window:bundle:com.google.Chrome" }, { requiresExplicitApproval: true },
    { tool: "mac_ui_type", targetKind: "ui_element", targetRef: "ui_element:invalid" }]) {
    assert.equal(await sessions.authorize({ ...operation, ...changed,
      ...("appId" in changed ? { targetRef: `app_window:window:${changed.appId}` } : {}) }), false);
  }
  assert.deepEqual(sessions.list("other"), []);
  assert.equal(f.issued.length, 0);
  f.store.revoke("session", operation.sessionId, "OWNER_REVOKED", NOW);
  assert.equal(await sessions.authorize(operation), false);
  assert.equal(await sessions.authorize({ ...operation, requestId: "fresh-owner-session", sessionId: "fresh-session" }), true);
  f.store.revoke("principal", operation.principalId, "OWNER_REVOKED", NOW);
  assert.equal(await sessions.authorize({ ...operation, requestId: "revoked-owner", sessionId: "fresh-session" }), false);
});

test("desktop consent never reuses browser consent and requires a current GUI launch or focus preview", async t => {
  const f = await fixture(t);
  const sessions = f.desktop();
  assert.throws(() => sessions.startDesktop("missing"), /current concrete app/u);
  f.pending("action-preview", "mac_ui_action");
  assert.throws(() => sessions.startDesktop("action-preview"), /current concrete app/u);
  f.pending("expired-preview");
  f.setNow(NOW + 600_000);
  assert.throws(() => sessions.startDesktop("expired-preview"), /current concrete app/u);
  f.setNow(NOW);
  f.pending("desktop-preview");
  sessions.startDesktop("desktop-preview");
  assert.throws(() => sessions.start("desktop-preview", true), /already been used/u);
  f.store.revoke("session", "session-1", "OWNER_REVOKED", NOW);
  f.pending("revoked-preview");
  assert.throws(() => sessions.startDesktop("revoked-preview"), /current concrete app/u);
});

test("desktop revocation and global auth reset persist and cannot be undone by replay", async t => {
  const f = await fixture(t); f.pending("desktop-preview");
  const sessions = f.desktop(); const grant = sessions.startDesktop("desktop-preview");
  assert.equal(await sessions.authorize(desktopOperation(f.operation)), true);
  sessions.revoke(grant.id);
  assert.equal(f.auth().desktopGrants()[0]?.revoked, true);
  assert.equal(f.store.approvalRecord(f.issued[0]!)?.revokedAtMs, NOW);
  assert.equal(await sessions.authorize({ ...desktopOperation(f.operation), requestId: "after-revocation" }), false);
  assert.throws(() => sessions.startDesktop("desktop-preview"), /already been used/u);
  sessions.close(); f.reopen();
  const restarted = f.desktop();
  assert.deepEqual(restarted.list("owner-1"), []);
  assert.throws(() => restarted.startDesktop("desktop-preview"), /already been used/u);
  f.pending("second-desktop-preview");
  const second = restarted.startDesktop("second-desktop-preview");
  f.auth().revokeAll();
  assert.equal(restarted.status(second.id), undefined);
  assert.equal(f.auth().desktopGrants().every(record => record.revoked), true);
  assert.equal(await restarted.authorize(desktopOperation(f.operation)), false);
});

for (const revocation of ["desktop", "session", "principal", "policy", "reset", "expiry"] as const) {
  test(`desktop ${revocation} change during issuance rejects and revokes the committed exact approval`, async t => {
    const f = await fixture(t); f.pending("desktop-preview");
    let finish!: () => void; const gate = new Promise<void>(resolve => { finish = resolve; });
    let approvalId = "";
    let clock = NOW;
    const sessions = new GuiSessionApprovals(f.store, async approval => {
      approvalId = approval.approvalId; await gate;
      f.store.issueApproval({ ...approval, approverPrincipalId: "browser-owner" });
    }, () => revocation === "expiry" ? clock : NOW, f.auth(), { allowDesktop: true });
    const grant = sessions.startDesktop("desktop-preview");
    const operation = desktopOperation(f.operation);
    const flight = sessions.authorize(operation);
    if (revocation === "desktop") sessions.revoke(grant.id);
    else if (revocation === "policy") {
      const record = f.auth().get("desktop_grant", grant.id)!;
      f.auth().put("desktop_grant", grant.id, { ...record, policyVersion: "policy-2" });
    }
    else if (revocation === "reset") f.auth().revokeAll();
    else if (revocation === "expiry") clock = operation.expiresAtMs;
    else f.store.revoke(revocation, revocation === "session" ? operation.sessionId : operation.principalId, "OWNER_REVOKED", NOW);
    finish();
    await assert.rejects(flight, /ended during issuance/u);
    assert.equal(f.store.approvalRecord(approvalId)?.revokedAtMs, revocation === "expiry" ? operation.expiresAtMs : NOW);
  });
}

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


test("browser launch consent shares the finite grant without authorizing arbitrary applications", async t => {
  const f = await fixture(t); f.pending("open-consent", "mac_app_open");
  const grant = f.sessions.start("open-consent");
  const operation = { ...f.operation, tool: "mac_app_open", targetKind: "app", targetRef: "app:bundle:com.google.Chrome" };
  assert.equal(await f.sessions.authorize(operation), true);
  assert.equal(f.sessions.status(grant.id)?.remainingOperations, 499);
  assert.equal(await f.sessions.authorize({ ...operation, targetRef: "app:bundle:com.apple.Safari" }), false);
  assert.equal(await f.sessions.authorize({ ...operation, appId: "bundle:com.apple.finder", targetRef: "app:bundle:com.apple.finder" }), false);
  f.setNow(NOW + GUI_SESSION_MS);
  assert.equal(await f.sessions.authorize(operation), false);
});

test("default browser access grants ordinary Chrome browsing to the owner only, and never overrides explicit approval or revocation", async t => {
  const f = await fixture(t);
  const issue = async (approval: Parameters<ConstructorParameters<typeof GuiSessionApprovals>[1]>[0]) => {
    f.store.issueApproval({ ...approval, approverPrincipalId: "browser-owner" });
  };
  const make = (principal?: string) => new GuiSessionApprovals(f.store, issue, () => NOW, f.auth(),
    principal === undefined ? {} : { defaultBrowserPrincipalId: principal });
  assert.equal(await make().authorize(f.operation), false);
  assert.equal(f.auth().browserGrants().length, 0);

  const sessions = make("owner-1");
  assert.equal(await sessions.authorize({ ...f.operation, principalId: "other" }), false);
  assert.equal(await sessions.authorize({ ...f.operation, appId: "com.apple.TextEdit" }), false);
  assert.equal(await sessions.authorize({ ...f.operation, requiresExplicitApproval: true }), false);
  assert.equal(await sessions.authorize({ ...f.operation, tool: "mac_write_file_atomic" }), false);
  assert.equal(f.auth().browserGrants().length, 0);
  assert.equal(f.auth().desktopGrants().length, 0);

  assert.equal(await sessions.authorize(f.operation), true);
  const [grant] = f.auth().browserGrants();
  assert.equal(grant?.revoked, false);
  assert.equal(grant?.policyVersion, "policy-1");
  assert.equal(grant?.appId, "bundle:com.google.Chrome");
  assert.equal(f.auth().desktopGrants().length, 0);

  f.reopen();
  const reopened = new GuiSessionApprovals(f.store, issue, () => NOW, f.auth(), { defaultBrowserPrincipalId: "owner-1" });
  assert.equal(await reopened.authorize({ ...f.operation, requestId: "operation-2" }), true);
  assert.equal(f.auth().browserGrants().length, 1);

  reopened.revoke(grant!.id);
  assert.equal(await reopened.authorize({ ...f.operation, requestId: "operation-3" }), false);
  assert.equal(f.auth().browserGrants().length, 1);
  assert.equal(await reopened.authorize({ ...f.operation, requestId: "operation-4", policyVersion: "policy-2" }), true);
  assert.equal(f.auth().browserGrants().filter(record => !record.revoked && record.policyVersion === "policy-2").length, 1);
});

test("defaultBrowserAccess config is limited to GUI grant profiles", () => {
  const base = { version: 1, issuer: "https://mcp.example.com/", resource: "https://mcp.example.com/mcp", issuerId: "mac-operator-auth",
    principalId: "owner-1", keyId: "key-1", port: 3444, allowedRedirectUris: ["https://claude.ai/api/mcp/auth_callback"] };
  assert.equal(configSchema.safeParse({ ...base, grantProfile: "g1", defaultBrowserAccess: true }).success, true);
  assert.equal(configSchema.safeParse({ ...base, grantProfile: "r1", defaultBrowserAccess: true }).success, false);
});
