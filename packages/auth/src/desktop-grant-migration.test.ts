import assert from "node:assert/strict";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { BrokerPolicy, TargetRule } from "@mac-operator/broker";
import { desktopGrantsForUnchangedGuiPolicy } from "./desktop-grant-migration.js";
import { AuthStore } from "./store.js";

const guiRule: TargetRule = { ruleId: "desktop-observe", effect: "allow", principalId: "owner-1",
  scope: "mac.ui.observe", target: { kind: "app_window", reference: "desktop" } };
const prior: Pick<BrokerPolicy, "version" | "targetRules"> = { version: "policy-1", targetRules: [guiRule] };
const grant = { id: "gui-session:12345678-1234-1234-1234-123456789abc", principalId: "owner-1",
  policyVersion: prior.version, consentRequestId: "owner-desktop-consent", createdAt: 1_700_000_000_000, revoked: false };

async function fixture(t: import("node:test").TestContext): Promise<AuthStore> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mop-desktop-grant-migration-")));
  const store = new AuthStore(root, true);
  t.after(async () => { store.close(); await rm(root, { recursive: true, force: true }); });
  store.put("desktop_grant", grant.id, grant);
  return store;
}

test("desktop consent rebind preserves identity and consent when signed GUI authority is unchanged", async t => {
  const store = await fixture(t);
  const next: typeof prior = { version: "policy-2", targetRules: [...prior.targetRules,
    { ruleId: "owner-terminal", effect: "allow", principalId: "owner-1", scope: "mac.terminal.exec",
      target: { kind: "host", reference: "owner-terminal" } }] };
  const selected = desktopGrantsForUnchangedGuiPolicy(store, "desktop", "owner-1", prior, next);
  assert.deepEqual(selected, [grant]);
  assert.deepEqual(store.get("desktop_grant", grant.id), grant, "selection must not mutate authority");
  store.transaction(() => { for (const value of selected) store.put("desktop_grant", value.id, { ...value, policyVersion: next.version }); });
  assert.deepEqual(store.get("desktop_grant", grant.id), { ...grant, policyVersion: next.version });
});

test("desktop consent rebind requires desktop configuration and excludes revoked, other owner and stale records", async t => {
  const store = await fixture(t);
  for (const [suffix, change] of [["1", { revoked: true }], ["2", { principalId: "owner-2" }], ["3", { policyVersion: "policy-0" }]] as const) {
    const id = grant.id.replace(/c$/u, suffix);
    store.put("desktop_grant", id, { ...grant, id, ...change });
  }
  const next = { ...prior, version: "policy-2" };
  assert.deepEqual(desktopGrantsForUnchangedGuiPolicy(store, undefined, "owner-1", prior, next), []);
  assert.deepEqual(desktopGrantsForUnchangedGuiPolicy(store, "browsers", "owner-1", prior, next), []);
  assert.deepEqual(desktopGrantsForUnchangedGuiPolicy(store, "desktop", "owner-1", prior, next), [grant]);
});

test("desktop consent remains unmodified when any signed GUI rule changes", async t => {
  const store = await fixture(t);
  const before = store.desktopGrants();
  for (const changed of [{ ...guiRule, effect: "deny" as const },
    { ...guiRule, target: { kind: "app_window" as const, reference: "window:bundle:com.google.Chrome" } },
    { ...guiRule, scope: "mac.ui.control" as const }, { ...guiRule, principalId: "owner-2" }]) {
    assert.throws(() => desktopGrantsForUnchangedGuiPolicy(store, "desktop", "owner-1", prior,
      { version: "policy-2", targetRules: [changed] }), /changed GUI authority/u);
    assert.deepEqual(store.desktopGrants(), before);
  }
});
