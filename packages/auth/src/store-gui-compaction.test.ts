import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { GUI_SESSION_PREVIEW_TTL_MS } from "@mac-operator/broker";
import { AuthStore } from "./store.js";

const NOW = 1_700_000_000_000;
const key = (consent: string) => createHash("sha256").update(consent).digest("hex");
const grantId = (index: number) => `gui-session:00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`;
async function fixture(t: test.TestContext) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "auth-gui-compact-")));
  let store = new AuthStore(root, true);
  t.after(async () => { store.close(); await rm(root, { recursive: true, force: true }); });
  return { root, store: () => store, reopen: () => { store.close(); store = new AuthStore(root); } };
}
function browser(index: number, consentRequestId = `consent-${index}`, revoked = true) {
  return { id: grantId(index), principalId: "owner", sessionId: "session", appId: "bundle:com.google.Chrome" as const,
    policyVersion: "policy-1", consentRequestId, createdAt: NOW, revoked };
}

for (const kind of ["browser_grant", "desktop_grant"] as const) {
  test(`${kind} compaction keeps active authority and live consent tombstones across restart`, async t => {
    const f = await fixture(t);
    const put = (index: number, revoked: boolean) => {
      const { sessionId: _session, appId: _app, ...record } = browser(index, `consent-${index}`, revoked);
      if (kind === "browser_grant") f.store().put(kind, record.id, browser(index, `consent-${index}`, revoked));
      else f.store().put(kind, record.id, record);
    };
    put(1, true); put(2, false);
    f.store().prune(NOW);
    assert.equal(f.store().get(kind, grantId(1)), undefined);
    assert.ok(f.store().get(kind, grantId(2)));
    assert.equal(f.store().hasGuiConsent("consent-1"), true);
    assert.equal(f.store().hasGuiConsent("consent-2"), true);
    assert.equal(f.store().get("gui_consent_tombstone", key("consent-1"))?.expiresAt, NOW + GUI_SESSION_PREVIEW_TTL_MS);
    f.reopen();
    assert.equal(f.store().hasGuiConsent("consent-1"), true);
    f.store().prune(NOW + GUI_SESSION_PREVIEW_TTL_MS);
    assert.equal(f.store().hasGuiConsent("consent-1"), false);
    assert.ok(f.store().get(kind, grantId(2)), "active permanent grants never expire during pruning");
  });
}

test("expired ordinary revoked history needs no tombstones and defaults never expire", async t => {
  const f = await fixture(t);
  f.store().put("browser_grant", grantId(1), browser(1));
  for (const [index, consent] of [[2, "default-browser:owner:bundle:com.google.Chrome:policy-1"],
    [3, `default-browser-v2:${"a".repeat(64)}`]] as const) f.store().put("browser_grant", grantId(index), browser(index, consent));
  f.store().prune(NOW + GUI_SESSION_PREVIEW_TTL_MS);
  assert.equal(f.store().get("gui_consent_tombstone", key("consent-1")), undefined);
  f.reopen();
  f.store().prune(Number.MAX_SAFE_INTEGER);
  assert.equal(f.store().hasGuiConsent("default-browser:owner:bundle:com.google.Chrome:policy-1"), true);
  assert.equal(f.store().hasGuiConsent(`default-browser-v2:${"a".repeat(64)}`), true);
});

test("a full tombstone kind retains additional revocations instead of evicting replay evidence", async t => {
  const f = await fixture(t);
  f.store().transaction(() => {
    for (let index = 0; index < 1000; index++) {
      const consentRequestId = `default-browser-v2:${index.toString(16).padStart(64, "0")}`;
      f.store().put("gui_consent_tombstone", key(consentRequestId), { consentRequestId });
    }
  });
  f.store().put("browser_grant", grantId(1), browser(1, "default-browser:owner:bundle:com.google.Chrome:policy-1"));
  f.store().prune(NOW);
  assert.equal(f.store().get("browser_grant", grantId(1))?.revoked, true);
  assert.equal(f.store().hasGuiConsent("default-browser:owner:bundle:com.google.Chrome:policy-1"), true);
  assert.throws(() => f.store().put("gui_consent_tombstone", key("overflow"), { consentRequestId: "overflow" }), /capacity/u);
  f.reopen();
  assert.equal(f.store().hasGuiConsent("default-browser:owner:bundle:com.google.Chrome:policy-1"), true);
  assert.equal(f.store().hasGuiConsent(`default-browser-v2:${"0".repeat(64)}`), true);
});

test("failed tombstone persistence rolls back removal of the original revoked row", async t => {
  const f = await fixture(t);
  f.store().put("browser_grant", grantId(1), browser(1));
  const db = new DatabaseSync(join(f.root, "auth.sqlite"));
  db.exec("CREATE TRIGGER reject_gui_marker BEFORE INSERT ON records WHEN NEW.kind='gui_consent_tombstone' BEGIN SELECT RAISE(ABORT,'injected'); END;");
  db.close();
  assert.throws(() => f.store().prune(NOW), /Auth state unavailable/u);
  f.reopen();
  assert.equal(f.store().get("browser_grant", grantId(1))?.revoked, true);
  assert.equal(f.store().get("gui_consent_tombstone", key("consent-1")), undefined);
});

test("tombstone identity validation fails closed on insertion, lookup and restart", async t => {
  const f = await fixture(t);
  assert.throws(() => f.store().put("gui_consent_tombstone", key("wrong"), { consentRequestId: "consent-1" }), /identity/u);
  const db = new DatabaseSync(join(f.root, "auth.sqlite"));
  db.prepare("INSERT INTO records VALUES(?,?,?)").run("gui_consent_tombstone", key("consent-1"), JSON.stringify({ consentRequestId: "wrong" }));
  db.close();
  assert.throws(() => f.store().hasGuiConsent("consent-1"), /Auth state unavailable/u);
  assert.throws(() => new AuthStore(f.root), /record kind=gui_consent_tombstone invalid/u);
});

test("ordinary revocation history can be reclaimed repeatedly after the maximum preview lifetime", async t => {
  const f = await fixture(t);
  for (let cycle = 0; cycle < 3; cycle++) {
    const createdAt = NOW + cycle * GUI_SESSION_PREVIEW_TTL_MS;
    f.store().transaction(() => {
      for (let index = 0; index < 1000; index++) {
        const offset = cycle * 1000 + index;
        f.store().put("browser_grant", grantId(offset), { ...browser(offset), createdAt });
      }
    });
    f.store().prune(createdAt);
    assert.equal(f.store().browserGrants().length, 0);
    assert.equal(f.store().hasGuiConsent(`consent-${cycle * 1000}`), true);
    f.store().prune(createdAt + GUI_SESSION_PREVIEW_TTL_MS);
    assert.equal(f.store().hasGuiConsent(`consent-${cycle * 1000}`), false);
    f.reopen();
  }
});

test("default revocation markers cannot be made expiring through the supported record schema", async t => {
  const f = await fixture(t);
  for (const consentRequestId of ["default-browser:owner:bundle:com.google.Chrome:policy-1", `default-browser-v2:${"b".repeat(64)}`]) {
    assert.throws(() => f.store().put("gui_consent_tombstone", key(consentRequestId), { consentRequestId, expiresAt: NOW }));
  }
});
