import assert from "node:assert/strict";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AuthStore } from "./store.js";

const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;

test("compactConsumedRefresh keeps the newest consumed tokens and every live token of the grant", async t => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mac-auth-refresh-")));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new AuthStore(directory, true);
  t.after(() => store.close());
  for (let index = 0; index < 30; index++) {
    store.put("refresh", `old-${index}`, { clientId: "client", grantId: "grant-a", expiresAt, consumed: true });
  }
  store.put("refresh", "other-consumed", { clientId: "client", grantId: "grant-b", expiresAt, consumed: true });
  store.put("refresh", "live", { clientId: "client", grantId: "grant-a", expiresAt, consumed: false });
  assert.equal(store.compactConsumedRefresh("grant-a", 5), 25);
  assert.equal(store.get("refresh", "old-24"), undefined);
  assert.ok(store.get("refresh", "old-25"));
  assert.ok(store.get("refresh", "old-29"));
  assert.ok(store.get("refresh", "live"));
  assert.ok(store.get("refresh", "other-consumed"));
  assert.equal(store.compactConsumedRefresh("grant-a", 5), 0);
});

test("a refresh table full of consumed tokens accepts a new token once compacted", async t => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mac-auth-refresh-full-")));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new AuthStore(directory, true);
  t.after(() => store.close());
  for (let index = 0; index < 1000; index++) {
    store.put("refresh", `old-${index}`, { clientId: "client", grantId: "grant-a", expiresAt, consumed: true });
  }
  assert.throws(() => store.put("refresh", "new", { clientId: "client", grantId: "grant-a", expiresAt, consumed: false }), /Auth capacity exceeded/u);
  store.compactConsumedRefresh("grant-a", 16);
  store.put("refresh", "new", { clientId: "client", grantId: "grant-a", expiresAt, consumed: false });
  assert.ok(store.get("refresh", "new"));
});

test("evictOldConsumedRefresh frees a full table for a new login and keeps live tokens", async t => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mac-auth-refresh-global-")));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new AuthStore(directory, true);
  t.after(() => store.close());
  for (let index = 0; index < 994; index++) {
    store.put("refresh", `old-${index}`, { clientId: "client", grantId: `grant-${index % 7}`, expiresAt, consumed: true });
  }
  for (let index = 0; index < 6; index++) {
    store.put("refresh", `live-${index}`, { clientId: "client", grantId: `grant-${index}`, expiresAt, consumed: false });
  }
  assert.throws(() => store.put("refresh", "new-login", { clientId: "client", grantId: "grant-new", expiresAt, consumed: false }), /Auth capacity exceeded/u);
  assert.equal(store.evictOldConsumedRefresh(500), 494);
  store.put("refresh", "new-login", { clientId: "client", grantId: "grant-new", expiresAt, consumed: false });
  assert.ok(store.get("refresh", "live-0"));
  assert.ok(store.get("refresh", "old-993"));
  assert.equal(store.get("refresh", "old-0"), undefined);
});
