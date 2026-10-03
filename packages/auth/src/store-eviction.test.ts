import assert from "node:assert/strict";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AuthStore } from "./store.js";

const redirectUris = ["https://client.test/callback"];

test("evictUnusedClients removes the oldest unreferenced clients and keeps clients with grants", async t => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mac-auth-evict-")));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new AuthStore(directory, true);
  t.after(() => store.close());
  for (let index = 0; index < 5; index++) {
    store.put("client", `client-${index}`, { id: `client-${index}`, name: "MCP client", redirectUris, expiresAt: Number.MAX_SAFE_INTEGER });
  }
  store.put("grant", "grant-0", { clientId: "client-0", principalId: "owner", scopes: ["mac.control.read"], expiresAt: Date.now() + 60_000, revoked: false });
  assert.equal(store.evictUnusedClients(2), 2);
  assert.ok(store.get("client", "client-0"));
  assert.equal(store.get("client", "client-1"), undefined);
  assert.equal(store.get("client", "client-2"), undefined);
  assert.ok(store.get("client", "client-3"));
  assert.equal(store.evictUnusedClients(100), 2);
  assert.ok(store.get("client", "client-0"));
  assert.equal(store.evictUnusedClients(100), 0);
});

test("a full client table accepts a new registration only after eviction frees a slot", async t => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mac-auth-full-")));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new AuthStore(directory, true);
  t.after(() => store.close());
  for (let index = 0; index < 1000; index++) {
    store.put("client", `client-${index}`, { id: `client-${index}`, name: "MCP client", redirectUris, expiresAt: Number.MAX_SAFE_INTEGER });
  }
  assert.throws(() => store.put("client", "client-new", { id: "client-new", name: "MCP client", redirectUris, expiresAt: Number.MAX_SAFE_INTEGER }), /Auth capacity exceeded/u);
  assert.equal(store.evictUnusedClients(100), 100);
  store.put("client", "client-new", { id: "client-new", name: "MCP client", redirectUris, expiresAt: Number.MAX_SAFE_INTEGER });
  assert.ok(store.get("client", "client-new"));
  assert.equal(store.get("client", "client-0"), undefined);
});

test("pruneConsumedRefreshTokens keeps the newest consumed hashes and every live token", async t => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mac-auth-refresh-")));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new AuthStore(directory, true);
  t.after(() => store.close());
  const expiresAt = Date.now() + 60_000;
  for (let index = 0; index < 6; index++) store.put("refresh", `old-${index}`, { clientId: "client-1", grantId: "grant-1", expiresAt, consumed: true });
  store.put("refresh", "other-consumed", { clientId: "client-1", grantId: "grant-2", expiresAt, consumed: true });
  store.put("refresh", "live", { clientId: "client-1", grantId: "grant-1", expiresAt, consumed: false });
  store.pruneConsumedRefreshTokens("grant-1", 3);
  for (const gone of ["old-0", "old-1", "old-2"]) assert.equal(store.get("refresh", gone), undefined, gone);
  for (const kept of ["old-3", "old-4", "old-5", "live", "other-consumed"]) assert.ok(store.get("refresh", kept), kept);
});
