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

test("client eviction preserves live transactions and authorization codes while expired flows release clients", async t => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mac-auth-live-flows-")));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new AuthStore(directory, true);
  t.after(() => store.close());
  for (let index = 0; index < 5; index++) {
    store.put("client", `client-${index}`, { id: `client-${index}`, name: "MCP client", redirectUris, expiresAt: Number.MAX_SAFE_INTEGER });
  }
  const transactionId = "a".repeat(64);
  const expiresAt = Date.now() + 60_000;
  const transaction = { clientId: "client-0", redirectUri: redirectUris[0]!, state: "state", challenge: "a".repeat(43), scopes: ["mac.control.read"] as ["mac.control.read"], expiresAt };
  store.put("transaction", transactionId, transaction);
  store.put("session", "session-0", { transactionId, csrf: "b".repeat(64), authenticated: true, expiresAt });
  store.put("code", "code-1", { clientId: "client-1", redirectUri: redirectUris[0]!, challenge: "challenge", scopes: ["mac.control.read"], grantId: "grant-1", principalId: "owner", expiresAt });
  store.put("transaction", "expired-2", { ...transaction, clientId: "client-2", expiresAt: Date.now() - 1 });
  assert.equal(store.evictUnusedClients(2), 2);
  assert.ok(store.get("client", "client-0"));
  assert.ok(store.get("client", "client-1"));
  assert.ok(store.get("session", "session-0"));
  assert.equal(store.get("client", "client-2"), undefined);
  assert.equal(store.get("client", "client-3"), undefined);
  assert.equal(store.evictUnusedClients(100), 1);
  assert.equal(store.get("client", "client-4"), undefined);
});
