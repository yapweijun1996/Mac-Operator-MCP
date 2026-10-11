import assert from "node:assert/strict";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AuthStore } from "./store.js";

test("AuthStore rejects insertions beyond the startup capacity while permitting updates and restart", async t => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mac-auth-capacity-")));
  t.after(() => rm(directory, { recursive: true, force: true }));
  let store = new AuthStore(directory, true);
  t.after(() => store.close());
  const expiresAt = Date.now() + 60_000;
  const redirectUri = "https://client.test/callback";
  const hash = "a".repeat(64);
  store.transaction(() => {
    for (let index = 0; index < 1_000; index++) {
      const clientId = `client-${index}`;
      store.put("account", `account-${index}`, { username: "owner", salt: hash, passwordHash: hash, principalId: "owner" });
      store.put("client", clientId, { id: clientId, name: "MCP client", redirectUris: [redirectUri], expiresAt });
      store.put("transaction", `transaction-${index}`, { clientId, redirectUri, state: "state", challenge: "a".repeat(43), scopes: ["mac.control.read"], expiresAt });
      store.put("session", `session-${index}`, { transactionId: hash, csrf: hash, authenticated: true, expiresAt });
      store.put("approval_session", `approval-${index}`, { requestId: `request-${index}`, csrf: hash, authenticated: true, expiresAt });
      store.put("code", `code-${index}`, { clientId, redirectUri, challenge: "challenge", scopes: ["mac.control.read"], grantId: `grant-${index}`, principalId: "owner", expiresAt });
      store.put("grant", `grant-${index}`, { clientId, principalId: "owner", scopes: ["mac.control.read"], expiresAt, revoked: false });
      store.put("refresh", `refresh-${index}`, { clientId, grantId: `grant-${index}`, expiresAt, consumed: false });
    }
  });
  const grantId = "gui-session:00000000-0000-4000-8000-000000000000";
  const browserGrant = { id: grantId, principalId: "owner", sessionId: "session-0", appId: "bundle:com.google.Chrome" as const,
    policyVersion: "policy-1", consentRequestId: "request-0", createdAt: Date.now(), revoked: false };
  assert.throws(() => store.put("browser_grant", grantId, browserGrant), /Auth capacity exceeded/u);
  store.put("client", "client-0", { id: "client-0", name: "Updated client", redirectUris: [redirectUri], expiresAt });
  store.close();
  store = new AuthStore(directory);
  assert.equal(store.get("client", "client-0")?.name, "Updated client");
  assert.equal(store.get("browser_grant", grantId), undefined);
  assert.equal(store.delete("refresh", "refresh-0"), true);
  store.put("browser_grant", grantId, browserGrant);
  store.close();
  store = new AuthStore(directory);
  assert.deepEqual(store.get("browser_grant", grantId), browserGrant);
});
