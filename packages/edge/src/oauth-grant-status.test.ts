import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { createOAuthGrantStatusReader, OAuthGrantRevocationMonitor } from "./oauth-grant-status.js";
import type { JwtRevocationContext } from "./jwt-verifier.js";

const statusUrl = new URL("https://issuer.example.test/oauth/status");
const context: JwtRevocationContext = {
  scopes: ["mac.control.read"],
  issuerId: "issuer-prod",
  subject: "principal-1",
  sessionId: "a".repeat(64),
  tokenId: "b".repeat(64),
  expiresAt: Math.floor(Date.now() / 1_000) + 60
};

test("OAuth status reader preserves explicit inactive authority and bounded scopes", async () => {
  const reader = createOAuthGrantStatusReader({
    url: statusUrl,
    key: Buffer.alloc(32, 7),
    fetch: async () => new Response(JSON.stringify({ active: false, scopes: [] }), {
      status: 200,
      headers: { "content-type": "application/json" }
    })
  });
  assert.deepEqual(await reader(context), { active: false, scopes: [] });
});

test("OAuth revocation monitor retries status outages and propagates idle-session revocation", async () => {
  let reads = 0;
  let revoked: JwtRevocationContext | undefined;
  const monitor = new OAuthGrantRevocationMonitor({
    intervalMs: 250,
    readStatus: async () => {
      reads++;
      if (reads === 1) throw new Error("temporary status outage");
      return { active: false, scopes: [] };
    },
    onRevoked: async (value) => {
      revoked = value;
    }
  });
  try {
    monitor.track(context);
    monitor.start();
    await delay(700);
    assert.ok(reads >= 2);
    assert.deepEqual(revoked, context);
  } finally {
    monitor.stop();
  }
});

test("OAuth revocation monitor accepts a direct issuer push and removes the retry entry after Broker propagation", async () => {
  let readCalls = 0;
  let propagated: JwtRevocationContext | undefined;
  const monitor = new OAuthGrantRevocationMonitor({
    intervalMs: 250,
    readStatus: async () => {
      readCalls++;
      return { active: true, scopes: context.scopes };
    },
    onRevoked: async value => { propagated = value; }
  });
  try {
    monitor.track(context);
    await monitor.notifyRevoked(context);
    assert.deepEqual(propagated, context);
    monitor.start();
    await new Promise(resolve => setTimeout(resolve, 300));
    assert.equal(readCalls, 0);
  } finally {
    monitor.stop();
  }
});
