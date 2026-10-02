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


for (const reverse of [false, true]) {
  test(`narrower accepted tokens preserve monitoring for active terminal authority (reverse=${reverse})`, async () => {
    const broad = { ...context, scopes: ["mac.control.read", "mac.terminal.exec"], expiresAt: Math.floor(Date.now() / 1000) + 60 };
    const narrow = { ...broad, tokenId: "narrow-token", scopes: ["mac.control.read"], expiresAt: broad.expiresAt + 60 };
    let propagated: JwtRevocationContext | undefined;
    const monitor = new OAuthGrantRevocationMonitor({ intervalMs: 250,
      readStatus: async () => ({ active: true, scopes: ["mac.control.read"] }),
      onRevoked: async value => { propagated = value; } });
    try {
      for (const value of reverse ? [narrow, broad] : [broad, narrow]) monitor.track(value);
      monitor.start();
      await delay(550);
      assert.ok(propagated);
      assert.deepEqual([...propagated.scopes].sort(), ["mac.control.read", "mac.terminal.exec"]);
      assert.equal(propagated.expiresAt, narrow.expiresAt);
    } finally { monitor.stop(); }
  });
}

test("expired terminal tokens do not extend terminal authority with a later read token", async () => {
  let now = Date.now();
  let reads = 0;
  let revocations = 0;
  const broad = { ...context, scopes: ["mac.control.read", "mac.terminal.exec"], expiresAt: Math.floor(now / 1000) + 1 };
  const narrow = { ...broad, scopes: ["mac.control.read"], expiresAt: broad.expiresAt + 60 };
  const monitor = new OAuthGrantRevocationMonitor({ intervalMs: 250, now: () => now,
    readStatus: async value => { reads++; assert.deepEqual(value.scopes, ["mac.control.read"]); return { active: true, scopes: value.scopes }; },
    onRevoked: async () => { revocations++; } });
  try {
    monitor.track(broad); monitor.track(narrow);
    now = (broad.expiresAt + 1) * 1000;
    monitor.start(); await delay(550);
    assert.ok(reads > 0); assert.equal(revocations, 0);
  } finally { monitor.stop(); }
});
