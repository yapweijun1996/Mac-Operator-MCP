import assert from "node:assert/strict";
import test from "node:test";
import type { AuthInfo } from "@modelcontextprotocol/server";
import { isBrokerId } from "./identity.js";
import { projectPrincipal } from "./principal.js";
import { FixedWindowRateLimiter } from "./rate-limiter.js";

const resourceServerUrl = new URL("https://edge.example.test/mcp");
const samples = [
  "a", "A1", "owner:a", "owner.b_c-d", "a".repeat(128), "a".repeat(129), "",
  "-lead", ":lead", ".lead", "owner@example.test", "session/one", "has space", "uni✓", "line\nbreak"
];

function authFor(identity: string): AuthInfo {
  return {
    token: "token", clientId: "client-1", scopes: [], expiresAt: Math.floor(Date.now() / 1_000) + 60, resource: resourceServerUrl,
    extra: { principalId: identity, issuer: "issuer-prod", sessionId: "session-1", issuedAtMs: Date.now() }
  };
}

test("Broker identity validators agree on every sample so an accepted identity is usable end to end", () => {
  for (const sample of samples) {
    const expected = isBrokerId(sample);
    let projected = true;
    try { projectPrincipal(authFor(sample), { edgeId: "edge-1", brokerAudience: "broker", resourceServerUrl }); } catch { projected = false; }
    let limited = true;
    try { new FixedWindowRateLimiter().consume(sample); } catch { limited = false; }
    assert.equal(projected, expected, `principal projection disagrees for ${JSON.stringify(sample)}`);
    assert.equal(limited, expected, `rate limiter disagrees for ${JSON.stringify(sample)}`);
  }
});

test("Broker identity contract rejects non-string values", () => {
  for (const value of [undefined, null, 1, {}, ["a"]]) assert.equal(isBrokerId(value), false);
});
