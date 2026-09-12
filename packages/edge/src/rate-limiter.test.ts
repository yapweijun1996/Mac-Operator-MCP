import assert from "node:assert/strict";
import test from "node:test";
import { FixedWindowRateLimiter } from "./rate-limiter.js";

test("fixed-window limiter bounds requests and reports retry time", () => {
  const limiter = new FixedWindowRateLimiter({ windowMs: 1_000, maxRequests: 2, maxKeys: 4 });
  assert.deepEqual(limiter.consume("client-1", 10_000), { allowed: true, remaining: 1, retryAfterMs: 0 });
  assert.deepEqual(limiter.consume("client-1", 10_100), { allowed: true, remaining: 0, retryAfterMs: 0 });
  assert.deepEqual(limiter.consume("client-1", 10_200), { allowed: false, remaining: 0, retryAfterMs: 800 });
  assert.deepEqual(limiter.consume("client-1", 11_000), { allowed: true, remaining: 1, retryAfterMs: 0 });
});

test("fixed-window limiter prunes expired identities and fails closed at key capacity", () => {
  const limiter = new FixedWindowRateLimiter({ windowMs: 1_000, maxRequests: 1, maxKeys: 1 });
  assert.equal(limiter.consume("client-1", 10_000).allowed, true);
  assert.equal(limiter.consume("client-2", 10_100).allowed, false);
  assert.equal(limiter.size(), 1);
  assert.equal(limiter.consume("client-2", 11_000).allowed, true);
  assert.equal(limiter.size(), 1);
});

test("fixed-window limiter rejects malformed identities", () => {
  const limiter = new FixedWindowRateLimiter();
  assert.throws(() => limiter.consume("../secret", 10_000), /identity/u);
  assert.throws(() => limiter.consume("client-1", -1), /clock/u);
});
