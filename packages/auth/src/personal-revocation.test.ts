import assert from "node:assert/strict";
import test from "node:test";
import { SCOPES } from "@mac-operator/contracts";
import { AUTH_REVOCATION_TYPE, createAuthRevocationQueue, parseAuthGrantRevocation, toJwtRevocationContext } from "./personal-revocation.js";

const valid = {
  type: AUTH_REVOCATION_TYPE,
  grantId: "a".repeat(64),
  principalId: "owner-1",
  scopes: [SCOPES[0]!],
  expiresAtMs: 1_800_000_000_000
};

test("Auth revocation notice parser freezes a bounded non-secret message", () => {
  const parsed = parseAuthGrantRevocation(valid);
  assert.ok(parsed);
  assert.equal(Object.isFrozen(parsed), true);
  assert.equal(Object.isFrozen(parsed.scopes), true);
  assert.deepEqual(toJwtRevocationContext(parsed, "mac-operator-auth"), {
    issuerId: "mac-operator-auth",
    subject: "owner-1",
    sessionId: "a".repeat(64),
    tokenId: `auth-grant:${"a".repeat(64)}`,
    expiresAt: 1_800_000_000,
    scopes: [SCOPES[0]]
  });
});

test("Auth revocation notice parser rejects expansion, duplicates, accessors, and foreign prototypes", () => {
  assert.equal(parseAuthGrantRevocation({ ...valid, extra: true }), undefined);
  assert.equal(parseAuthGrantRevocation({ ...valid, scopes: ["mac.unknown"] }), undefined);
  assert.equal(parseAuthGrantRevocation({ ...valid, scopes: [SCOPES[0], SCOPES[0]] }), undefined);
  const accessor = { ...valid } as Record<string, unknown>;
  Object.defineProperty(accessor, "grantId", { enumerable: true, get: () => valid.grantId });
  assert.equal(parseAuthGrantRevocation(accessor), undefined);
  assert.equal(parseAuthGrantRevocation(Object.assign(Object.create({ inherited: true }), valid)), undefined);
  assert.equal(parseAuthGrantRevocation({ ...valid, expiresAtMs: Number.MAX_SAFE_INTEGER + 1 }), undefined);
});

test("Auth revocation queue preserves order and fails closed on transport loss", async () => {
  const second = { ...valid, grantId: "b".repeat(64) };
  let connected = false;
  let sendCount = 0;
  const sent: string[] = [];
  let fatal: Error | undefined;
  const queue = createAuthRevocationQueue({
    isConnected: () => connected,
    send: (message, callback) => {
      sent.push(message.grantId);
      sendCount += 1;
      queueMicrotask(() => callback(sendCount === 2 ? new Error("transport closed") : null));
    },
    onSendFailure: error => { fatal = error; }
  });
  queue.enqueue(valid);
  queue.enqueue(second);
  assert.equal(queue.pendingCount(), 2);
  queue.flush();
  assert.deepEqual(sent, []);

  connected = true;
  queue.flush();
  await new Promise<void>(resolve => setImmediate(resolve));
  assert.deepEqual(sent, [valid.grantId, second.grantId]);
  assert.equal(queue.pendingCount(), 1);
  assert.equal(fatal?.message, "transport closed");
  assert.equal(queue.pendingCount(), 1);
  assert.deepEqual(sent, [valid.grantId, second.grantId]);
});

test("Auth revocation queue rejects bounded overflow instead of dropping notices", () => {
  const queue = createAuthRevocationQueue({
    isConnected: () => false,
    send: () => undefined,
    onSendFailure: () => undefined,
    maxPending: 2
  });
  queue.enqueue(valid);
  queue.enqueue({ ...valid, grantId: "c".repeat(64) });
  assert.throws(() => queue.enqueue({ ...valid, grantId: "d".repeat(64) }), /capacity exceeded/u);
  assert.equal(queue.pendingCount(), 2);
});
