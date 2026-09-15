import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";

test("stored audit rows reject malformed bounded fields before readback", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-row-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  try {
    store.admitRequest({
      requestId: "request:audit-row",
      edgeId: "edge:local",
      nonce: "nonce-audit-row",
      nonceExpiresAtMs: 100,
      principalId: "principal-1",
      sessionId: "session-1",
      tool: "mac_health",
      policyVersion: "policy-0.1",
      payloadDigest: "a".repeat(64),
      mutation: false,
      receivedAtMs: 1
    });
    store.recordRequestDecision({
      requestId: "request:audit-row",
      principalId: "principal-1",
      tool: "mac_health",
      eventType: "decision",
      decision: "allow",
      resultClass: "AUTHORIZED",
      targetRef: "host:broker",
      policyVersion: "policy-0.1",
      evidence: {},
      timestampMs: 2
    });
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare("UPDATE audit_events SET tool = ? WHERE sequence = 1").run("mac_" + "x".repeat(200));
    } finally {
      database.close();
    }
    assert.throws(
      () => store.auditRows(),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
