import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { BrokerError, sha256 } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";

function requestInput(requestId: string) {
  return {
    requestId,
    edgeId: "edge:local",
    nonce: `nonce-${requestId}`,
    nonceExpiresAtMs: 100,
    principalId: "principal-1",
    sessionId: "session-1",
    tool: "mac_health",
    policyVersion: "policy-0.1",
    payloadDigest: sha256(requestId),
    mutation: false,
    receivedAtMs: 1
  } as const;
}

test("stored Request state/result mismatches fail closed on readback", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-request-corruption-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  store.admitRequest(requestInput("request:corrupt-state"));
  store.close();
  try {
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare("UPDATE requests SET state = 'FAILED', result_class = 'AUTHORIZED' WHERE request_id = ?")
        .run("request:corrupt-state");
    } finally {
      database.close();
    }
    const reopened = new BrokerStore(databasePath);
    try {
      assert.throws(
        () => reopened.requestRecord("request:corrupt-state"),
        (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
      );
    } finally {
      reopened.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("stored Request timestamp ordering is enforced before Broker decisions", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-request-timestamps-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  store.admitRequest(requestInput("request:corrupt-time"));
  store.close();
  try {
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare("UPDATE requests SET state = 'FAILED', result_class = 'EXECUTION_FAILED', updated_at_ms = 0 WHERE request_id = ?")
        .run("request:corrupt-time");
    } finally {
      database.close();
    }
    const reopened = new BrokerStore(databasePath);
    try {
      assert.throws(
        () => reopened.requestRecord("request:corrupt-time"),
        (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
      );
    } finally {
      reopened.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
