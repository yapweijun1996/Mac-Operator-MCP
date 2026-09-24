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

test("stored Request state/result mismatches fail closed during startup", async () => {
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
    let reopened: BrokerStore | undefined;
    try {
      assert.throws(
        () => { reopened = new BrokerStore(databasePath); },
        (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
      );
    } finally {
      reopened?.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("stored Request timestamp ordering is enforced during startup", async () => {
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
    let reopened: BrokerStore | undefined;
    try {
      assert.throws(
        () => { reopened = new BrokerStore(databasePath); },
        (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
      );
    } finally {
      reopened?.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("stored Request target and result text remain bounded during startup", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-request-text-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  store.admitRequest(requestInput("request:corrupt-text"));
  store.close();
  try {
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare("UPDATE requests SET state = 'FAILED', result_class = ?, target_ref = ? WHERE request_id = ?")
        .run("EXECUTION_FAILED", `host:${"x".repeat(4_096)}`, "request:corrupt-text");
    } finally {
      database.close();
    }
    let reopened: BrokerStore | undefined;
    try {
      assert.throws(
        () => { reopened = new BrokerStore(databasePath); },
        (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
      );
    } finally {
      reopened?.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("stored Request identity fields fail closed before reconciliation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-request-identity-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  store.admitRequest(requestInput("request:corrupt-identity"));
  store.close();
  try {
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare("UPDATE requests SET principal_id = ?, payload_digest = ? WHERE request_id = ?")
        .run("bad principal", "not-a-digest", "request:corrupt-identity");
    } finally {
      database.close();
    }
    let reopened: BrokerStore | undefined;
    try {
      assert.throws(
        () => { reopened = new BrokerStore(databasePath); },
        (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
      );
    } finally {
      reopened?.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("stored Request Edge-key identity must be bound to its Edge before startup", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-request-edge-key-corruption-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  store.admitRequest({ ...requestInput("request:corrupt-edge-key"), edgeKeyId: "edge:local:key-1" });
  store.close();
  try {
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare("UPDATE requests SET edge_key_id = ? WHERE request_id = ?")
        .run("edge:other:key-1", "request:corrupt-edge-key");
    } finally {
      database.close();
    }
    let reopened: BrokerStore | undefined;
    try {
      assert.throws(
        () => { reopened = new BrokerStore(databasePath); },
        (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
      );
    } finally {
      reopened?.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
