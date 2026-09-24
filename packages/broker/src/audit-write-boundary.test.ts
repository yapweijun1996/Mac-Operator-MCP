import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { BrokerStore, type AuditEvent } from "./persistence.js";

function validAuditEvent(requestId: string, evidence: unknown = {}): AuditEvent {
  return {
    requestId,
    principalId: "principal-1",
    tool: "mac_health",
    eventType: "completion",
    decision: "allow",
    resultClass: "SUCCEEDED",
    targetRef: "host:broker",
    policyVersion: "policy-0.1",
    evidence,
    timestampMs: 1
  };
}

test("malformed audit events fail before persistence", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-write-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const insertAudit = (store as unknown as { insertAudit: (event: AuditEvent) => string }).insertAudit.bind(store);
    assert.throws(
      () => insertAudit({
        requestId: "request:audit-write",
        principalId: "principal-1",
        tool: "malicious_tool",
        eventType: "completion",
        decision: "allow",
        resultClass: "SUCCEEDED",
        targetRef: "host:broker",
        policyVersion: "policy-0.1",
        evidence: {},
        timestampMs: 1
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    assert.deepEqual(store.auditRows(), []);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("append-only audit retention rejects the next write and preserves the chain", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-retention-"));
  const databasePath = join(directory, "broker.sqlite");
  const retention = { maxEvents: 2, maxBytes: 16 * 1024 };
  let store = new BrokerStore(databasePath, { auditRetention: retention });
  try {
    store.appendAudit(validAuditEvent("audit-retention-1"));
    store.appendAudit(validAuditEvent("audit-retention-2"));
    assert.throws(
      () => store.appendAudit(validAuditEvent("audit-retention-3")),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    assert.equal(store.auditRows().length, 2);
    store.close();
    store = new BrokerStore(databasePath, { auditRetention: retention });
    assert.equal(store.auditRows().length, 2);
    assert.throws(
      () => store.appendAudit(validAuditEvent("audit-retention-4")),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    assert.equal(store.auditRows().length, 2);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("audit retention rejects a persisted database that exceeds a newly selected bound", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-retention-restart-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath, { auditRetention: { maxEvents: 4, maxBytes: 16 * 1024 } });
  try {
    store.appendAudit(validAuditEvent("audit-retention-bound-1", { marker: "persisted" }));
    store.appendAudit(validAuditEvent("audit-retention-bound-2", { marker: "persisted" }));
  } finally {
    store.close();
  }
  try {
    assert.throws(
      () => new BrokerStore(databasePath, { auditRetention: { maxEvents: 1, maxBytes: 16 * 1024 } }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("audit retention rejects a single event whose logical row bytes exceed the bound", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-retention-bytes-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"), {
    auditRetention: { maxEvents: 10, maxBytes: 512 }
  });
  try {
    assert.throws(
      () => store.appendAudit(validAuditEvent("audit-retention-bytes-1", { marker: "x".repeat(2_000) })),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    assert.deepEqual(store.auditRows(), []);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
