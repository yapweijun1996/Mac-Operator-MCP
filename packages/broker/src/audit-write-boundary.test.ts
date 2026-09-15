import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { BrokerStore, type AuditEvent } from "./persistence.js";

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
