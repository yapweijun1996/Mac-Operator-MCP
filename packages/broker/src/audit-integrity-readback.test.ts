import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";

function auditEvent(requestId: string, timestampMs: number) {
  return {
    requestId,
    principalId: "principal-1",
    tool: "mac_health",
    eventType: "completion" as const,
    decision: "allow" as const,
    resultClass: "SUCCEEDED",
    targetRef: "host:broker",
    policyVersion: "policy-0.1",
    evidence: { requestId, secret: "must-not-be-returned" },
    timestampMs
  };
}

test("audit integrity readback exposes only a bounded verified summary", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-readback-"));
  const databasePath = join(directory, "broker.sqlite");
  const anchorPath = join(directory, "audit.anchor");
  const store = new BrokerStore(databasePath, {
    auditAnchor: {
      path: anchorPath,
      keySource: {
        keyId: "audit-readback-key",
        loadKey: () => Buffer.from("audit-readback-key-0123456789abcdef", "ascii")
      }
    }
  });
  try {
    store.appendAudit(auditEvent("audit-readback-1", 1));
    const readback = store.auditIntegrityReadback();
    assert.deepEqual(readback, {
      format: "mac-operator-audit-integrity-v1",
      eventCount: 1,
      tailSequence: 1,
      tailHash: readback.tailHash,
      keyedAnchor: "verified"
    });
    assert.match(readback.tailHash ?? "", /^[a-f0-9]{64}$/u);
    assert.equal("evidence" in readback, false);
    assert.equal(JSON.stringify(readback).includes("must-not-be-returned"), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("audit integrity readback fails closed after a keyed-tail publication outage", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-readback-outage-"));
  const databasePath = join(directory, "broker.sqlite");
  const anchorPath = join(directory, "audit.anchor");
  const store = new BrokerStore(databasePath, {
    auditAnchor: {
      path: anchorPath,
      keySource: {
        keyId: "audit-readback-outage-key",
        loadKey: () => Buffer.from("audit-readback-outage-key-0123456789", "ascii")
      }
    }
  });
  try {
    store.appendAudit(auditEvent("audit-readback-before-outage", 1));
    await writeFile(`${anchorPath}.lock`, "operator-held\n", { mode: 0o600 });
    assert.throws(
      () => store.appendAudit(auditEvent("audit-readback-after-outage", 2)),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    assert.throws(
      () => store.auditIntegrityReadback(),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
  } finally {
    await rm(`${anchorPath}.lock`, { force: true });
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
