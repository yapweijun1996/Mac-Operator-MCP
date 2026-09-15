import assert from "node:assert/strict";
import { mkdtemp, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";

test("audit anchor outage fails closed for read-only Broker admission", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-readonly-outage-"));
  const databasePath = join(directory, "broker.sqlite");
  const anchorPath = join(directory, "audit.anchor");
  const anchorOptions = {
    path: anchorPath,
    keySource: {
      keyId: "audit-key-readonly-outage",
      loadKey: () => Buffer.from("audit-anchor-readonly-outage-key-0123456789", "ascii")
    }
  };
  const store = new BrokerStore(databasePath, { auditAnchor: anchorOptions });
  try {
    store.appendAudit({
      requestId: "audit-readonly-before",
      principalId: "principal-1",
      tool: "mac_health",
      eventType: "completion",
      decision: "allow",
      resultClass: "SUCCEEDED",
      targetRef: "host:broker",
      policyVersion: "policy-0.1",
      evidence: { persisted: true },
      timestampMs: 1
    });
    await writeFile(`${anchorPath}.lock`, "operator-held\n", { mode: 0o600 });
    assert.throws(
      () => store.appendAudit({
        requestId: "audit-readonly-failed-publication",
        principalId: "principal-1",
        tool: "mac_health",
        eventType: "completion",
        decision: "allow",
        resultClass: "SUCCEEDED",
        targetRef: "host:broker",
        policyVersion: "policy-0.1",
        evidence: { persisted: true },
        timestampMs: 2
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    await unlink(`${anchorPath}.lock`);

    assert.throws(
      () => store.admitRequest({
        requestId: "readonly-admission-after-outage",
        edgeId: "edge-1",
        nonce: "readonly-admission-after-outage-nonce",
        nonceExpiresAtMs: 10_000,
        principalId: "principal-1",
        sessionId: "session-1",
        tool: "mac_health",
        policyVersion: "policy-0.1",
        payloadDigest: "0".repeat(64),
        mutation: false,
        receivedAtMs: 3
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    assert.equal(store.requestRecord("readonly-admission-after-outage"), undefined);
    assert.equal(store.auditRows().length, 2);
  } finally {
    await unlink(`${anchorPath}.lock`).catch(() => undefined);
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
