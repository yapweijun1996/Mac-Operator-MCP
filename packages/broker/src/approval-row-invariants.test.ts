import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { BrokerError, sha256 } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";

function approvalInput(approvalId: string) {
  return {
    approvalId,
    approverPrincipalId: "principal-approver",
    requestingPrincipalId: "principal-requester",
    tool: "mac_write_file_atomic",
    contractVersion: "0.1",
    targetKind: "path",
    targetRef: "path:workspace",
    payloadDigest: sha256(approvalId),
    policyVersion: "policy-0.1",
    approvalClass: "trusted_write" as const,
    unattended: false,
    issuedAtMs: 10,
    expiresAtMs: 100
  };
}

async function expectCorruptApproval(
  suffix: string,
  approvalId: string,
  mutate: (database: DatabaseSync) => void
): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), `mac-operator-approval-${suffix}-`));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  store.issueApproval(approvalInput(approvalId));
  store.close();
  try {
    const database = new DatabaseSync(databasePath);
    try {
      mutate(database);
    } finally {
      database.close();
    }
    const reopened = new BrokerStore(databasePath);
    try {
      assert.throws(
        () => reopened.approvalRecord(approvalId),
        (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
      );
    } finally {
      reopened.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("stored Approval consumption fields must agree with the single-use counter", async () => {
  await expectCorruptApproval("consumption", "approval:corrupt-consumption", (database) => {
    database.prepare("UPDATE approvals SET used_count = 1 WHERE approval_id = ?").run("approval:corrupt-consumption");
  });
});

test("stored Approval expiry must remain after issuance", async () => {
  await expectCorruptApproval("expiry", "approval:corrupt-expiry", (database) => {
    database.prepare("UPDATE approvals SET expires_at_ms = issued_at_ms WHERE approval_id = ?").run("approval:corrupt-expiry");
  });
});

test("stored Approval revocation fields must be paired and revisioned", async () => {
  await expectCorruptApproval("revocation", "approval:corrupt-revocation", (database) => {
    database.prepare("UPDATE approvals SET revoked_at_ms = 20 WHERE approval_id = ?").run("approval:corrupt-revocation");
  });
});
