import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { BrokerError, sha256 } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";

const NOW = 1_700_000_000_000;
const TARGET_REF = "path:workspace";
const TOOL = "mac_write_file_atomic";
const ARGUMENTS_DIGEST = sha256("request-arguments");

function requestInput(requestId: string) {
  return {
    requestId,
    edgeId: "edge-1",
    nonce: `nonce-${requestId}`,
    nonceExpiresAtMs: NOW + 60_000,
    principalId: "principal-1",
    sessionId: "session-1",
    tool: TOOL,
    policyVersion: "policy-0.1",
    payloadDigest: sha256(requestId),
    mutation: true,
    receivedAtMs: NOW
  } as const;
}

function approvalInput(approvalId: string) {
  return {
    approvalId,
    approverPrincipalId: "operator-1",
    requestingPrincipalId: "principal-1",
    tool: TOOL,
    contractVersion: "0.1",
    targetKind: "path",
    targetRef: TARGET_REF,
    payloadDigest: ARGUMENTS_DIGEST,
    policyVersion: "policy-0.1",
    approvalClass: "trusted_write" as const,
    unattended: false,
    issuedAtMs: NOW,
    expiresAtMs: NOW + 60_000
  };
}

function jobInput(jobId: string, ownerPrincipalId = "principal-1") {
  return {
    jobId,
    ownerPrincipalId,
    ownerSessionId: "session-1",
    tool: TOOL,
    targetRef: TARGET_REF,
    policyVersion: "policy-0.1",
    payloadDigest: ARGUMENTS_DIGEST,
    idempotencyKey: `idempotency-${jobId.slice(4)}`,
    createdAtMs: NOW + 2
  } as const;
}

function prepareIntent(store: BrokerStore, requestId: string, approvalId: string): void {
  store.admitRequest(requestInput(requestId));
  store.recordRequestDecision({
    requestId,
    principalId: "principal-1",
    tool: TOOL,
    eventType: "decision",
    decision: "allow",
    resultClass: "AUTHORIZED",
    targetRef: TARGET_REF,
    policyVersion: "policy-0.1",
    evidence: {},
    timestampMs: NOW + 1
  });
  store.issueApproval(approvalInput(approvalId));
  store.recordRequestIntent({
    requestId,
    principalId: "principal-1",
    tool: TOOL,
    eventType: "intent",
    decision: "allow",
    resultClass: "INTENT_RECORDED",
    targetRef: TARGET_REF,
    policyVersion: "policy-0.1",
    evidence: {},
    timestampMs: NOW + 2
  }, {
    contractVersion: "0.1",
    targetKind: "path",
    targetRef: TARGET_REF,
    payloadDigest: ARGUMENTS_DIGEST,
    approvalClass: "trusted_write",
    unattended: false
  });
}

test("Request-to-Job linkage requires a matching owned Job", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-request-link-runtime-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    prepareIntent(store, "request:link-runtime", "approval:link-runtime");
    store.createJob(jobInput("job:link-runtime", "principal-other"));
    assert.throws(
      () => store.linkRequestJob("request:link-runtime", "job:link-runtime", NOW + 3),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT"
    );
    assert.equal(store.requestRecord("request:link-runtime")?.jobId, null);
    assert.throws(
      () => store.linkRequestJob("request:link-runtime", "job:missing", NOW + 3),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "TARGET_NOT_FOUND"
    );
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("missing persisted Request Approval linkage fails closed during startup", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-request-link-approval-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  prepareIntent(store, "request:link-missing-approval", "approval:link-missing-approval");
  store.close();
  try {
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare("DELETE FROM approvals WHERE approval_id = ?").run("approval:link-missing-approval");
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

test("mismatched persisted Request Job linkage fails closed during startup", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-request-link-job-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  prepareIntent(store, "request:link-job", "approval:link-job");
  store.createJob(jobInput("job:link-job"));
  store.linkRequestJob("request:link-job", "job:link-job", NOW + 3);
  store.close();
  try {
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare("UPDATE jobs SET owner_session_id = ? WHERE job_id = ?")
        .run("session-other", "job:link-job");
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
