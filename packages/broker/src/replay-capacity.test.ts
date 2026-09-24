import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";
import { join } from "node:path";
import test from "node:test";
import { BrokerError, canonicalJson, sha256, type CapabilityFamily } from "@mac-operator/contracts";
import { BrokerStore, type AdmitRequestInput, type AuthenticatedApprovalIssuance, type IssueApprovalInput } from "./persistence.js";

const REPLAY_CAPACITY = 4_096;

interface ReplayLedgerRetentionCase {
  name: string;
  table: string;
  insertSql: string;
  insertValues: (index: number) => readonly (string | number)[];
  admit: (store: BrokerStore, index: number, acceptedAtMs: number) => void;
}

const REMAINING_REPLAY_LEDGER_CASES: readonly ReplayLedgerRetentionCase[] = [
  {
    name: "policy signer",
    table: "policy_signer_nonces",
    insertSql: "INSERT INTO policy_signer_nonces(nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)",
    insertValues: (index) => [`policy-nonce-${String(index).padStart(16, "0")}`, `policy-request-${String(index).padStart(16, "0")}`, 1, 100_001],
    admit: (store, index, acceptedAtMs) => store.admitPolicySignerCommand({
      requestId: `policy-request-${String(index).padStart(16, "0")}`,
      nonce: `policy-nonce-${String(index).padStart(16, "0")}`,
      acceptedAtMs,
      expiresAtMs: acceptedAtMs + 100_000
    })
  },
  {
    name: "authority control",
    table: "authority_control_nonces",
    insertSql: "INSERT INTO authority_control_nonces(nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)",
    insertValues: (index) => [`authority-nonce-${String(index).padStart(16, "0")}`, `authority-request-${String(index).padStart(16, "0")}`, 1, 100_001],
    admit: (store, index, acceptedAtMs) => store.admitAuthorityControlCommand({
      requestId: `authority-request-${String(index).padStart(16, "0")}`,
      nonce: `authority-nonce-${String(index).padStart(16, "0")}`,
      acceptedAtMs,
      expiresAtMs: acceptedAtMs + 100_000
    })
  },
  {
    name: "Broker status",
    table: "broker_status_nonces",
    insertSql: "INSERT INTO broker_status_nonces(nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)",
    insertValues: (index) => [`broker-status-nonce-${String(index).padStart(16, "0")}`, `request:broker-status-${String(index).padStart(16, "0")}`, 1, 100_001],
    admit: (store, index, acceptedAtMs) => store.admitBrokerStatusRequest({
      requestId: `request:broker-status-${String(index).padStart(16, "0")}`,
      nonce: `broker-status-nonce-${String(index).padStart(16, "0")}`,
      timestampMs: acceptedAtMs,
      expiresAtMs: acceptedAtMs + 100_000
    })
  },
  {
    name: "virtualization guest",
    table: "virtualization_guest_nonces",
    insertSql: "INSERT INTO virtualization_guest_nonces(nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)",
    insertValues: (index) => [`guest-nonce-${String(index).padStart(16, "0")}`, `request:guest-${String(index).padStart(16, "0")}`, 1, 100_001],
    admit: (store, index, acceptedAtMs) => store.admitVirtualizationGuestRequest({
      requestId: `request:guest-${String(index).padStart(16, "0")}`,
      nonce: `guest-nonce-${String(index).padStart(16, "0")}`,
      acceptedAtMs,
      expiresAtMs: acceptedAtMs + 100_000
    })
  },
  {
    name: "Edge revocation",
    table: "edge_revocation_nonces",
    insertSql: "INSERT INTO edge_revocation_nonces(nonce, request_id, edge_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?, ?)",
    insertValues: (index) => [`edge-revoke-nonce:${String(index).padStart(16, "0")}`, `edge-revoke:${String(index).padStart(16, "0")}`, `edge-${String(index).padStart(16, "0")}`, 1, 100_001],
    admit: (store, index, acceptedAtMs) => store.admitEdgeRevocationEvent({
      requestId: `edge-revoke:${String(index).padStart(16, "0")}`,
      nonce: `edge-revoke-nonce:${String(index).padStart(16, "0")}`,
      edgeId: `edge-${String(index).padStart(16, "0")}`,
      acceptedAtMs,
      expiresAtMs: acceptedAtMs + 100_000
    })
  }
];

function requestInput(index: number, receivedAtMs = 1): AdmitRequestInput {
  const suffix = String(index).padStart(16, "0");
  return {
    requestId: `request:replay-capacity-${suffix}`,
    edgeId: "edge-replay-capacity",
    nonce: `nonce:replay-capacity-${suffix}`,
    nonceExpiresAtMs: receivedAtMs + 100_000,
    principalId: "principal-replay-capacity",
    sessionId: `session-replay-capacity-${suffix}`,
    tool: "mac_health",
    policyVersion: "policy-0.1",
    payloadDigest: "a".repeat(64),
    mutation: false,
    capabilityFamilies: ["read" satisfies CapabilityFamily],
    receivedAtMs
  };
}

function authenticatedApprovalInput(index: number, timestampMs: number): AuthenticatedApprovalIssuance {
  const suffix = String(index).padStart(16, "0");
  const approval: IssueApprovalInput = {
    approvalId: `approval:replay-capacity-${suffix}`,
    approverPrincipalId: "issuer-replay-capacity",
    requestingPrincipalId: "requester-replay-capacity",
    tool: "mac_health",
    contractVersion: "0.1",
    targetKind: "host",
    targetRef: "host:replay-capacity",
    payloadDigest: "a".repeat(64),
    policyVersion: "policy-0.1",
    approvalClass: "trusted_write",
    unattended: false,
    issuedAtMs: timestampMs,
    expiresAtMs: timestampMs + 100_000,
    useLimit: 1
  };
  const base = {
    protocolVersion: "0.1" as const,
    requestId: `approval-issue:${suffix}`,
    nonce: `approval-nonce:${suffix}`,
    nonceExpiresAtMs: timestampMs + 100_000,
    issuerId: "issuer-replay-capacity",
    keyId: "operator-key-replay",
    timestampMs,
    approval,
    previewDigest: "b".repeat(64)
  };
  return { ...base, issuanceDigest: sha256(canonicalJson(base)) };
}

test("request replay ledger is bounded and expired rows are reclaimed transactionally", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-request-replay-capacity-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    for (let index = 0; index < REPLAY_CAPACITY; index += 1) {
      store.admitRequest(requestInput(index));
    }
    assert.throws(
      () => store.admitRequest(requestInput(REPLAY_CAPACITY, 2)),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    assert.equal(store.requestRecord(requestInput(REPLAY_CAPACITY, 2).requestId), undefined);

    const reclaimed = store.admitRequest(requestInput(REPLAY_CAPACITY + 1, 100_001));
    assert.equal(reclaimed.state, "RECEIVED");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("privileged-helper replay ledger reclaims rows exactly at expiry before capacity denial", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-helper-replay-capacity-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    for (let index = 0; index < REPLAY_CAPACITY; index += 1) {
      const suffix = String(index).padStart(16, "0");
      store.admitPrivilegedHelperCommand({
        requestId: `request:helper-replay-capacity-${suffix}`,
        nonce: `helper-nonce-replay-capacity-${suffix}`,
        acceptedAtMs: 1,
        expiresAtMs: 100_001
      });
    }
    assert.throws(
      () => store.admitPrivilegedHelperCommand({
        requestId: `request:helper-replay-capacity-${String(REPLAY_CAPACITY).padStart(16, "0")}`,
        nonce: `helper-nonce-replay-capacity-${String(REPLAY_CAPACITY).padStart(16, "0")}`,
        acceptedAtMs: 2,
        expiresAtMs: 100_002
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    store.admitPrivilegedHelperCommand({
      requestId: `request:helper-replay-capacity-${String(REPLAY_CAPACITY + 1).padStart(16, "0")}`,
      nonce: `helper-nonce-replay-capacity-${String(REPLAY_CAPACITY + 1).padStart(16, "0")}`,
      acceptedAtMs: 100_001,
      expiresAtMs: 200_001
    });
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Keychain delivery replay ledger is bounded and reclaims exact expiry", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-keychain-replay-capacity-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    for (let index = 0; index < REPLAY_CAPACITY; index += 1) {
      const suffix = String(index).padStart(16, "0");
      store.admitKeychainDeliveryRequest({
        requestId: `delivery-request-${suffix}`,
        nonce: `delivery-nonce-${suffix}`,
        acceptedAtMs: 1,
        expiresAtMs: 100_001
      });
    }
    assert.throws(
      () => store.admitKeychainDeliveryRequest({
        requestId: `delivery-request-${String(REPLAY_CAPACITY).padStart(16, "0")}`,
        nonce: `delivery-nonce-${String(REPLAY_CAPACITY).padStart(16, "0")}`,
        acceptedAtMs: 2,
        expiresAtMs: 100_002
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    store.admitKeychainDeliveryRequest({
      requestId: `delivery-request-${String(REPLAY_CAPACITY + 1).padStart(16, "0")}`,
      nonce: `delivery-nonce-${String(REPLAY_CAPACITY + 1).padStart(16, "0")}`,
      acceptedAtMs: 100_001,
      expiresAtMs: 200_001
    });
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("remaining protocol replay ledgers reclaim expired rows before capacity denial", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-protocol-replay-capacity-"));
  const databasePath = join(directory, "broker.sqlite");
  const initialStore = new BrokerStore(databasePath);
  initialStore.close();
  const database = new DatabaseSync(databasePath);
  try {
    for (const replayCase of REMAINING_REPLAY_LEDGER_CASES) {
      const insert = database.prepare(replayCase.insertSql);
      for (let index = 0; index < REPLAY_CAPACITY; index += 1) {
        insert.run(...replayCase.insertValues(index));
      }
    }
  } finally {
    database.close();
  }

  const store = new BrokerStore(databasePath);
  try {
    for (const replayCase of REMAINING_REPLAY_LEDGER_CASES) {
      assert.throws(
        () => replayCase.admit(store, REPLAY_CAPACITY, 2),
        (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
      );
      replayCase.admit(store, REPLAY_CAPACITY + 1, 100_001);
    }
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("approval issuance replay ledger reclaims expired rows before capacity denial", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-approval-replay-capacity-"));
  const databasePath = join(directory, "broker.sqlite");
  const initialStore = new BrokerStore(databasePath);
  initialStore.close();
  const database = new DatabaseSync(databasePath);
  try {
    const insert = database.prepare(
      "INSERT INTO approval_nonces(issuer_id, key_id, nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?, ?, ?)"
    );
    for (let index = 0; index < REPLAY_CAPACITY; index += 1) {
      const suffix = String(index).padStart(16, "0");
      insert.run(
        "issuer-replay-capacity",
        "operator-key-replay",
        `approval-nonce:${suffix}`,
        `approval-issue:${suffix}`,
        1,
        100_001
      );
    }
  } finally {
    database.close();
  }

  const store = new BrokerStore(databasePath);
  try {
    assert.throws(
      () => store.issueAuthenticatedApproval(authenticatedApprovalInput(REPLAY_CAPACITY, 2)),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    const reclaimed = authenticatedApprovalInput(REPLAY_CAPACITY + 1, 100_001);
    const record = store.issueAuthenticatedApproval(reclaimed);
    assert.equal(record.approvalId, reclaimed.approval.approvalId);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
