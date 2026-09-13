import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { stat } from "node:fs/promises";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  ApprovalAuthority,
  approvalPreviewDigest,
  signApprovalIssuance,
  type UnsignedApprovalIssuance
} from "./approval-authority.js";
import { ApprovalIpcServer } from "./approval-ipc-server.js";
import { BrokerStore, type IssueApprovalInput } from "./persistence.js";

const NOW = 1_700_000_000_000;

function approval(overrides: Partial<IssueApprovalInput> = {}): IssueApprovalInput {
  return {
    approvalId: "approval:authority-test",
    approverPrincipalId: "operator-1",
    requestingPrincipalId: "agent-1",
    tool: "mac_write_file_atomic",
    contractVersion: "0.1",
    targetKind: "path",
    targetRef: "path:project",
    payloadDigest: "a".repeat(64),
    policyVersion: "policy-0.1",
    approvalClass: "trusted_write",
    unattended: false,
    issuedAtMs: NOW,
    expiresAtMs: NOW + 30_000,
    ...overrides
  };
}

function signed(input: IssueApprovalInput, key: Buffer): ReturnType<typeof signApprovalIssuance> {
  const unsigned: UnsignedApprovalIssuance = {
    protocolVersion: "0.1",
    requestId: "approval-issue:authority-test",
    nonce: "approval-nonce:authority-test",
    nonceExpiresAtMs: NOW + 10_000,
    issuerId: input.approverPrincipalId,
    keyId: "operator-key-1",
    timestampMs: NOW,
    approval: input,
    previewDigest: approvalPreviewDigest(input)
  };
  return signApprovalIssuance(unsigned, key);
}

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-approval-authority-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const authority = new ApprovalAuthority(store, [{
    issuerId: "operator-1",
    keyId: "operator-key-1",
    key,
    notBeforeMs: NOW - 1_000,
    expiresAtMs: NOW + 60_000,
    allowUnattended: false
  }], { now: () => NOW });
  return {
    authority,
    key,
    store,
    close: async () => { store.close(); await rm(directory, { recursive: true, force: true }); }
  };
}

test("authenticated approval issuance binds issuer, preview, provenance, and audit", async () => {
  const context = await fixture();
  try {
    const record = context.authority.issue(signed(approval(), context.key));
    assert.equal(record.approvalId, "approval:authority-test");
    assert.equal(record.approverPrincipalId, "operator-1");
    assert.equal(context.store.auditRows().length, 2);
    const [decision, completion] = context.store.auditRows();
    assert.ok(decision && completion);
    assert.equal(decision.result_class, "AUTHORIZED");
    assert.equal(completion.result_class, "SUCCEEDED");
    const evidence = JSON.parse(decision.evidence_json as string) as Record<string, unknown>;
    assert.equal(evidence.issuerKeyId, "operator-key-1");
    assert.equal(evidence.previewDigest, approvalPreviewDigest(approval()));
  } finally {
    await context.close();
  }
});

test("approval issuance nonce replay is denied after BrokerStore reopen", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-approval-replay-"));
  const databasePath = join(directory, "broker.sqlite");
  const key = randomBytes(32);
  const issuance = signed(approval({ approvalId: "approval:replay" }), key);
  let store = new BrokerStore(databasePath);
  let authority = new ApprovalAuthority(store, [{
    issuerId: "operator-1", keyId: "operator-key-1", key,
    notBeforeMs: NOW - 1_000, expiresAtMs: NOW + 60_000, allowUnattended: false
  }], { now: () => NOW });
  authority.issue(issuance);
  store.close();
  store = new BrokerStore(databasePath);
  authority = new ApprovalAuthority(store, [{
    issuerId: "operator-1", keyId: "operator-key-1", key,
    notBeforeMs: NOW - 1_000, expiresAtMs: NOW + 60_000, allowUnattended: false
  }], { now: () => NOW });
  try {
    assert.throws(() => authority.issue(issuance), /nonce or request ID was already accepted/u);
    assert.equal(store.approvalRecord("approval:replay")?.usedCount, 0);
    assert.equal(store.auditRows().length, 2);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("tampered approval issuance fails before persistence", async () => {
  const context = await fixture();
  try {
    const issuance = signed(approval({ approvalId: "approval:tamper" }), context.key);
    assert.throws(
      () => context.authority.issue({ ...issuance, approval: { ...issuance.approval, targetRef: "path:other" } }),
      /digest is invalid/u
    );
    assert.throws(
      () => context.authority.issue({ ...issuance, authenticationProof: "0".repeat(64) }),
      /authentication failed/u
    );
    assert.throws(
      () => context.authority.issue({
        ...issuance,
        approval: { ...issuance.approval, unexpected: "field" } as IssueApprovalInput & { unexpected: string }
      }),
      /unknown field/u
    );
    assert.equal(context.store.approvalRecord("approval:tamper"), undefined);
    assert.equal(context.store.auditRows().length, 0);
  } finally {
    await context.close();
  }
});

test("unattended approval requires an explicitly enabled profile issuer", async () => {
  const context = await fixture();
  try {
    const unattended = signed(approval({
      approvalId: "approval:unattended",
      approvalClass: "trusted_profile",
      unattended: true
    }), context.key);
    assert.throws(() => context.authority.issue(unattended), /authorized profile issuer/u);
    assert.equal(context.store.approvalRecord("approval:unattended"), undefined);
  } finally {
    await context.close();
  }
});

test("revoked approval issuer keys fail closed before issuance", async () => {
  const context = await fixture();
  try {
    context.store.revoke("approval_key", "operator-1:operator-key-1", "COMPROMISED", NOW);
    assert.throws(
      () => context.authority.issue(signed(approval({ approvalId: "approval:revoked-key" }), context.key)),
      /issuer key has been revoked/u
    );
    assert.equal(context.store.approvalRecord("approval:revoked-key"), undefined);
    assert.deepEqual(
      context.store.auditRows().map((row) => [row.tool, row.event_type, row.result_class]),
      [
        ["internal_authority_revoke", "intent", "INTENT_RECORDED"],
        ["internal_authority_revoke", "completion", "SUCCEEDED"]
      ]
    );
  } finally {
    await context.close();
  }
});

test("approval issuance uses a separate owner-only local IPC channel", async () => {
  const context = await fixture();
  const socketPath = join((await mkdtemp(join(tmpdir(), "mac-operator-approval-ipc-"))), "approval.sock");
  const server = new ApprovalIpcServer({
    socketPath,
    authority: context.authority,
    peerPolicy: currentProcessPeerPolicy()
  });
  await server.listen();
  try {
    assert.equal((await stat(socketPath)).mode & 0o777, 0o600);
    const response = await sendApproval(socketPath, `${JSON.stringify(signed(approval({ approvalId: "approval:ipc" }), context.key))}\n`);
    assert.deepEqual(response, { ok: true, approval_id: "approval:ipc", expires_at_ms: NOW + 30_000, revision: 0 });
  } finally {
    await server.close();
    await context.close();
  }
});

test("approval IPC drops a denied local peer before parsing or auditing", async () => {
  const context = await fixture();
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-approval-peer-deny-"));
  const socketPath = join(directory, "approval.sock");
  const server = new ApprovalIpcServer({
    socketPath,
    authority: context.authority,
    peerPolicy: deniedPeerPolicy()
  });
  await server.listen();
  try {
    await assert.rejects(sendApproval(socketPath, "not-json\n"), /(?:EPIPE|ECONNRESET|Unexpected end of JSON input)/u);
    assert.deepEqual(context.store.auditRows(), []);
  } finally {
    await server.close();
    await context.close();
    await rm(directory, { recursive: true, force: true });
  }
});

function sendApproval(socketPath: string, body: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    let response = "";
    socket.setEncoding("utf8");
    socket.on("connect", () => socket.write(body));
    socket.on("data", (chunk: string) => { response += chunk; });
    socket.on("end", () => {
      try { resolve(JSON.parse(response.trim()) as unknown); } catch (error) { reject(error); }
    });
    socket.on("error", reject);
  });
}

function currentProcessPeerPolicy(): { expectedUid: number; expectedGid: number; allowedProcessIds: ReadonlySet<number> } {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined) throw new Error("POSIX identity is unavailable");
  return { expectedUid: uid, expectedGid: gid, allowedProcessIds: new Set([process.pid]) };
}

function deniedPeerPolicy(): { expectedUid: number; allowedProcessIds: ReadonlySet<number> } {
  const uid = process.getuid?.();
  if (uid === undefined) throw new Error("POSIX identity is unavailable");
  return { expectedUid: uid, allowedProcessIds: new Set([process.pid + 1]) };
}
