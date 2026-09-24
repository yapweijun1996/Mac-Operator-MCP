import assert from "node:assert/strict";
import test from "node:test";
import { PassThrough } from "node:stream";
import {
  approvalIssuanceCommandFromPreview,
  confirmApprovalPreview,
  executeApprovalIssuanceCliCommand,
  parseApprovalIssuanceCliArgs,
  parseApprovalPreviewIssuanceCliArgs,
  type ApprovalIssuanceCliClient
} from "./approval-issuance-cli.js";

const NOW = 1_700_000_000_000;
const BASE_ARGS = [
  "issue",
  "--database", "/tmp/broker.sqlite",
  "--socket", "/tmp/approval.sock",
  "--key-config", "/tmp/approval-keys.json",
  "--issuer-id", "operator-1",
  "--key-id", "operator-key-1",
  "--requesting-principal", "agent-1",
  "--tool", "mac_user_service_control",
  "--contract-version", "0.1",
  "--target-kind", "service",
  "--target-ref", "service:gui/501/com.example.agent",
  "--payload-digest", "a".repeat(64),
  "--policy-version", "policy-r2",
  "--approval-class", "trusted_write",
  "--ttl-ms", "30000",
  "--confirm", "issue"
];

test("approval issuance CLI parses a bounded owner approval command", () => {
  const command = parseApprovalIssuanceCliArgs(BASE_ARGS);
  assert.equal(command.kind, "issue");
  assert.equal(command.tool, "mac_user_service_control");
  assert.equal(command.ttlMs, 30_000);
  assert.equal(command.confirmation, "issue");
});

test("approval issuance CLI resolves an exact pending Broker preview by request ID", () => {
  const command = parseApprovalPreviewIssuanceCliArgs([
    "issue",
    "--database", "/tmp/broker.sqlite",
    "--socket", "/tmp/approval.sock",
    "--key-config", "/tmp/approval-keys.json",
    "--issuer-id", "operator-1",
    "--key-id", "operator-key-1",
    "--request-id", "request-preview",
    "--confirm", "issue"
  ]);
  const preview = {
    requestId: "request-preview",
    requestingPrincipalId: "agent-1",
    tool: "mac_user_service_control",
    contractVersion: "0.1",
    targetKind: "service",
    targetRef: "service:gui/501/com.example.agent",
    payloadDigest: "a".repeat(64),
    policyVersion: "policy-r2",
    approvalClass: "trusted_write",
    unattended: false,
    status: "pending",
    approvalId: null,
    createdAtMs: NOW - 1_000,
    expiresAtMs: NOW + 30_000,
    revision: 0
  } as const;
  const resolved = approvalIssuanceCommandFromPreview(command, preview, NOW);
  assert.equal(resolved.requestingPrincipalId, "agent-1");
  assert.equal(resolved.targetRef, "service:gui/501/com.example.agent");
  assert.match(resolved.approvalId ?? "", /^approval:owner-preview-[a-f0-9]{48}$/u);
  assert.equal(resolved.ttlMs, 30_000);
  assert.throws(
    () => approvalIssuanceCommandFromPreview(command, { ...preview, status: "issued", approvalId: "approval:issued", revision: 1 }, NOW),
    /no longer live/u
  );
});

test("approval issuance CLI creates a non-unattended approval and verifies exact client readback", async () => {
  const command = parseApprovalIssuanceCliArgs(BASE_ARGS);
  let received: Record<string, unknown> | undefined;
  const client: ApprovalIssuanceCliClient = {
    async issue(approval) {
      received = approval as unknown as Record<string, unknown>;
      return { approval_id: approval.approvalId, expires_at_ms: approval.expiresAtMs, revision: 4 };
    }
  };
  const result = await executeApprovalIssuanceCliCommand(command, client, NOW, async () => {});
  assert.equal(result.schemaVersion, "0.1");
  assert.equal(result.operation, "issue");
  assert.equal(result.expiresAtMs, NOW + 30_000);
  assert.equal(result.revision, 4);
  assert.equal(result.verified, true);
  assert.equal(received?.approverPrincipalId, "operator-1");
  assert.equal(received?.unattended, false);
  assert.equal(received?.useLimit, 1);
});

test("approval issuance CLI requires explicit confirmation and rejects unsupported fields", () => {
  assert.throws(() => parseApprovalIssuanceCliArgs(BASE_ARGS.map((value, index) => index === BASE_ARGS.length - 1 ? "no" : value)), /malformed or confirmation/u);
  assert.throws(() => parseApprovalIssuanceCliArgs([...BASE_ARGS, "--unattended", "true"]), /unsupported field/u);
});

test("approval issuance CLI displays a safe preview and requires the exact approval token", async () => {
  const approval = {
    approvalId: "approval:preview",
    approverPrincipalId: "operator-1",
    requestingPrincipalId: "agent-1",
    tool: "mac_user_service_control",
    contractVersion: "0.1",
    targetKind: "service",
    targetRef: "service:gui/501/com.example.agent",
    payloadDigest: "a".repeat(64),
    policyVersion: "policy-r2",
    approvalClass: "trusted_write" as const,
    unattended: false,
    issuedAtMs: NOW,
    expiresAtMs: NOW + 30_000,
    useLimit: 1
  };
  const input = new PassThrough();
  const output = new PassThrough();
  let rendered = "";
  output.setEncoding("utf8");
  output.on("data", chunk => { rendered += chunk; });
  const pending = confirmApprovalPreview(approval, { input, output, isTTY: true, timeoutMs: 1_000 });
  input.end(`APPROVE ${approval.approvalId}\n`);
  await pending;
  assert.match(rendered, /OWNER APPROVAL PREVIEW/u);
  assert.match(rendered, /mac_user_service_control/u);
  assert.match(rendered, /Payload digest/u);
});

test("approval issuance CLI rejects non-TTY and mismatched human confirmation", async () => {
  const approval = {
    approvalId: "approval:preview-reject",
    approverPrincipalId: "operator-1",
    requestingPrincipalId: "agent-1",
    tool: "mac_user_service_control",
    contractVersion: "0.1",
    targetKind: "service",
    targetRef: "service:gui/501/com.example.agent",
    payloadDigest: "a".repeat(64),
    policyVersion: "policy-r2",
    approvalClass: "trusted_write" as const,
    unattended: false,
    issuedAtMs: NOW,
    expiresAtMs: NOW + 30_000,
    useLimit: 1
  };
  await assert.rejects(confirmApprovalPreview(approval, { isTTY: false }), /TTY/u);
  const input = new PassThrough();
  const pending = confirmApprovalPreview(approval, { input, output: new PassThrough(), isTTY: true, timeoutMs: 1_000 });
  input.end("APPROVE approval:other\n");
  await assert.rejects(pending, /did not match/u);
});
