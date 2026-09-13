import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020").default as new (options: Record<string, unknown>) => {
  compile(schema: object): ((value: unknown) => boolean) & { errors?: unknown };
};
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const schema = JSON.parse(await readFile(join(repositoryRoot, "schemas", "ledger-records.schema.json"), "utf8")) as object;
const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);

const digest = "a".repeat(64);

test("versioned ledger schemas accept bounded request, approval, Job, and audit records", () => {
  const records = [
    {
      schema_version: "0.1",
      record_type: "request",
      record: {
        requestId: "request:ledger-1",
        edgeId: "edge-1",
        principalId: "principal-1",
        sessionId: "session-1",
        tool: "mac_health",
        policyVersion: "policy-0.1",
        payloadDigest: digest,
        mutation: false,
        state: "SUCCEEDED",
        resultClass: "SUCCEEDED",
        targetRef: "host:broker",
        approvalId: null,
        jobId: null,
        receivedAtMs: 1,
        updatedAtMs: 2,
        revision: 1
      }
    },
    {
      schema_version: "0.1",
      record_type: "approval",
      record: {
        approvalId: "approval:ledger-1",
        approverPrincipalId: "operator-1",
        requestingPrincipalId: "principal-1",
        tool: "mac_write_file_atomic",
        contractVersion: "0.1",
        targetKind: "path",
        targetRef: "root:test/file.txt",
        payloadDigest: digest,
        policyVersion: "policy-0.1",
        approvalClass: "trusted_write",
        unattended: false,
        issuedAtMs: 1,
        expiresAtMs: 10,
        useLimit: 1,
        usedCount: 0,
        lastConsumedAtMs: null,
        lastRequestId: null,
        revokedAtMs: null,
        revocationReason: null,
        revision: 0
      }
    },
    {
      schema_version: "0.1",
      record_type: "job",
      record: {
        jobId: "job:ledger-1",
        ownerPrincipalId: "principal-1",
        ownerSessionId: "session-1",
        tool: "mac_priv_service_control",
        targetRef: "service:system/com.example.test",
        policyVersion: "policy-0.1",
        payloadDigest: digest,
        idempotencyKey: "ledger-1",
        state: "queued",
        resultClass: "queued",
        createdAtMs: 1,
        startedAtMs: null,
        finishedAtMs: null,
        exitCode: null,
        stdout: "",
        stderr: "",
        truncated: false,
        cancelRequested: false,
        revision: 0,
        privilegedPayload: { operation: "service_control", service_id: "system/com.example.test", action: "start" }
      }
    },
    {
      schema_version: "0.1",
      record_type: "audit",
      record: {
        requestId: "request:ledger-1",
        principalId: "principal-1",
        tool: "internal_authority_switch",
        eventType: "completion",
        decision: "allow",
        resultClass: "SUCCEEDED",
        targetRef: "switch:privileged",
        policyVersion: "internal-authority-0.1",
        evidence: { persisted: true },
        timestampMs: 2
      }
    }
  ];
  for (const record of records) assert.equal(validate(record), true);
});

test("versioned ledger schemas reject authority expansion and malformed state", () => {
  const valid = {
    schema_version: "0.1",
    record_type: "job",
    record: {
      jobId: "job:ledger-2",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_priv_service_control",
      targetRef: "service:system/com.example.test",
      policyVersion: "policy-0.1",
      payloadDigest: digest,
      idempotencyKey: "ledger-2",
      state: "queued",
      resultClass: "queued",
      createdAtMs: 1,
      startedAtMs: null,
      finishedAtMs: null,
      exitCode: null,
      stdout: "",
      stderr: "",
      truncated: false,
      cancelRequested: false,
      revision: 0,
      privilegedPayload: { operation: "service_control", service_id: "system/com.example.test", action: "start" }
    }
  };
  assert.equal(validate(valid), true);
  const withRawAuthority = structuredClone(valid) as { record: { privilegedPayload: Record<string, unknown> } };
  withRawAuthority.record.privilegedPayload.executable = "/bin/sh";
  assert.equal(validate(withRawAuthority), false);
  const withBadVersion = { ...valid, schema_version: "9.9" };
  assert.equal(validate(withBadVersion), false);
  const withBadAudit = {
    schema_version: "0.1",
    record_type: "audit",
    record: {
      requestId: "request:ledger-2",
      principalId: "principal-1",
      tool: "internal_authority_switch",
      eventType: "completion",
      decision: "allow",
      resultClass: "SUCCEEDED",
      targetRef: "switch:global",
      policyVersion: "internal-authority-0.1",
      evidence: [],
      timestampMs: 2
    }
  };
  assert.equal(validate(withBadAudit), false);
});
