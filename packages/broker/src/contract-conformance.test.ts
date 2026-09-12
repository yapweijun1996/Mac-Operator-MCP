import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { canonicalJson, sha256, signRequest, type Scope, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { BrokerStore } from "./persistence.js";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020").default as new (options: Record<string, unknown>) => {
  compile(schema: object): ((value: unknown) => boolean) & { errors?: unknown };
  errorsText(errors: unknown): string;
};
const addFormats = require("ajv-formats").default as (ajv: InstanceType<typeof Ajv2020>) => void;
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

test("implemented broker results conform to versioned success and failure schemas", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-contract-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const now = Date.now();
  const samplePath = join(directory, "sample.txt");
  const writePath = join(directory, "contract-write.txt");
  await writeFile(samplePath, "hello");
  const keyring = new EdgeKeyring([{ edgeId: "edge-1", keyId: "edge-key-1", key, notBeforeMs: now - 1_000, expiresAtMs: now + 60_000 }]);
  const basePolicy = createDefaultPolicy(
    "edge-1",
    true,
    ["mac.control.read", "mac.policy.explain", "mac.system.read", "mac.process.read", "mac.files.read", "mac.files.hash", "mac.files.write", "mac.job.read", "mac.job.cancel"],
    ["edge-key-1"],
    [{ rootId: "test-root", path: directory, metadata: true, contentRead: true, write: true, denyRelativePaths: [] }]
  );
  const writeTool = basePolicy.tools.get("mac_write_file_atomic");
  assert.ok(writeTool);
  const policy = {
    ...basePolicy,
    tools: new Map(basePolicy.tools).set("mac_write_file_atomic", { ...writeTool, enabled: true })
  };
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: keyring,
    now: () => now
  });
  store.createJob({
    jobId: "job:contract",
    ownerPrincipalId: "principal-1",
    ownerSessionId: "session-1",
    tool: "mac_task_run",
    targetRef: "task:contract",
    policyVersion: "policy-0.1",
    payloadDigest: "a".repeat(64),
    idempotencyKey: "contract-job",
    createdAtMs: now - 1_000
  });
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  try {
    const cases = [
      { tool: "mac_health", arguments: { include_components: true } },
      { tool: "mac_capabilities", arguments: {} },
      { tool: "mac_system_summary", arguments: { include_load: true } },
      { tool: "mac_process_list", arguments: { limit: 20, sort: "pid" } },
      { tool: "mac_policy_explain", arguments: { proposed_tool: "mac_health", target: { kind: "host", reference: "broker" } } },
      { tool: "mac_stat_path", arguments: { path: samplePath, follow_symlink: true } },
      { tool: "mac_read_file", arguments: { path: samplePath, max_bytes: 5, encoding: "utf8" } },
      { tool: "mac_hash_file", arguments: { path: samplePath, algorithm: "sha256" } },
      { tool: "mac_list_directory", arguments: { path: directory, limit: 10, include_hidden: false } },
      { tool: "mac_directory_tree", arguments: { path: directory, depth: 1, max_entries: 20 } },
      { tool: "mac_write_file_atomic", arguments: { path: writePath, content: "safe", idempotency_key: "contract-write-1", encoding: "utf8", create_only: true } },
      { tool: "mac_job_status", arguments: { job_id: "job:contract", tail_bytes: 128 } },
      { tool: "mac_job_cancel", arguments: { job_id: "job:contract", reason: "contract-test" } }
    ];
    const cancelCase = cases.find((item) => item.tool === "mac_job_cancel");
    assert.ok(cancelCase);
    store.issueApproval({
      approvalId: "approval:contract-cancel",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_job_cancel",
      contractVersion: "0.1",
      targetKind: "job",
      targetRef: "job:job:contract",
      payloadDigest: sha256(canonicalJson(cancelCase.arguments)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_write",
      unattended: false,
      issuedAtMs: now - 500,
      expiresAtMs: now + 30_000
    });
    const writeCase = cases.find((item) => item.tool === "mac_write_file_atomic");
    assert.ok(writeCase);
    store.issueApproval({
      approvalId: "approval:contract-write",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_write_file_atomic",
      contractVersion: "0.1",
      targetKind: "path",
      targetRef: "path:test-root",
      payloadDigest: sha256(canonicalJson(writeCase.arguments)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_write",
      unattended: false,
      issuedAtMs: now - 500,
      expiresAtMs: now + 30_000
    });
    for (const [index, item] of cases.entries()) {
      const result = await broker.handle(signRequest(makeRequest(now, index, item.tool, item.arguments), key));
      const contract = JSON.parse(await readFile(join(repositoryRoot, "tool-contracts", `${item.tool}.json`), "utf8")) as {
        approval_policy: string;
        output_schema: object;
      };
      assert.equal(policy.tools.get(item.tool)?.approvalPolicy, contract.approval_policy);
      const validate = ajv.compile(contract.output_schema);
      assert.equal(validate(result), true, ajv.errorsText(validate.errors));
    }

    const deniedRequest = makeRequest(now, 20, "mac_health", {});
    deniedRequest.principal = { ...deniedRequest.principal, scopes: ["mac.files.read"] };
    const denied = await broker.handle(signRequest(deniedRequest, key));
    const failureSchema = JSON.parse(await readFile(join(repositoryRoot, "schemas", "broker-failure.schema.json"), "utf8")) as object;
    const validateFailure = ajv.compile(failureSchema);
    assert.equal(validateFailure(denied), true, ajv.errorsText(validateFailure.errors));
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

function makeRequest(now: number, index: number, tool: string, args: Record<string, unknown>): UnsignedBrokerRequest {
  return {
    protocolVersion: "0.1",
    requestId: `contract-request-${index}`,
    contractVersion: "0.1",
    tool,
    arguments: args,
      principal: {
      principalId: "principal-1", sessionId: "session-1", issuer: "test-issuer",
      audience: "mac-operator-broker", scopes: ["mac.control.read", "mac.policy.explain", "mac.system.read", ...(tool === "mac_process_list" ? ["mac.process.read"] : []), "mac.files.read", ...(tool === "mac_hash_file" ? ["mac.files.hash"] : []), ...(tool === "mac_write_file_atomic" ? ["mac.files.write"] : []), "mac.job.read", "mac.job.cancel"] as Scope[],
      issuedAtMs: now - 1_000, expiresAtMs: now + 60_000, edgeId: "edge-1"
    },
    timestampMs: now,
    nonce: `contract-nonce-${index}`,
    policyAudience: "mac-operator-broker",
    policyVersion: "policy-0.1",
    authenticationKeyId: "edge-key-1"
  };
}
