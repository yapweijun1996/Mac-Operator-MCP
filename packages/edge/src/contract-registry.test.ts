import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { ToolContractRegistry } from "./contract-registry.js";

const validContract = {
  $schema: "./tool-contract.schema.json",
  schema_version: "0.1",
  tool_name: "mac_test",
  capability_level: "L0",
  purpose: "bounded test contract",
  required_scopes: ["mac.control.read"],
  normalized_target_type: "broker",
  timeout_ms: 3_000,
  output_cap_bytes: 65_536,
  filesystem_policy: "none",
  secret_policy: "redact",
  approval_policy: "trusted_read",
  postcondition_verification: {
    required: false,
    strategy: "component_health_result_validation",
    failure_class: "VERIFICATION_FAILED"
  },
  audit_class: "observe",
  tool_delivery_wave: "wave_1",
  implementation_status: "planned",
  input_summary: null,
  output_summary: null,
  input_schema: {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    title: "mac_test input",
    type: "object",
    properties: {},
    additionalProperties: false
  },
  output_schema: {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    title: "mac_test output",
    type: "object",
    properties: {},
    additionalProperties: false
  },
  source: {
    kbid: "mac-operator-mcp",
    kb_id: "90f1df58-87f6-4f47-aa9a-2881c478f8a0",
    kb_item_id: "00000000-0000-4000-8000-000000000001",
    source_text: "bounded test contract"
  },
  idempotent: true,
  safety_class: "read_only",
  network_policy: "none"
};

test("contract registry loads bounded regular files and exposes the parsed contract", async () => {
  await withTempDirectory(async (directory) => {
    await writeContract(directory, validContract);
    const registry = await ToolContractRegistry.load(directory);
    assert.deepEqual(registry.get("mac_test"), {
      schemaVersion: "0.1",
      toolName: "mac_test",
      purpose: "bounded test contract",
      inputSchema: validContract.input_schema,
      outputSchema: validContract.output_schema,
      idempotent: true,
      safetyClass: "read_only",
      networkPolicy: "none"
    });
  });
});

test("contract registry rejects a symlinked contract file", async () => {
  await withTempDirectory(async (directory) => {
    await writeFile(join(directory, "source.json"), JSON.stringify(validContract), "utf8");
    await symlink("source.json", join(directory, "mac_test.json"));
    await assert.rejects(() => ToolContractRegistry.load(directory));
  });
});

test("contract registry rejects a symlinked contract directory", async () => {
  await withTempDirectory(async (directory) => {
    const target = join(directory, "target");
    const link = join(directory, "link");
    await rm(target, { recursive: true, force: true });
    await import("node:fs/promises").then(({ mkdir }) => mkdir(target));
    await symlink(target, link);
    await assert.rejects(() => ToolContractRegistry.load(link), /must be a directory/u);
  });
});

test("contract registry rejects oversized files and invalid schema versions", async () => {
  await withTempDirectory(async (directory) => {
    await writeFile(join(directory, "mac_test.json"), Buffer.alloc(1_048_577, 0x20));
    await assert.rejects(() => ToolContractRegistry.load(directory), /supported size/u);
  });

  await withTempDirectory(async (directory) => {
    await writeContract(directory, { ...validContract, schema_version: "v0" });
    await assert.rejects(() => ToolContractRegistry.load(directory), /schema_version is invalid/u);
  });
});

test("contract registry rejects unknown top-level fields", async () => {
  await withTempDirectory(async (directory) => {
    await writeContract(directory, { ...validContract, unexpected: true });
    await assert.rejects(() => ToolContractRegistry.load(directory), /unknown field/u);
  });
});

test("contract registry rejects incomplete authority metadata", async () => {
  await withTempDirectory(async (directory) => {
    const { required_scopes: _requiredScopes, ...incomplete } = validContract;
    await writeContract(directory, incomplete);
    await assert.rejects(() => ToolContractRegistry.load(directory), /missing a required field/u);
  });
});

test("contract registry requires the explicit schema identity", async () => {
  await withTempDirectory(async (directory) => {
    const { $schema: _schema, ...withoutSchema } = validContract;
    await writeContract(directory, withoutSchema);
    await assert.rejects(() => ToolContractRegistry.load(directory), /missing a required field/u);
  });
});

test("contract registry rejects unknown scopes and malformed postconditions", async () => {
  await withTempDirectory(async (directory) => {
    await writeContract(directory, { ...validContract, required_scopes: ["mac.not_a_scope"] });
    await assert.rejects(() => ToolContractRegistry.load(directory), /required_scopes is invalid/u);
  });

  await withTempDirectory(async (directory) => {
    await writeContract(directory, {
      ...validContract,
      postcondition_verification: { required: true, strategy: "unknown", failure_class: "VERIFICATION_FAILED" }
    });
    await assert.rejects(() => ToolContractRegistry.load(directory), /postcondition_verification is invalid/u);
  });
});

test("contract registry rejects writable contract directories and files", async () => {
  await withTempDirectory(async (directory) => {
    await chmod(directory, 0o770);
    await writeContract(directory, validContract);
    await assert.rejects(() => ToolContractRegistry.load(directory), /directory must not be writable/u);
  });

  await withTempDirectory(async (directory) => {
    await writeContract(directory, validContract);
    await chmod(join(directory, "mac_test.json"), 0o660);
    await assert.rejects(() => ToolContractRegistry.load(directory), /contract must not be writable/u);
  });
});

async function writeContract(directory: string, contract: object): Promise<void> {
  await writeFile(join(directory, "mac_test.json"), JSON.stringify(contract), "utf8");
}

async function withTempDirectory(run: (directory: string) => Promise<void>): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-contracts-"));
  try {
    await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
