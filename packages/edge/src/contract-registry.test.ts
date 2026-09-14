import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { ToolContractRegistry } from "./contract-registry.js";

const validContract = {
  schema_version: "0.1",
  tool_name: "mac_test",
  purpose: "bounded test contract",
  input_schema: { type: "object" },
  output_schema: { type: "object" },
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
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
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
