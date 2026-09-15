import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createDefaultPolicy } from "./default-policy.js";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const contractsDirectory = join(repositoryRoot, "tool-contracts");

type ContractEnvelope = {
  tool_name: string;
  required_scopes: string[];
  normalized_target_type: string;
  timeout_ms: number;
  output_cap_bytes: number;
  approval_policy: string;
  safety_class: string;
};

test("default Broker policy stays in parity with materialized contract authority", async () => {
  const policy = createDefaultPolicy("contract-parity");
  const contractFiles = (await readdir(contractsDirectory))
    .filter((file) => /^mac_[a-z0-9_]+\.json$/u.test(file))
    .sort();
  const contractTools = new Set<string>();

  for (const file of contractFiles) {
    const contract = JSON.parse(await readFile(join(contractsDirectory, file), "utf8")) as ContractEnvelope;
    contractTools.add(contract.tool_name);
    const tool = policy.tools.get(contract.tool_name);
    assert.ok(tool, `${contract.tool_name} must have a Broker policy entry`);
    assert.deepEqual(tool.requiredScopes, contract.required_scopes, `${contract.tool_name}: required scopes drift`);
    assert.equal(tool.targetType, policyTargetType(contract.tool_name, contract.normalized_target_type), `${contract.tool_name}: target type drift`);
    assert.equal(tool.timeoutMs, contract.timeout_ms, `${contract.tool_name}: timeout drift`);
    assert.equal(tool.outputCapBytes, contract.output_cap_bytes, `${contract.tool_name}: output cap drift`);
    assert.equal(tool.approvalPolicy, contract.approval_policy, `${contract.tool_name}: approval policy drift`);
    assert.equal(tool.mutation, mutationForSafetyClass(contract.safety_class), `${contract.tool_name}: mutation safety drift`);
  }

  assert.deepEqual([...policy.tools.keys()].sort(), [...contractTools].sort(), "Broker policy and contract tool sets must match");
});

function policyTargetType(toolName: string, contractTargetType: string): string {
  // Contract target labels describe the caller-facing identifier. The Broker
  // normalizes aliases to its authorization target vocabulary before dispatch.
  if (toolName === "mac_project_summary") return "path";
  const aliases: Record<string, string> = {
    app_id: "app",
    container_id: "docker_object",
    host: "broker",
    host_network: "broker",
    job_id: "job",
    package_id: "package",
    pid: "process",
    policy_request: "policy_query",
    process_set: "process",
    project_root: "project",
    service_id: "service"
  };
  return aliases[contractTargetType] ?? contractTargetType;
}

function mutationForSafetyClass(safetyClass: string): boolean {
  if (safetyClass === "read_only") return false;
  if (safetyClass === "writes_local" || safetyClass === "destructive" || safetyClass === "privileged") return true;
  throw new Error(`Unsupported contract safety class: ${safetyClass}`);
}
