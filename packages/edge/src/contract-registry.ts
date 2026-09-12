import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

export interface EdgeToolContract {
  schemaVersion: string;
  toolName: string;
  purpose: string;
  inputSchema: Record<string, unknown>;
  outputSchema: Record<string, unknown>;
  idempotent: boolean;
  safetyClass: string;
  networkPolicy: string;
}

export class ToolContractRegistry {
  private constructor(private readonly contracts: ReadonlyMap<string, EdgeToolContract>) {}

  static async load(directory: string): Promise<ToolContractRegistry> {
    const files = (await readdir(directory))
      .filter((file) => /^mac_[a-z0-9_]+\.json$/u.test(file))
      .sort();
    const contracts = new Map<string, EdgeToolContract>();
    for (const file of files) {
      const raw = JSON.parse(await readFile(join(directory, file), "utf8")) as unknown;
      const contract = parseContract(raw, file);
      if (contracts.has(contract.toolName)) throw new Error(`Duplicate Edge tool contract: ${contract.toolName}`);
      contracts.set(contract.toolName, contract);
    }
    return new ToolContractRegistry(contracts);
  }

  get(toolName: string): EdgeToolContract | undefined {
    return this.contracts.get(toolName);
  }
}

function parseContract(value: unknown, file: string): EdgeToolContract {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${file}: tool contract must be an object`);
  }
  const record = value as Record<string, unknown>;
  const toolName = stringField(record, "tool_name", file);
  if (file !== `${toolName}.json`) throw new Error(`${file}: filename does not match tool_name`);
  return {
    schemaVersion: stringField(record, "schema_version", file),
    toolName,
    purpose: stringField(record, "purpose", file),
    inputSchema: objectField(record, "input_schema", file),
    outputSchema: objectField(record, "output_schema", file),
    idempotent: booleanField(record, "idempotent", file),
    safetyClass: stringField(record, "safety_class", file),
    networkPolicy: stringField(record, "network_policy", file)
  };
}

function stringField(record: Record<string, unknown>, key: string, file: string): string {
  const value = record[key];
  if (typeof value !== "string" || value.length === 0) throw new Error(`${file}: ${key} must be a non-empty string`);
  return value;
}

function booleanField(record: Record<string, unknown>, key: string, file: string): boolean {
  const value = record[key];
  if (typeof value !== "boolean") throw new Error(`${file}: ${key} must be a boolean`);
  return value;
}

function objectField(record: Record<string, unknown>, key: string, file: string): Record<string, unknown> {
  const value = record[key];
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${file}: ${key} must be an object`);
  return value as Record<string, unknown>;
}
