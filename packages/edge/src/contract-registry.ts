import { constants } from "node:fs";
import { lstat, open, readdir } from "node:fs/promises";
import { join } from "node:path";
import { decodeUtf8Strict, parseJsonStrict } from "@mac-operator/contracts";

const MAX_CONTRACT_FILES = 64;
const MAX_CONTRACT_FILE_BYTES = 1_048_576;
const MAX_CONTRACT_BYTES = 8 * 1_048_576;
const MAX_TOOL_NAME_LENGTH = 128;
const MAX_SCHEMA_VERSION_LENGTH = 32;
const MAX_PURPOSE_LENGTH = 2_048;
const MAX_POLICY_FIELD_LENGTH = 128;

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
    if (typeof directory !== "string" || directory.length === 0 || directory.includes("\0")) {
      throw new Error("Tool contract directory is invalid");
    }
    const directoryStat = await lstat(directory);
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) throw new Error("Tool contract path must be a directory (regular non-symlink)");
    if ((directoryStat.mode & 0o022) !== 0) throw new Error("Tool contract directory must not be writable by group or other users");
    const files = (await readdir(directory, { withFileTypes: true }))
      .filter((entry) => /^mac_[a-z0-9_]+\.json$/u.test(entry.name))
      .map((entry) => entry.name)
      .sort();
    if (files.length > MAX_CONTRACT_FILES) throw new Error("Too many tool contracts");
    const contracts = new Map<string, EdgeToolContract>();
    let totalBytes = 0;
    for (const file of files) {
      const rawText = await readContractFile(join(directory, file));
      totalBytes += Buffer.byteLength(rawText, "utf8");
      if (totalBytes > MAX_CONTRACT_BYTES) throw new Error("Tool contracts exceed the supported size");
      let raw: unknown;
      try {
        raw = parseJsonStrict(rawText);
      } catch {
        throw new Error(`${file}: tool contract is not valid JSON`);
      }
      const contract = parseContract(raw, file);
      if (contracts.has(contract.toolName)) throw new Error(`Duplicate Edge tool contract: ${contract.toolName}`);
      contracts.set(contract.toolName, contract);
    }
    const finalDirectoryStat = await lstat(directory);
    if (!finalDirectoryStat.isDirectory() || finalDirectoryStat.isSymbolicLink() ||
        finalDirectoryStat.dev !== directoryStat.dev || finalDirectoryStat.ino !== directoryStat.ino ||
        (finalDirectoryStat.mode & 0o022) !== 0) {
      throw new Error("Tool contract directory changed while loading");
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
  if (toolName.length > MAX_TOOL_NAME_LENGTH || !/^mac_[a-z0-9_]+$/u.test(toolName)) {
    throw new Error(`${file}: tool_name is invalid`);
  }
  if (file !== `${toolName}.json`) throw new Error(`${file}: filename does not match tool_name`);
  const schemaVersion = stringField(record, "schema_version", file);
  if (
    schemaVersion.length > MAX_SCHEMA_VERSION_LENGTH ||
    !/^\d+\.\d+$/u.test(schemaVersion)
  ) {
    throw new Error(`${file}: schema_version is invalid`);
  }
  const purpose = stringField(record, "purpose", file);
  if (purpose.length > MAX_PURPOSE_LENGTH) throw new Error(`${file}: purpose is too long`);
  const safetyClass = stringField(record, "safety_class", file);
  const networkPolicy = stringField(record, "network_policy", file);
  if (safetyClass.length > MAX_POLICY_FIELD_LENGTH || networkPolicy.length > MAX_POLICY_FIELD_LENGTH) {
    throw new Error(`${file}: policy field is too long`);
  }
  return {
    schemaVersion,
    toolName,
    purpose,
    inputSchema: objectField(record, "input_schema", file),
    outputSchema: objectField(record, "output_schema", file),
    idempotent: booleanField(record, "idempotent", file),
    safetyClass,
    networkPolicy
  };
}

async function readContractFile(path: string): Promise<string> {
  const noFollow = constants.O_NOFOLLOW;
  if (typeof noFollow !== "number") throw new Error("Contract loading requires O_NOFOLLOW support");
  const pathStat = await lstat(path);
  if (!pathStat.isFile() || pathStat.isSymbolicLink()) throw new Error("Tool contract must be a regular non-symlink file");
  if ((pathStat.mode & 0o022) !== 0) throw new Error("Tool contract must not be writable by group or other users");
  const handle = await open(path, constants.O_RDONLY | noFollow);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.isSymbolicLink() || before.dev !== pathStat.dev || before.ino !== pathStat.ino ||
        (before.mode & 0o022) !== 0) throw new Error("Tool contract target changed while opening");
    if (before.size > MAX_CONTRACT_FILE_BYTES) throw new Error("Tool contract exceeds the supported size");
    const buffer = Buffer.alloc(MAX_CONTRACT_FILE_BYTES + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    const after = await handle.stat();
    if (!after.isFile() || after.isSymbolicLink() || after.dev !== pathStat.dev || after.ino !== pathStat.ino ||
        (after.mode & 0o022) !== 0 || after.size > MAX_CONTRACT_FILE_BYTES || bytesRead > MAX_CONTRACT_FILE_BYTES) {
      throw new Error("Tool contract exceeds the supported size");
    }
    if (after.size !== bytesRead) throw new Error("Tool contract changed while loading");
    return decodeUtf8Strict(buffer.subarray(0, bytesRead));
  } finally {
    await handle.close();
  }
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
