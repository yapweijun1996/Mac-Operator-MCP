import { constants } from "node:fs";
import { lstat, open, readdir } from "node:fs/promises";
import { join } from "node:path";
import { CONTRACT_VERSION, SCOPES, decodeUtf8Strict, parseJsonStrict } from "@mac-operator/contracts";
import { isPlainDataRecord } from "./plain-record.js";
import { readProtectedFileAfterIdentity, sameProtectedFileMetadata } from "./protected-file.js";

const MAX_CONTRACT_FILES = 64;
const MAX_CONTRACT_FILE_BYTES = 1_048_576;
const MAX_CONTRACT_BYTES = 8 * 1_048_576;
const MAX_TOOL_NAME_LENGTH = 128;
const MAX_SCHEMA_VERSION_LENGTH = 32;
const MAX_PURPOSE_LENGTH = 2_048;
const MAX_POLICY_FIELD_LENGTH = 128;
const MAX_TARGET_TYPE_LENGTH = 128;
const MAX_SUMMARY_LENGTH = 2_048;
const MAX_SOURCE_TEXT_LENGTH = 16_384;
const MAX_TIMEOUT_MS = 600_000;
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const CONTRACT_KEYS = new Set([
  "$schema", "schema_version", "tool_name", "capability_level", "safety_class", "required_scopes",
  "normalized_target_type", "timeout_ms", "output_cap_bytes", "network_policy", "filesystem_policy",
  "secret_policy", "approval_policy", "idempotent", "postcondition_verification", "audit_class",
  "tool_delivery_wave", "implementation_status", "purpose", "input_summary", "output_summary",
  "input_schema", "output_schema", "source"
]);
const REQUIRED_CONTRACT_KEYS = new Set([
  "$schema", "schema_version", "tool_name", "capability_level", "safety_class", "required_scopes",
  "normalized_target_type", "timeout_ms", "output_cap_bytes", "network_policy", "filesystem_policy",
  "secret_policy", "approval_policy", "idempotent", "postcondition_verification", "audit_class",
  "tool_delivery_wave", "implementation_status", "purpose", "input_summary", "output_summary",
  "input_schema", "output_schema", "source"
]);
const CAPABILITY_LEVELS = new Set(["L0", "L1", "L2", "L3", "L4", "L5"]);
const SAFETY_CLASSES = new Set(["read_only", "writes_local", "destructive", "privileged"]);
const AUDIT_CLASSES = new Set([
  "observe", "filesystem_read", "developer_read", "execution", "filesystem_write", "git_write",
  "app_control", "gui_control", "privileged"
]);
const DELIVERY_WAVES = new Set(["wave_1", "wave_2", "wave_3", "wave_4", "wave_5"]);
const POSTCONDITION_STRATEGIES = new Set([
  "bounded_result_validation", "bounded_tree_result_validation", "capability_state_result_validation",
  "component_health_result_validation", "policy_decision_result_validation", "bounded_system_result_validation",
  "bounded_storage_result_validation", "bounded_process_result_validation", "sanitized_log_result_validation",
  "bounded_network_result_validation", "service_state_result_validation", "canonical_metadata_result_validation",
  "bounded_content_result_validation", "digest_result_validation", "safe_project_result_validation",
  "sanitized_diff_result_validation", "package_metadata_result_validation", "sanitized_docker_result_validation",
  "exit_status_and_declared_task_verification", "job_result_validation", "job_state_termination_verification",
  "changed_paths_and_hash_readback", "readback_hash", "staged_diff_hash",
  "commit_id_parent_and_staged_precondition", "app_inventory_result_validation",
  "launch_state_and_target_reobservation", "focused_app_window_reobservation",
  "accessibility_snapshot_validation", "accessibility_reobservation", "focused_target_and_input_postcondition",
  "service_state_readback", "installed_version_verification", "handoff_acceptance_and_scheduled_state"
]);

export interface EdgeToolContract {
  schemaVersion: string;
  toolName: string;
  requiredScopes: readonly string[];
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
    const currentUid = process.getuid?.();
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink() || currentUid === undefined || directoryStat.uid !== currentUid) {
      throw new Error("Tool contract path must be a directory (regular non-symlink) owned by the Edge user");
    }
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
    const finalCurrentUid = process.getuid?.();
    if (!finalDirectoryStat.isDirectory() || finalDirectoryStat.isSymbolicLink() ||
        finalCurrentUid === undefined || finalDirectoryStat.uid !== finalCurrentUid ||
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
  if (!isPlainDataRecord(value)) {
    throw new Error(`${file}: tool contract must be an object`);
  }
  const record = value;
  const keys = Object.keys(record);
  if (keys.some((key) => !CONTRACT_KEYS.has(key))) {
    throw new Error(`${file}: tool contract contains an unknown field`);
  }
  if (keys.length !== REQUIRED_CONTRACT_KEYS.size || [...REQUIRED_CONTRACT_KEYS].some((key) => !Object.prototype.hasOwnProperty.call(record, key))) {
    throw new Error(`${file}: tool contract is missing a required field`);
  }
  if (record.$schema !== "./tool-contract.schema.json") {
    throw new Error(`${file}: $schema is invalid`);
  }
  const toolName = stringField(record, "tool_name", file);
  if (toolName.length > MAX_TOOL_NAME_LENGTH || !/^mac_[a-z0-9_]+$/u.test(toolName)) {
    throw new Error(`${file}: tool_name is invalid`);
  }
  if (file !== `${toolName}.json`) throw new Error(`${file}: filename does not match tool_name`);
  const schemaVersion = stringField(record, "schema_version", file, MAX_SCHEMA_VERSION_LENGTH);
  if (schemaVersion !== CONTRACT_VERSION) {
    throw new Error(`${file}: schema_version is invalid`);
  }
  const purpose = stringField(record, "purpose", file);
  if (purpose.length > MAX_PURPOSE_LENGTH) throw new Error(`${file}: purpose is too long`);
  const safetyClass = stringField(record, "safety_class", file);
  const networkPolicy = stringField(record, "network_policy", file);
  if (safetyClass.length > MAX_POLICY_FIELD_LENGTH || networkPolicy.length > MAX_POLICY_FIELD_LENGTH) {
    throw new Error(`${file}: policy field is too long`);
  }
  enumField(record, "capability_level", CAPABILITY_LEVELS, file);
  enumField(record, "safety_class", SAFETY_CLASSES, file);
  enumField(record, "audit_class", AUDIT_CLASSES, file);
  enumField(record, "tool_delivery_wave", DELIVERY_WAVES, file);
  if (record.implementation_status !== "planned") throw new Error(`${file}: implementation_status is invalid`);
  const scopes = record.required_scopes;
  if (!Array.isArray(scopes) || scopes.length === 0 || scopes.length > SCOPES.length ||
      new Set(scopes).size !== scopes.length || scopes.some((scope) => typeof scope !== "string" || !SCOPES.includes(scope as typeof SCOPES[number]))) {
    throw new Error(`${file}: required_scopes is invalid`);
  }
  const targetType = stringField(record, "normalized_target_type", file, MAX_TARGET_TYPE_LENGTH);
  if (targetType.length > MAX_TARGET_TYPE_LENGTH) throw new Error(`${file}: normalized_target_type is too long`);
  const timeoutMs = record.timeout_ms;
  if (typeof timeoutMs !== "number" || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new Error(`${file}: timeout_ms is invalid`);
  }
  const outputCapBytes = record.output_cap_bytes;
  if (typeof outputCapBytes !== "number" || !Number.isSafeInteger(outputCapBytes) || outputCapBytes < 1 || outputCapBytes > MAX_OUTPUT_BYTES) {
    throw new Error(`${file}: output_cap_bytes is invalid`);
  }
  for (const key of ["filesystem_policy", "secret_policy", "approval_policy"] as const) {
    stringField(record, key, file, MAX_POLICY_FIELD_LENGTH);
  }
  if (typeof record.idempotent !== "boolean") throw new Error(`${file}: idempotent must be a boolean`);
  validatePostcondition(record.postcondition_verification, file);
  for (const key of ["input_summary", "output_summary"] as const) {
    const summary = record[key];
    if (summary !== null && (typeof summary !== "string" || summary.length > MAX_SUMMARY_LENGTH)) {
      throw new Error(`${file}: ${key} is invalid`);
    }
  }
  validateFunctionalSchema(record.input_schema, "input_schema", file);
  validateFunctionalSchema(record.output_schema, "output_schema", file);
  validateSource(record.source, file);
  return {
    schemaVersion,
    toolName,
    requiredScopes: [...scopes as string[]],
    purpose,
    inputSchema: objectField(record, "input_schema", file),
    outputSchema: objectField(record, "output_schema", file),
    idempotent: booleanField(record, "idempotent", file),
    safetyClass,
    networkPolicy
  };
}

function enumField(record: Record<string, unknown>, key: string, allowed: ReadonlySet<string>, file: string): string {
  const value = record[key];
  if (typeof value !== "string" || !allowed.has(value)) throw new Error(`${file}: ${key} is invalid`);
  return value;
}

function validatePostcondition(value: unknown, file: string): void {
  if (!isPlainDataRecord(value) || !hasExactKeys(value, ["required", "strategy", "failure_class"]) ||
      typeof value.required !== "boolean" || typeof value.strategy !== "string" ||
      !POSTCONDITION_STRATEGIES.has(value.strategy) || value.failure_class !== "VERIFICATION_FAILED") {
    throw new Error(`${file}: postcondition_verification is invalid`);
  }
}

function validateFunctionalSchema(value: unknown, key: string, file: string): void {
  if (!isPlainDataRecord(value) || value.$schema !== "https://json-schema.org/draft/2020-12/schema" ||
      typeof value.title !== "string" || value.title.length === 0 || value.title.length > MAX_PURPOSE_LENGTH ||
      value.type !== "object" || !isPlainDataRecord(value.properties) || value.additionalProperties !== false ||
      (value.required !== undefined && (!Array.isArray(value.required) || new Set(value.required).size !== value.required.length ||
        value.required.some((entry) => typeof entry !== "string" || entry.length === 0 || entry.length > MAX_TARGET_TYPE_LENGTH)))) {
    throw new Error(`${file}: ${key} is invalid`);
  }
}

function validateSource(value: unknown, file: string): void {
  if (!isPlainDataRecord(value) || !hasExactKeys(value, ["kbid", "kb_id", "kb_item_id", "source_text"]) ||
      value.kbid !== "mac-operator-mcp" || value.kb_id !== "90f1df58-87f6-4f47-aa9a-2881c478f8a0" ||
      typeof value.kb_item_id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value.kb_item_id) ||
      typeof value.source_text !== "string" || value.source_text.length === 0 || value.source_text.length > MAX_SOURCE_TEXT_LENGTH) {
    throw new Error(`${file}: source is invalid`);
  }
}

function hasExactKeys(value: Record<string, unknown>, required: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === required.length && required.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

async function readContractFile(path: string): Promise<string> {
  const noFollow = constants.O_NOFOLLOW;
  if (typeof noFollow !== "number") throw new Error("Contract loading requires O_NOFOLLOW support");
  const pathStat = await lstat(path);
  const currentUid = process.getuid?.();
  if (!pathStat.isFile() || pathStat.isSymbolicLink() || currentUid === undefined || pathStat.uid !== currentUid) {
    throw new Error("Tool contract must be a regular non-symlink file owned by the Edge user");
  }
  if ((pathStat.mode & 0o022) !== 0) throw new Error("Tool contract must not be writable by group or other users");
  const handle = await open(path, constants.O_RDONLY | noFollow);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.isSymbolicLink() || !sameProtectedFileMetadata(pathStat, before) ||
        (before.mode & 0o022) !== 0) throw new Error("Tool contract target changed while opening");
    if (before.size > MAX_CONTRACT_FILE_BYTES) throw new Error("Tool contract exceeds the supported size");
    const buffer = Buffer.alloc(MAX_CONTRACT_FILE_BYTES + 1);
    try {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
      const content = buffer.subarray(0, bytesRead);
      const readback = await readProtectedFileAfterIdentity({
        readFile: async () => content,
        stat: () => handle.stat()
      }, before, MAX_CONTRACT_FILE_BYTES, "Tool contract");
      try {
        return decodeUtf8Strict(readback);
      } finally {
        readback.fill(0);
      }
    } finally {
      buffer.fill(0);
    }
  } finally {
    await handle.close();
  }
}

function stringField(record: Record<string, unknown>, key: string, file: string, maxLength = MAX_PURPOSE_LENGTH): string {
  const value = record[key];
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) throw new Error(`${file}: ${key} must be a non-empty string`);
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
