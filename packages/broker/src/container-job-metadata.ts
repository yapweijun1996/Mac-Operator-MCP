import { BrokerError, canonicalJson, parseJsonStrict } from "@mac-operator/contracts";
import { isPlainDataRecord } from "./plain-record.js";

export const MAX_CONTAINER_TASK_RUNTIME_MS = 600_000;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const PRINCIPAL_PATTERN = /^[A-Za-z0-9._:@/-]{1,128}$/u;
const IDENTITY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const METADATA_FIELDS = [
  "containerId", "deadlineAtMs", "engineId", "imageId", "maxRuntimeMs", "memoryBytes", "nanoCpus", "nonce", "owner",
  "pidsLimit", "readonlyWorkspace", "recordedAtMs", "schemaVersion", "taskDescriptorDigest", "taskId"
].sort().join(",");

/** Exact, non-secret authority needed to terminate a container after interruption. */
export interface ContainerTaskJobMetadata {
  schemaVersion: "0.1";
  containerId: string;
  engineId: string;
  imageId: string;
  taskId: string;
  owner: string;
  nonce: string;
  taskDescriptorDigest: string;
  recordedAtMs: number;
  deadlineAtMs: number;
  readonlyWorkspace: boolean;
  memoryBytes: number;
  nanoCpus: number;
  pidsLimit: number;
  maxRuntimeMs: number;
}

export function validateContainerTaskJobMetadata(value: unknown): asserts value is ContainerTaskJobMetadata {
  if (!isPlainDataRecord(value) || Object.keys(value).sort().join(",") !== METADATA_FIELDS ||
      value.schemaVersion !== "0.1" ||
      typeof value.containerId !== "string" || !DIGEST_PATTERN.test(value.containerId) ||
      typeof value.engineId !== "string" || !IDENTITY_PATTERN.test(value.engineId) ||
      typeof value.imageId !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(value.imageId) ||
      typeof value.taskId !== "string" || !IDENTITY_PATTERN.test(value.taskId) ||
      typeof value.owner !== "string" || !PRINCIPAL_PATTERN.test(value.owner) ||
      typeof value.nonce !== "string" || !DIGEST_PATTERN.test(value.nonce) ||
      typeof value.taskDescriptorDigest !== "string" || !DIGEST_PATTERN.test(value.taskDescriptorDigest) ||
      typeof value.readonlyWorkspace !== "boolean" ||
      !Number.isSafeInteger(value.memoryBytes) || (value.memoryBytes as number) < 64 * 1024 * 1024 ||
      (value.memoryBytes as number) > 4 * 1024 * 1024 * 1024 ||
      !Number.isSafeInteger(value.nanoCpus) || (value.nanoCpus as number) < 100_000_000 || (value.nanoCpus as number) > 4_000_000_000 ||
      !Number.isSafeInteger(value.pidsLimit) || (value.pidsLimit as number) < 16 || (value.pidsLimit as number) > 512 ||
      !Number.isSafeInteger(value.maxRuntimeMs) || (value.maxRuntimeMs as number) < 1 || (value.maxRuntimeMs as number) > MAX_CONTAINER_TASK_RUNTIME_MS ||
      !Number.isSafeInteger(value.recordedAtMs) || (value.recordedAtMs as number) < 0 ||
      !Number.isSafeInteger(value.deadlineAtMs) ||
      (value.deadlineAtMs as number) <= (value.recordedAtMs as number) ||
      (value.deadlineAtMs as number) - (value.recordedAtMs as number) > (value.maxRuntimeMs as number)) {
    throw new BrokerError("PRECONDITION_FAILED", "Container task ownership metadata is malformed");
  }
}

export function serializeContainerTaskJobMetadata(metadata: ContainerTaskJobMetadata): string {
  validateContainerTaskJobMetadata(metadata);
  return canonicalJson(metadata);
}

export function parseContainerTaskJobMetadata(value: string): ContainerTaskJobMetadata {
  try {
    if (typeof value !== "string" || Buffer.byteLength(value, "utf8") < 1 || Buffer.byteLength(value, "utf8") > 2_048) {
      throw new Error("Invalid metadata size");
    }
    const metadata: unknown = parseJsonStrict(value);
    validateContainerTaskJobMetadata(metadata);
    return Object.freeze(metadata);
  } catch {
    throw new BrokerError("AUDIT_UNAVAILABLE", "Stored container task ownership metadata is malformed");
  }
}
