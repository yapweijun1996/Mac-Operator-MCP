import { lstatSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import {
  createApprovalIssuerRuntime,
  type ApprovalIssuerRuntimeAssembly,
  type BrokerStore
} from "@mac-operator/broker";
import { readAuthFile } from "./cli.js";

const MAX_CONFIG_BYTES = 16 * 1024;

export interface PersonalApprovalIssuerConfig {
  schemaVersion: "0.1";
  enabled: boolean;
  keyConfigPath: string;
  socketPath: string;
}

/**
 * Reads the fixed owner-controlled approval startup document. A missing file
 * is the same as disabled so existing R1 installations are unchanged.
 */
export function loadPersonalApprovalIssuerConfig(
  configPath: string,
  dataRoot: string,
  runtimeRoot: string
): PersonalApprovalIssuerConfig | undefined {
  try {
    lstatSync(configPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  const bytes = readAuthFile(configPath, MAX_CONFIG_BYTES);
  try {
    const value: unknown = JSON.parse(bytes.toString("utf8"));
    return validatePersonalApprovalIssuerConfig(value, configPath, dataRoot, runtimeRoot);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Personal approval issuer")) throw error;
    throw new Error("Personal approval issuer config is not valid JSON");
  } finally {
    bytes.fill(0);
  }
}

export async function createPersonalApprovalIssuerRuntime(options: {
  configPath: string;
  dataRoot: string;
  runtimeRoot: string;
  store: BrokerStore;
  uid: number;
  gid?: number;
  now?: () => number;
}): Promise<ApprovalIssuerRuntimeAssembly | undefined> {
  const config = loadPersonalApprovalIssuerConfig(options.configPath, options.dataRoot, options.runtimeRoot);
  if (config === undefined || !config.enabled) return undefined;
  return createApprovalIssuerRuntime({
    store: options.store,
    startup: {
      enabled: true,
      keyConfigPath: config.keyConfigPath,
      socketPath: config.socketPath,
      peerPolicy: {
        expectedUid: options.uid,
        ...(options.gid === undefined ? {} : { expectedGid: options.gid })
      }
    },
    ...(options.now === undefined ? {} : { now: options.now })
  });
}

export function validatePersonalApprovalIssuerConfig(
  value: unknown,
  configPath: string,
  dataRoot: string,
  runtimeRoot: string
): PersonalApprovalIssuerConfig {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Personal approval issuer config is malformed");
  }
  const record = value as Record<string, unknown>;
  const keys = ["schemaVersion", "enabled", "keyConfigPath", "socketPath"];
  if (Object.keys(record).some((key) => !keys.includes(key)) ||
      record.schemaVersion !== "0.1" || typeof record.enabled !== "boolean" ||
      typeof record.keyConfigPath !== "string" || typeof record.socketPath !== "string") {
    throw new Error("Personal approval issuer config is malformed");
  }
  if (!isCanonicalAbsolutePath(configPath) || !isCanonicalAbsolutePath(dataRoot) || !isCanonicalAbsolutePath(runtimeRoot) ||
      !isCanonicalAbsolutePath(record.keyConfigPath) || !isCanonicalAbsolutePath(record.socketPath)) {
    throw new Error("Personal approval issuer config paths are not canonical");
  }
  const expectedKeyPath = resolve(dataRoot, "approval-keys.json");
  const expectedSocketPath = resolve(runtimeRoot, "approval.sock");
  if (record.keyConfigPath !== expectedKeyPath || record.socketPath !== expectedSocketPath ||
      configPath !== resolve(dataRoot, "approval-issuer.json")) {
    throw new Error("Personal approval issuer config paths are not fixed to the protected profile");
  }
  return {
    schemaVersion: "0.1",
    enabled: record.enabled,
    keyConfigPath: expectedKeyPath,
    socketPath: expectedSocketPath
  };
}

function isCanonicalAbsolutePath(value: string): boolean {
  return isAbsolute(value) && resolve(value) === value && !value.includes("\0") && !value.includes("\n");
}
