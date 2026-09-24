#!/usr/bin/env node
import { lstat, mkdir, realpath } from "node:fs/promises";
import type { Stats } from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { BrokerError, type ErrorClass } from "@mac-operator/contracts";
import {
  createKeychainAuditAnchorKeySource,
  createKeychainAuditArchiveKeySource
} from "./credentials.js";
import { assertSocketNotActive } from "./ipc-server.js";
import { BrokerStore } from "./persistence.js";
import { validateProtectedDirectory, type BrokerBackupKeySource } from "./persistence-backup.js";
import { pruneArchiveArtifacts } from "./archive-retention.js";
import { BrokerServiceInstanceLock } from "./service-instance-lock.js";
import {
  brokerAuditArchiveDirectoryPath,
  brokerServiceInstanceLockPath,
  loadBrokerServiceStartupConfig,
  type BrokerServiceStartupConfig
} from "./service-startup.js";
import type { AuditArchiveManifest } from "./audit-export.js";
import type { LedgerArchiveManifest } from "./ledger-export.js";

const AUDIT_ARCHIVE_DIRECTORY_NAME = "audit-exports";

export const AUDIT_ARCHIVE_CLI_USAGE = [
  "mac-operator-audit export --config /absolute/path/broker-service.json --confirm export",
  "mac-operator-audit inspect --config /absolute/path/broker-service.json --archive /absolute/path/audit-export-...json.enc --confirm inspect",
  "mac-operator-audit ledger-export --config /absolute/path/broker-service.json --confirm ledger-export",
  "mac-operator-audit ledger-inspect --config /absolute/path/broker-service.json --archive /absolute/path/ledger-export-...json.enc --confirm ledger-inspect",
  "mac-operator-audit ledger-rotate --config /absolute/path/broker-service.json --retain-requests 10000 --retain-jobs 10000 --min-age-ms 86400000 --confirm ledger-rotate",
  "mac-operator-audit archive-prune --config /absolute/path/broker-service.json --retain-audit 7 --retain-ledger 7 --min-age-ms 86400000 --confirm archive-prune",
  "The export operation requires a separate configured Keychain archive key and a stopped Broker."
].join("\n");

export interface AuditArchiveExportCliCommand {
  kind: "export";
  configPath: string;
  confirmation: "export";
}

export interface AuditArchiveInspectCliCommand {
  kind: "inspect";
  configPath: string;
  archivePath: string;
  confirmation: "inspect";
}

export interface LedgerArchiveExportCliCommand {
  kind: "ledger-export";
  configPath: string;
  confirmation: "ledger-export";
}

export interface LedgerArchiveInspectCliCommand {
  kind: "ledger-inspect";
  configPath: string;
  archivePath: string;
  confirmation: "ledger-inspect";
}

export interface LedgerArchiveRotateCliCommand {
  kind: "ledger-rotate";
  configPath: string;
  retainRequestCount: number;
  retainJobCount: number;
  minAgeMs: number;
  confirmation: "ledger-rotate";
}

export interface ArchivePruneCliCommand {
  kind: "archive-prune";
  configPath: string;
  retainAuditCount: number;
  retainLedgerCount: number;
  minAgeMs: number;
  confirmation: "archive-prune";
}

export type AuditArchiveCliCommand =
  | AuditArchiveExportCliCommand
  | AuditArchiveInspectCliCommand
  | LedgerArchiveExportCliCommand
  | LedgerArchiveInspectCliCommand
  | LedgerArchiveRotateCliCommand
  | ArchivePruneCliCommand;

export interface AuditArchiveCliResult {
  schemaVersion: "0.1";
  operation: "export" | "inspect" | "ledger-export" | "ledger-inspect" | "ledger-rotate" | "archive-prune";
  verified: true;
  manifest?: AuditArchiveManifest | LedgerArchiveManifest;
  rotatedRequestCount?: number;
  rotatedJobCount?: number;
  retainedAuditCount?: number;
  retainedLedgerCount?: number;
  removedAuditCount?: number;
  removedLedgerCount?: number;
}

export function parseAuditArchiveCliArgs(args: readonly string[]): AuditArchiveCliCommand {
  const operation = args[0];
  if (operation !== "export" && operation !== "inspect" && operation !== "ledger-export" && operation !== "ledger-inspect" && operation !== "ledger-rotate" && operation !== "archive-prune") {
    throw usageError("Only export, inspect, ledger-export, ledger-inspect, ledger-rotate, and archive-prune operations are supported");
  }
  const values = parseOptionValues(args.slice(1));
  const configPath = requiredPath(values, "--config");
  const confirmation = values.get("--confirm");
  const allowed = operation === "export" || operation === "ledger-export"
    ? ["--config", "--confirm"]
    : operation === "ledger-rotate" || operation === "archive-prune"
      ? operation === "ledger-rotate"
        ? ["--config", "--retain-requests", "--retain-jobs", "--min-age-ms", "--confirm"]
        : ["--config", "--retain-audit", "--retain-ledger", "--min-age-ms", "--confirm"]
      : ["--config", "--archive", "--confirm"];
  for (const key of values.keys()) {
    if (!allowed.includes(key)) throw usageError("Audit archive options contain an unsupported field");
  }
  if (confirmation !== operation) throw usageError(`Audit archive operation requires --confirm ${operation}`);
  if (operation === "export") {
    return { kind: "export", configPath, confirmation: "export" };
  }
  if (operation === "ledger-export") {
    return { kind: "ledger-export", configPath, confirmation: "ledger-export" };
  }
  if (operation === "ledger-rotate") {
    return {
      kind: "ledger-rotate",
      configPath,
      retainRequestCount: requiredInteger(values, "--retain-requests"),
      retainJobCount: requiredInteger(values, "--retain-jobs"),
      minAgeMs: requiredInteger(values, "--min-age-ms"),
      confirmation: "ledger-rotate"
    };
  }
  if (operation === "archive-prune") {
    return {
      kind: "archive-prune",
      configPath,
      retainAuditCount: requiredInteger(values, "--retain-audit"),
      retainLedgerCount: requiredInteger(values, "--retain-ledger"),
      minAgeMs: requiredInteger(values, "--min-age-ms"),
      confirmation: "archive-prune"
    };
  }
  if (operation === "ledger-inspect") {
    return {
      kind: "ledger-inspect",
      configPath,
      archivePath: requiredPath(values, "--archive"),
      confirmation: "ledger-inspect"
    };
  }
  return {
    kind: "inspect",
    configPath,
    archivePath: requiredPath(values, "--archive"),
    confirmation: "inspect"
  };
}

export async function runAuditArchiveCli(args: readonly string[]): Promise<AuditArchiveCliResult> {
  const command = parseAuditArchiveCliArgs(args);
  const config = await loadBrokerServiceStartupConfig(command.configPath);
  const archiveKeySource = configuredArchiveKeySource(config);
  if (command.kind === "inspect" || command.kind === "ledger-inspect") {
    const archivePath = resolveArchivePath(config, command.archivePath);
    const manifest = command.kind === "inspect"
      ? await BrokerStore.inspectAuditArchive(archivePath, archiveKeySource)
      : await BrokerStore.inspectLedgerArchive(archivePath, archiveKeySource);
    return { schemaVersion: "0.1", operation: command.kind, verified: true, manifest };
  }

  const instanceLock = await BrokerServiceInstanceLock.acquire(brokerServiceInstanceLockPath(config.runtimeRoot));
  let store: BrokerStore | undefined;
  try {
    await assertSocketNotActive(config.brokerSocketPath);
    const archiveDirectory = await ensureAuditArchiveDirectory(config);
    if (command.kind === "archive-prune") {
      const pruned = await pruneArchiveArtifacts(archiveDirectory, {
        retainAuditCount: command.retainAuditCount,
        retainLedgerCount: command.retainLedgerCount,
        minAgeMs: command.minAgeMs
      });
      return {
        schemaVersion: "0.1",
        operation: command.kind,
        verified: true,
        retainedAuditCount: pruned.retainedAudit.length,
        retainedLedgerCount: pruned.retainedLedger.length,
        removedAuditCount: pruned.removedAudit.length,
        removedLedgerCount: pruned.removedLedger.length
      };
    }
    store = new BrokerStore(config.brokerDatabasePath, {
      runtimeFence: true,
      auditAnchor: {
        path: config.auditAnchorPath,
        keySource: createKeychainAuditAnchorKeySource(
          config.auditAnchorKeyService,
          config.auditAnchorKeyAccount,
          config.auditAnchorKeyId
        )
      }
    });
    if (command.kind === "ledger-rotate") {
      const rotation = await store.rotateLedgerArchive(archiveDirectory, {
        keySource: archiveKeySource,
        retainRequestCount: command.retainRequestCount,
        retainJobCount: command.retainJobCount,
        minAgeMs: command.minAgeMs
      });
      return {
        schemaVersion: "0.1",
        operation: command.kind,
        verified: true,
        manifest: rotation.archive,
        rotatedRequestCount: rotation.rotatedRequestCount,
        rotatedJobCount: rotation.rotatedJobCount
      };
    }
    const manifest = command.kind === "export"
      ? await store.exportAuditArchive(archiveDirectory, { keySource: archiveKeySource })
      : await store.exportLedgerArchive(archiveDirectory, { keySource: archiveKeySource });
    return { schemaVersion: "0.1", operation: command.kind, verified: true, manifest };
  } finally {
    try {
      store?.close();
    } finally {
      await instanceLock.close();
    }
  }
}

function configuredArchiveKeySource(config: BrokerServiceStartupConfig): BrokerBackupKeySource {
  if (config.auditArchiveKeyService === undefined || config.auditArchiveKeyAccount === undefined || config.auditArchiveKeyId === undefined) {
    throw new BrokerError("POLICY_DENIED", "Audit archive Keychain configuration is not enabled");
  }
  return createKeychainAuditArchiveKeySource(
    config.auditArchiveKeyService,
    config.auditArchiveKeyAccount,
    config.auditArchiveKeyId
  );
}

async function ensureAuditArchiveDirectory(config: BrokerServiceStartupConfig): Promise<string> {
  const dataRoot = await validateProtectedDirectory(config.dataRoot);
  const dataRootIdentity = await lstat(dataRoot, { bigint: false });
  const canonicalDataRoot = await realpath(dataRoot);
  if (canonicalDataRoot !== dataRoot) throw new BrokerError("POLICY_DENIED", "Broker data root is not canonical");
  const directory = brokerAuditArchiveDirectoryPath(config);
  if (basename(directory) !== AUDIT_ARCHIVE_DIRECTORY_NAME || dirname(directory) !== dataRoot) {
    throw new BrokerError("POLICY_DENIED", "Audit archive directory escaped the Broker data root");
  }
  try {
    await mkdir(directory, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }
  const dataRootAfter = await lstat(dataRoot, { bigint: false });
  if (!sameDirectoryIdentity(dataRootIdentity, dataRootAfter)) {
    throw new BrokerError("CONFLICT", "Broker data root changed during archive directory setup", true);
  }
  return validateProtectedDirectory(directory);
}

function sameDirectoryIdentity(
  left: Stats,
  right: Stats
): boolean {
  return left.isDirectory() && right.isDirectory() && left.dev === right.dev && left.ino === right.ino &&
    left.uid === right.uid && (left.mode & 0o7777) === (right.mode & 0o7777);
}

function resolveArchivePath(config: BrokerServiceStartupConfig, path: string): string {
  const directory = brokerAuditArchiveDirectoryPath(config);
  const target = resolve(path);
  const child = relative(directory, target);
  if (!isAbsolute(path) || target !== path || child.length === 0 || child.includes("/") || child === ".." || child.startsWith("..")) {
    throw new BrokerError("POLICY_DENIED", "Audit archive path must be a direct child of the configured archive directory");
  }
  return target;
}

function parseOptionValues(args: readonly string[]): Map<string, string> {
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const option = args[index];
    const value = args[index + 1];
    if (typeof option !== "string" || !option.startsWith("--") || option.length < 3 || values.has(option) ||
        typeof value !== "string" || value.startsWith("--")) {
      throw usageError("Audit archive options are malformed or duplicated");
    }
    values.set(option, value);
  }
  return values;
}

function requiredPath(values: ReadonlyMap<string, string>, option: string): string {
  const value = values.get(option);
  if (value === undefined || !isAbsolute(value) || resolve(value) !== value || value.includes("\0") || value.includes("\n") || value.includes("\r")) {
    throw usageError(`${option} must be a canonical absolute path`);
  }
  return value;
}

function requiredInteger(values: ReadonlyMap<string, string>, option: string): number {
  const value = values.get(option);
  if (value === undefined || !/^(?:0|[1-9][0-9]*)$/u.test(value)) throw usageError(`${option} must be a non-negative integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw usageError(`${option} is outside the safe integer range`);
  return parsed;
}

function usageError(message: string): BrokerError {
  return new BrokerError("PRECONDITION_FAILED", message);
}

function cliError(error: unknown): { schemaVersion: "0.1"; ok: false; errorClass: ErrorClass; message: string; retryable: boolean } {
  if (error instanceof BrokerError) {
    return { schemaVersion: "0.1", ok: false, errorClass: error.errorClass, message: error.message, retryable: error.retryable };
  }
  return { schemaVersion: "0.1", ok: false, errorClass: "PRECONDITION_FAILED", message: "Audit archive operation failed", retryable: false };
}

export async function main(args = process.argv.slice(2)): Promise<void> {
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
    process.stdout.write(`${AUDIT_ARCHIVE_CLI_USAGE}\n`);
    return;
  }
  try {
    const result = await runAuditArchiveCli(args);
    process.stdout.write(`${JSON.stringify({ schemaVersion: "0.1", ok: true, result })}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify(cliError(error))}\n`);
    process.exitCode = 1;
  }
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && pathToFileURL(resolve(invokedPath)).href === import.meta.url) {
  void main();
}
