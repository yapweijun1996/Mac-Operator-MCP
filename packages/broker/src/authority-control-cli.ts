#!/usr/bin/env node
import { lstat, realpath } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { isAbsolute, dirname, resolve } from "node:path";
import { BrokerError, type ErrorClass } from "@mac-operator/contracts";
import {
  AUTHORITY_CONTROL_REVOCATION_KINDS,
  AUTHORITY_CONTROL_SWITCH_NAMES,
  AuthorityControlIpcClient,
} from "./authority-control-ipc.js";
import { AuthorityControlKeyManager } from "./authority-control-keyring.js";
import { BrokerStore, type RevocationKind, type SwitchName } from "./persistence.js";

const REASON_PATTERN = /^[A-Z0-9._:-]{1,96}$/u;
const MAX_TIMEOUT_MS = 600_000;

export type AuthorityControlCliCommand =
  | {
      kind: "status";
      databasePath: string;
      socketPath: string;
      keyConfigPath: string;
      timeoutMs: number;
      switchName?: SwitchName;
      revocationKind?: RevocationKind;
      subjectId?: string;
    }
  | {
      kind: "set-switch";
      databasePath: string;
      socketPath: string;
      keyConfigPath: string;
      timeoutMs: number;
      switchName: SwitchName;
      disabled: boolean;
      expectedDisabled: boolean;
      reason: string;
      confirmation: "set-switch";
    }
  | {
      kind: "revoke";
      databasePath: string;
      socketPath: string;
      keyConfigPath: string;
      timeoutMs: number;
      revocationKind: RevocationKind;
      subjectId: string;
      reason: string;
      confirmation: "revoke";
    };

export type AuthorityControlCliResult =
  | {
      schemaVersion: "0.1";
      operation: "status";
      switches: Readonly<Partial<Record<SwitchName, boolean>>>;
      revocation?: { kind: RevocationKind; subjectId: string; revoked: boolean };
    }
  | {
      schemaVersion: "0.1";
      operation: "set-switch";
      switchName: SwitchName;
      disabled: boolean;
      verified: true;
    }
  | {
      schemaVersion: "0.1";
      operation: "revoke";
      revocationKind: RevocationKind;
      subjectId: string;
      revoked: true;
      verified: true;
    };

export interface AuthorityControlCliClient {
  setSwitch(switchName: SwitchName, disabled: boolean, expectedDisabled: boolean, reason: string): Promise<void>;
  revoke(kind: RevocationKind, subjectId: string, reason: string): Promise<void>;
  readSwitch(switchName: SwitchName): Promise<boolean>;
  readRevocation(kind: RevocationKind, subjectId: string): Promise<boolean>;
}

export const AUTHORITY_CONTROL_CLI_USAGE = [
  "mac-operator-authority status --database PATH --socket PATH --key-config PATH [--name SWITCH | --kind KIND --subject-id ID]",
  "mac-operator-authority set-switch --database PATH --socket PATH --key-config PATH --name SWITCH --disabled true|false --expected-disabled true|false --reason CODE --confirm set-switch",
  "mac-operator-authority revoke --database PATH --socket PATH --key-config PATH --kind KIND --subject-id ID --reason CODE --confirm revoke"
].join("\n");

/**
 * Parses the deliberately small operator surface. It accepts no raw key,
 * command, executable, target path, or capability grant.
 */
export function parseAuthorityControlCliArgs(args: readonly string[]): AuthorityControlCliCommand {
  if (args.length < 1) throw usageError("An operation is required");
  const operation = args[0];
  if (operation !== "status" && operation !== "set-switch" && operation !== "revoke") {
    throw usageError("Unsupported authority operation");
  }
  const values = new Map<string, string>();
  for (let index = 1; index < args.length; index += 1) {
    const option = args[index];
    if (typeof option !== "string" || !option.startsWith("--") || option.length < 3 || values.has(option)) {
      throw usageError("Authority options are malformed or duplicated");
    }
    const value = args[index + 1];
    if (typeof value !== "string" || value.startsWith("--")) throw usageError(`Missing value for ${option}`);
    values.set(option, value);
    index += 1;
  }
  const databasePath = requiredPath(values, "--database");
  const socketPath = requiredPath(values, "--socket");
  const keyConfigPath = requiredPath(values, "--key-config");
  const timeoutMs = parseTimeout(values.get("--timeout-ms"));
  const switchName = parseSwitch(values.get("--name"));
  const revocationKind = parseRevocationKind(values.get("--kind"));
  const subjectId = values.get("--subject-id");
  if (subjectId !== undefined && !/^[A-Za-z0-9._:@/-]{1,257}$/u.test(subjectId)) {
    throw usageError("Subject ID is malformed");
  }
  const reason = values.get("--reason");
  if (reason !== undefined && !REASON_PATTERN.test(reason)) throw usageError("Reason must be an uppercase reason code");
  const confirmation = values.get("--confirm");
  const allowedCommon = new Set(["--database", "--socket", "--key-config", "--timeout-ms"]);
  if (operation === "status") {
    for (const key of values.keys()) {
      if (!allowedCommon.has(key) && key !== "--name" && key !== "--kind" && key !== "--subject-id") {
        throw usageError("Status accepts only a switch or revocation readback target");
      }
    }
    if (switchName !== undefined && (revocationKind !== undefined || subjectId !== undefined)) {
      throw usageError("Status target must be either a switch or a revocation");
    }
    if (revocationKind !== undefined && subjectId === undefined) throw usageError("Revocation status requires --subject-id");
    if (revocationKind === undefined && subjectId !== undefined) throw usageError("--subject-id requires --kind");
    return {
      kind: "status", databasePath, socketPath, keyConfigPath, timeoutMs,
      ...(switchName === undefined ? {} : { switchName }),
      ...(revocationKind === undefined ? {} : { revocationKind }),
      ...(subjectId === undefined ? {} : { subjectId })
    };
  }
  if (operation === "set-switch") {
    for (const key of values.keys()) {
      if (!allowedCommon.has(key) && !["--name", "--disabled", "--expected-disabled", "--reason", "--confirm"].includes(key)) {
        throw usageError("Switch changes contain an unsupported option");
      }
    }
    const disabled = parseBoolean(values.get("--disabled"), "--disabled");
    const expectedDisabled = parseBoolean(values.get("--expected-disabled"), "--expected-disabled");
    if (switchName === undefined || reason === undefined || confirmation !== "set-switch") {
      throw usageError("Switch changes require --name, --disabled, --expected-disabled, --reason, and --confirm set-switch");
    }
    return { kind: "set-switch", databasePath, socketPath, keyConfigPath, timeoutMs, switchName, disabled, expectedDisabled, reason, confirmation };
  }
  for (const key of values.keys()) {
    if (!allowedCommon.has(key) && !["--kind", "--subject-id", "--reason", "--confirm"].includes(key)) {
      throw usageError("Revocation contains an unsupported option");
    }
  }
  if (revocationKind === undefined || subjectId === undefined || reason === undefined || confirmation !== "revoke") {
    throw usageError("Revocation requires --kind, --subject-id, --reason, and --confirm revoke");
  }
  return { kind: "revoke", databasePath, socketPath, keyConfigPath, timeoutMs, revocationKind, subjectId, reason, confirmation };
}

/** Executes a parsed command and verifies every mutation with a readback. */
export async function executeAuthorityControlCliCommand(
  command: AuthorityControlCliCommand,
  client: AuthorityControlCliClient
): Promise<AuthorityControlCliResult> {
  if (command.kind === "status") {
    if (command.switchName !== undefined) {
      return {
        schemaVersion: "0.1",
        operation: "status",
        switches: { [command.switchName]: await client.readSwitch(command.switchName) }
      };
    }
    if (command.revocationKind !== undefined && command.subjectId !== undefined) {
      return {
        schemaVersion: "0.1",
        operation: "status",
        switches: {},
        revocation: {
          kind: command.revocationKind,
          subjectId: command.subjectId,
          revoked: await client.readRevocation(command.revocationKind, command.subjectId)
        }
      };
    }
    const switches = {} as Record<SwitchName, boolean>;
    for (const name of AUTHORITY_CONTROL_SWITCH_NAMES) switches[name] = await client.readSwitch(name);
    return { schemaVersion: "0.1", operation: "status", switches };
  }
  if (command.kind === "set-switch") {
    await client.setSwitch(command.switchName, command.disabled, command.expectedDisabled, command.reason);
    const disabled = await client.readSwitch(command.switchName);
    if (disabled !== command.disabled) throw new BrokerError("AUTH_INVALID", "Authority switch readback does not match the requested state");
    return { schemaVersion: "0.1", operation: "set-switch", switchName: command.switchName, disabled, verified: true };
  }
  await client.revoke(command.revocationKind, command.subjectId, command.reason);
  const revoked = await client.readRevocation(command.revocationKind, command.subjectId);
  if (!revoked) throw new BrokerError("AUTH_INVALID", "Authority revocation readback did not confirm revocation");
  return {
    schemaVersion: "0.1",
    operation: "revoke",
    revocationKind: command.revocationKind,
    subjectId: command.subjectId,
    revoked: true,
    verified: true
  };
}

export async function runAuthorityControlCli(args: readonly string[]): Promise<AuthorityControlCliResult> {
  const command = parseAuthorityControlCliArgs(args);
  await assertProtectedDatabase(command.databasePath);
  const store = new BrokerStore(command.databasePath);
  const keyManager = new AuthorityControlKeyManager(command.keyConfigPath, store);
  let client: AuthorityControlIpcClient | undefined;
  try {
    await keyManager.restore();
    client = keyManager.createClient({ socketPath: command.socketPath, timeoutMs: command.timeoutMs });
    return await executeAuthorityControlCliCommand(command, client);
  } finally {
    client?.dispose();
    keyManager.dispose();
    store.close();
  }
}

function usageError(message: string): BrokerError {
  return new BrokerError("PRECONDITION_FAILED", message);
}

function requiredPath(values: ReadonlyMap<string, string>, option: string): string {
  const value = values.get(option);
  if (value === undefined || !isAbsolute(value) || resolve(value) !== value || value.includes("\0") || value.includes("\n")) {
    throw usageError(`${option} must be a canonical absolute path`);
  }
  return value;
}

function parseTimeout(value: string | undefined): number {
  if (value === undefined) return 15_000;
  if (!/^[0-9]{1,6}$/u.test(value)) throw usageError("--timeout-ms is malformed");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > MAX_TIMEOUT_MS) throw usageError("--timeout-ms is outside the supported range");
  return parsed;
}

function parseBoolean(value: string | undefined, option: string): boolean {
  if (value === "true") return true;
  if (value === "false") return false;
  throw usageError(`${option} must be true or false`);
}

function parseSwitch(value: string | undefined): SwitchName | undefined {
  if (value === undefined) return undefined;
  if (!(AUTHORITY_CONTROL_SWITCH_NAMES as readonly string[]).includes(value)) throw usageError("Switch name is unsupported");
  return value as SwitchName;
}

function parseRevocationKind(value: string | undefined): RevocationKind | undefined {
  if (value === undefined) return undefined;
  if (!(AUTHORITY_CONTROL_REVOCATION_KINDS as readonly string[]).includes(value)) throw usageError("Revocation kind is unsupported");
  return value as RevocationKind;
}

async function assertProtectedDatabase(path: string): Promise<void> {
  const stat = await lstat(path).catch(() => undefined);
  const uid = process.getuid?.();
  if (!stat || !stat.isFile() || stat.isSymbolicLink() || uid === undefined || stat.uid !== uid || (stat.mode & 0o077) !== 0) {
    throw new BrokerError("POLICY_DENIED", "Authority control database is not a protected owner-only file");
  }
  const parentPath = dirname(path);
  const parent = await lstat(parentPath).catch(() => undefined);
  if (!parent || !parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== uid || (parent.mode & 0o077) !== 0) {
    throw new BrokerError("POLICY_DENIED", "Authority control database directory is not protected");
  }
  const canonicalParent = await realpath(parentPath).catch(() => undefined);
  if (canonicalParent === undefined) throw new BrokerError("POLICY_DENIED", "Authority control database directory is not canonical");
  const canonicalStat = await lstat(canonicalParent);
  if (!canonicalStat.isDirectory() || canonicalStat.dev !== parent.dev || canonicalStat.ino !== parent.ino) {
    throw new BrokerError("POLICY_DENIED", "Authority control database directory changed while opening");
  }
}

function cliError(error: unknown): { schemaVersion: "0.1"; ok: false; errorClass: ErrorClass; message: string; retryable: boolean } {
  if (error instanceof BrokerError) {
    return { schemaVersion: "0.1", ok: false, errorClass: error.errorClass, message: error.message, retryable: error.retryable };
  }
  return { schemaVersion: "0.1", ok: false, errorClass: "PRECONDITION_FAILED", message: "Authority control operation failed", retryable: false };
}

export async function main(args = process.argv.slice(2)): Promise<void> {
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
    process.stdout.write(`${AUTHORITY_CONTROL_CLI_USAGE}\n`);
    return;
  }
  try {
    const result = await runAuthorityControlCli(args);
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
