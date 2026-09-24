import { randomBytes } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { chmod, lstat, open, rename, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { canonicalJson, parseJsonUtf8Strict } from "@mac-operator/contracts";

const JOURNAL_MECHANISM = "macos-launchagent-deployment-journal-v1" as const;
const JOURNAL_SCHEMA_VERSION = "0.1" as const;
const JOURNAL_FILE_NAME = ".macos-launchagent-deployment.journal.json";
const MAX_JOURNAL_BYTES = 64 * 1024;
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const COMPONENTS = ["authority", "edge", "broker"] as const;

export type MacOsDeploymentJournalComponent = (typeof COMPONENTS)[number];
export type MacOsDeploymentOperation = "install" | "upgrade" | "rollback" | "uninstall";
export type MacOsDeploymentJournalPhase = "in-progress" | "applied" | "recovered" | "recovery-required";

export interface MacOsDeploymentJournalRecord {
  schemaVersion: typeof JOURNAL_SCHEMA_VERSION;
  mechanism: typeof JOURNAL_MECHANISM;
  transactionId: string;
  operation: MacOsDeploymentOperation;
  order: readonly MacOsDeploymentJournalComponent[];
  completedComponents: readonly MacOsDeploymentJournalComponent[];
  phase: MacOsDeploymentJournalPhase;
  sourceDigest: string;
  updatedAtMs: number;
  failedComponent: MacOsDeploymentJournalComponent | null;
}

/**
 * Writes a small owner-only deployment state record. It is deliberately not
 * an audit log: the record contains only bounded transaction identity and
 * component state, never secrets, command output, or service payloads.
 */
export async function writeMacOsDeploymentJournal(
  path: string,
  record: MacOsDeploymentJournalRecord
): Promise<void> {
  validateJournalPath(path);
  validateJournalRecord(record);
  const directory = await validateJournalDirectory(path);
  const bytes = Buffer.from(`${canonicalJson(record)}\n`, "utf8");
  if (bytes.byteLength > MAX_JOURNAL_BYTES) throw new Error("macOS deployment journal exceeds its byte budget");
  const temporary = `${dirname(path)}/${basename(path)}.tmp-${randomBytes(12).toString("hex")}`;
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    await writeAll(handle, bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await chmod(temporary, 0o600);
    await rename(temporary, path);
    await syncDirectory(directory);
    const readback = await readMacOsDeploymentJournal(path);
    if (readback === null || canonicalJson(readback) !== canonicalJson(record)) {
      throw new Error("macOS deployment journal publication readback failed");
    }
  } catch (error) {
    if (handle !== undefined) await handle.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

/** Reads and validates the current journal through an identity-stable descriptor. */
export async function readMacOsDeploymentJournal(
  path: string
): Promise<MacOsDeploymentJournalRecord | null> {
  validateJournalPath(path);
  await validateJournalDirectory(path);
  const initial = await lstat(path).catch((error: unknown) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  });
  if (initial === undefined) return null;
  validateJournalFile(initial);
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat({ bigint: false });
    if (!sameIdentity(initial, opened)) throw new Error("macOS deployment journal changed while opening");
    if (opened.size > MAX_JOURNAL_BYTES) throw new Error("macOS deployment journal exceeds its byte budget");
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: false });
    if (!sameIdentity(opened, after) || bytes.byteLength !== after.size) {
      throw new Error("macOS deployment journal changed while reading");
    }
    let value: unknown;
    try {
      value = parseJsonUtf8Strict(bytes);
    } finally {
      bytes.fill(0);
    }
    validateJournalRecord(value);
    return value;
  } finally {
    await handle.close();
  }
}

export function macOsDeploymentJournalPath(installRoot: string): string {
  if (typeof installRoot !== "string" || !isAbsolute(installRoot) || resolve(installRoot) !== installRoot || installRoot.endsWith("/")) {
    throw new Error("macOS deployment install root is not canonical");
  }
  return `${installRoot}/${JOURNAL_FILE_NAME}`;
}

function validateJournalPath(path: string): void {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path || path.includes("\0") ||
      basename(path) !== JOURNAL_FILE_NAME || path.endsWith("/")) {
    throw new Error("macOS deployment journal path is malformed");
  }
}

async function validateJournalDirectory(path: string): Promise<string> {
  const directory = dirname(path);
  await validateDirectoryChain(directory);
  const stat = await lstat(directory);
  const uid = process.getuid?.();
  if (!stat.isDirectory() || stat.isSymbolicLink() || uid === undefined || stat.uid !== uid || (stat.mode & 0o077) !== 0) {
    throw new Error("macOS deployment journal directory must be a canonical owner-only directory");
  }
  return directory;
}

async function validateDirectoryChain(directory: string): Promise<void> {
  const segments = resolve(directory).split("/").filter(Boolean);
  let current = "/";
  for (const segment of segments) {
    current = join(current, segment);
    const stat = await lstat(current);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0) {
      throw new Error("macOS deployment journal path crosses an unsafe directory chain");
    }
  }
}

function validateJournalFile(stat: Stats): void {
  const uid = process.getuid?.();
  if (!stat.isFile() || stat.isSymbolicLink() || uid === undefined || stat.uid !== uid || (stat.mode & 0o7777) !== 0o600 ||
      !Number.isSafeInteger(stat.size) || stat.size < 1 || stat.size > MAX_JOURNAL_BYTES) {
    throw new Error("macOS deployment journal must be an owner-only bounded regular file");
  }
}

function validateJournalRecord(value: unknown): asserts value is MacOsDeploymentJournalRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error("macOS deployment journal is not a plain object");
  }
  const record = value as Record<string, unknown>;
  const updatedAtMs = record.updatedAtMs;
  const expected = [
    "completedComponents", "failedComponent", "mechanism", "operation", "order", "phase",
    "schemaVersion", "sourceDigest", "transactionId", "updatedAtMs"
  ];
  const keys = Object.keys(record).sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new Error("macOS deployment journal contains unsupported or missing fields");
  }
  if (record.schemaVersion !== JOURNAL_SCHEMA_VERSION || record.mechanism !== JOURNAL_MECHANISM ||
      typeof record.transactionId !== "string" || !ID_PATTERN.test(record.transactionId) ||
      !isOperation(record.operation) || !isPhase(record.phase) || typeof record.sourceDigest !== "string" ||
      !HASH_PATTERN.test(record.sourceDigest) || typeof updatedAtMs !== "number" || !Number.isSafeInteger(updatedAtMs) || updatedAtMs < 0 ||
      updatedAtMs > 9_999_999_999_999_999 || !Array.isArray(record.order) || !Array.isArray(record.completedComponents)) {
    throw new Error("macOS deployment journal fields are malformed");
  }
  const order = record.order as unknown[];
  const completed = record.completedComponents as unknown[];
  if (!validOrder(order) || completed.some((component) => !isComponent(component)) ||
      completed.some((component, index) => component !== order[index])) {
    throw new Error("macOS deployment journal component order is malformed");
  }
  if (record.failedComponent !== null && !isComponent(record.failedComponent)) {
    throw new Error("macOS deployment journal failed component is malformed");
  }
  if (record.phase === "applied" && completed.length !== order.length) {
    throw new Error("applied deployment journal must contain all completed components");
  }
  if (record.phase === "recovery-required" && record.failedComponent === null) {
    throw new Error("recovery-required deployment journal must identify the failed component");
  }
}

function validOrder(value: readonly unknown[]): value is readonly MacOsDeploymentJournalComponent[] {
  const text = value.join(",");
  return text === "edge,broker" || text === "broker,edge" || text === "authority,edge,broker" || text === "broker,edge,authority";
}

function isComponent(value: unknown): value is MacOsDeploymentJournalComponent {
  return typeof value === "string" && (COMPONENTS as readonly string[]).includes(value);
}

function isOperation(value: unknown): value is MacOsDeploymentOperation {
  return value === "install" || value === "upgrade" || value === "rollback" || value === "uninstall";
}

function isPhase(value: unknown): value is MacOsDeploymentJournalPhase {
  return value === "in-progress" || value === "applied" || value === "recovered" || value === "recovery-required";
}

async function writeAll(handle: Awaited<ReturnType<typeof open>>, bytes: Buffer): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const result = await handle.write(bytes, offset, bytes.byteLength - offset);
    if (result.bytesWritten < 1) throw new Error("macOS deployment journal write made no progress");
    offset += result.bytesWritten;
  }
}

async function syncDirectory(directory: string): Promise<void> {
  const handle = await open(directory, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function sameIdentity(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid && left.gid === right.gid &&
    (left.mode & 0o7777) === (right.mode & 0o7777) && left.size === right.size &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}
