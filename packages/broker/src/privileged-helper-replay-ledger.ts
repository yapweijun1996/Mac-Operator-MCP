import { constants } from "node:fs";
import {
  closeSync,
  fchmodSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  realpathSync
} from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { join, resolve } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import type { PrivilegedHelperReplayGuard, UnsignedPrivilegedHelperCommand } from "./privileged-helper.js";

const MAX_REPLAY_LEDGER_ROWS = 4096;
const DATABASE_MODE = 0o600;
const DIRECTORY_MODE = 0o700;

type ReplayAdmission = Pick<UnsignedPrivilegedHelperCommand, "requestId" | "nonce" | "timestampMs" | "nonceExpiresAtMs">;

/**
 * A root-helper-owned replay ledger. The database is separate from BrokerStore
 * and is reopened for each admission so no SQLite handle outlives its caller.
 */
export class PrivilegedHelperReplayLedger implements PrivilegedHelperReplayGuard {
  readonly durability = "durable" as const;
  readonly path: string;
  private readonly helperRoot: string;
  private readonly stateDirectory: string;
  private readonly ownerUid: number;

  constructor(helperRoot: string) {
    const uid = process.geteuid?.();
    if (uid === undefined || !Number.isSafeInteger(uid) || uid < 0) {
      throw new Error("Privileged helper replay ledger requires a POSIX effective user identity");
    }
    if (typeof helperRoot !== "string" || !helperRoot.startsWith("/") || resolve(helperRoot) !== helperRoot ||
        helperRoot === "/" || helperRoot === "/Users" || helperRoot.startsWith("/Users/")) {
      throw new Error("Privileged helper replay ledger root is invalid");
    }
    this.ownerUid = uid;
    this.helperRoot = helperRoot;
    this.path = privilegedHelperReplayLedgerPath(helperRoot);
    this.stateDirectory = join(helperRoot, "state");
    this.ensureProtectedDirectories(helperRoot);
    this.withDatabase((database) => {
      database.exec(`
        CREATE TABLE IF NOT EXISTS privileged_helper_nonces (
          nonce TEXT PRIMARY KEY,
          request_id TEXT NOT NULL UNIQUE,
          accepted_at_ms INTEGER NOT NULL,
          expires_at_ms INTEGER NOT NULL
        ) STRICT;
      `);
      this.verifyDatabase(database);
    });
  }

  admit(command: ReplayAdmission): void {
    validateReplayAdmission(command);
    try {
      this.withDatabase((database) => {
        this.verifyDatabase(database);
        database.exec("BEGIN IMMEDIATE;");
        try {
          database.prepare("DELETE FROM privileged_helper_nonces WHERE expires_at_ms <= ?").run(command.timestampMs);
          const row = database.prepare("SELECT COUNT(*) AS count FROM privileged_helper_nonces").get() as { count?: unknown } | undefined;
          if (!Number.isSafeInteger(row?.count) || (row?.count as number) < 0 || (row?.count as number) >= MAX_REPLAY_LEDGER_ROWS) {
            throw new BrokerError("AUDIT_UNAVAILABLE", "Privileged helper replay ledger is at capacity");
          }
          database.prepare(
            "INSERT INTO privileged_helper_nonces(nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)"
          ).run(command.nonce, command.requestId, command.timestampMs, command.nonceExpiresAtMs);
          database.exec("COMMIT;");
        } catch (error) {
          try { database.exec("ROLLBACK;"); } catch { /* The transaction may already have rolled back. */ }
          if (String(error).includes("UNIQUE constraint failed")) {
            throw new BrokerError("REPLAY_DENIED", "Privileged helper command nonce or request ID was already accepted");
          }
          if (error instanceof BrokerError) throw error;
          throw new BrokerError("AUDIT_UNAVAILABLE", "Privileged helper replay admission could not be persisted");
        }
      });
    } catch (error) {
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("AUDIT_UNAVAILABLE", "Privileged helper replay admission could not be persisted");
    }
  }

  private ensureProtectedDirectories(helperRoot: string): void {
    let root;
    try {
      root = lstatSync(helperRoot);
      if (!root.isDirectory() || root.isSymbolicLink() || root.uid !== this.ownerUid || (root.mode & 0o022) !== 0 ||
          realpathSync(helperRoot) !== helperRoot) {
        throw new Error("Privileged helper replay ledger root is not protected");
      }
      try {
        mkdirSync(this.stateDirectory, { mode: DIRECTORY_MODE });
        syncDirectory(helperRoot);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }
      const state = lstatSync(this.stateDirectory);
      if (!state.isDirectory() || state.isSymbolicLink() || state.uid !== this.ownerUid ||
          (state.mode & 0o777) !== DIRECTORY_MODE || realpathSync(this.stateDirectory) !== this.stateDirectory) {
        throw new Error("Privileged helper replay ledger state directory is not owner-only");
      }
    } catch (error) {
      throw new Error("Privileged helper replay ledger directories are unavailable or unprotected", { cause: error });
    }
  }

  private withDatabase<T>(operation: (database: DatabaseSync) => T): T {
    this.ensureProtectedDirectories(this.helperRoot);
    this.ensureProtectedDatabaseFile();
    const before = lstatSync(this.path);
    let database: DatabaseSync | undefined;
    try {
      database = new DatabaseSync(this.path);
      database.exec("PRAGMA busy_timeout = 5000; PRAGMA journal_mode = DELETE; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;");
      const after = lstatSync(this.path);
      if (!after.isFile() || after.isSymbolicLink() || after.uid !== this.ownerUid || after.nlink !== 1 ||
          (after.mode & 0o777) !== DATABASE_MODE || before.dev !== after.dev || before.ino !== after.ino) {
        throw new Error("Privileged helper replay ledger file changed while opening");
      }
      return operation(database);
    } finally {
      database?.close();
    }
  }

  private ensureProtectedDatabaseFile(): void {
    let existing;
    try { existing = lstatSync(this.path); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    if (existing === undefined) {
      const flags = constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW;
      const descriptor = openSync(this.path, flags, DATABASE_MODE);
      try {
        fchmodSync(descriptor, DATABASE_MODE);
        fsyncSync(descriptor);
      } finally {
        closeSync(descriptor);
      }
      syncDirectory(this.stateDirectory);
      existing = lstatSync(this.path);
    }
    if (!existing.isFile() || existing.isSymbolicLink() || existing.uid !== this.ownerUid || existing.nlink !== 1 ||
        (existing.mode & 0o777) !== DATABASE_MODE || realpathSync(this.path) !== this.path) {
      throw new Error("Privileged helper replay ledger file is not a protected owner-only regular file");
    }
  }

  private verifyDatabase(database: DatabaseSync): void {
    const integrity = database.prepare("PRAGMA quick_check(1)").get() as { quick_check?: unknown } | undefined;
    if (integrity?.quick_check !== "ok") throw new Error("Privileged helper replay ledger integrity check failed");
    const schema = database.prepare("PRAGMA table_info(privileged_helper_nonces)").all() as Array<Record<string, unknown>>;
    const expected = [
      ["nonce", "TEXT", 1],
      ["request_id", "TEXT", 0],
      ["accepted_at_ms", "INTEGER", 0],
      ["expires_at_ms", "INTEGER", 0]
    ] as const;
    if (schema.length !== expected.length || expected.some(([name, type, primaryKey], index) => {
      const column = schema[index];
      return column?.name !== name || column.type !== type || Number(column.pk) !== primaryKey;
    })) {
      throw new Error("Privileged helper replay ledger schema is invalid");
    }
    const requestUnique = database.prepare("PRAGMA index_list(privileged_helper_nonces)").all() as Array<Record<string, unknown>>;
    const hasUniqueRequestId = requestUnique.some((index) => {
      if (Number(index.unique) !== 1) return false;
      const name = index.name;
      if (typeof name !== "string" || !/^sqlite_autoindex_privileged_helper_nonces_[0-9]+$/u.test(name)) return false;
      const columns = database.prepare(`PRAGMA index_info(${name})`).all() as Array<Record<string, unknown>>;
      return columns.length === 1 && columns[0]?.name === "request_id";
    });
    if (!hasUniqueRequestId) throw new Error("Privileged helper replay ledger request uniqueness is missing");
  }
}

export function privilegedHelperReplayLedgerPath(helperRoot: string): string {
  return join(helperRoot, "state", "replay-ledger.sqlite");
}

function validateReplayAdmission(command: ReplayAdmission): void {
  if (!/^request:[A-Za-z0-9._:-]{1,240}$/u.test(command.requestId) ||
      !/^[A-Za-z0-9._:@/-]{16,128}$/u.test(command.nonce) ||
      !Number.isSafeInteger(command.timestampMs) || command.timestampMs < 0 ||
      !Number.isSafeInteger(command.nonceExpiresAtMs) || command.nonceExpiresAtMs <= command.timestampMs) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper replay admission is malformed");
  }
}

function syncDirectory(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY);
  try { fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
}
