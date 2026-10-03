import { DatabaseSync } from "node:sqlite";
import { closeSync, constants, lstatSync, openSync, realpathSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { recordSchemas, type Kind, type RecordValue } from "./contracts.js";

export interface GrantRevocationNotice {
  grantId: string;
  principalId: string;
  scopes: readonly string[];
  expiresAtMs: number;
}

export type GrantRevocationListener = (notice: GrantRevocationNotice) => void | Promise<void>;

export function assertPrivateDirectory(directory: string): void {
  const stat = lstatSync(directory);
  if (!isAbsolute(directory) || realpathSync(directory) !== directory || !stat.isDirectory() ||
      stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0) throw new Error("Protected auth directory required");
}

export function assertPrivateFile(path: string): void {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== process.getuid?.() ||
      (stat.mode & 0o077) !== 0 || realpathSync(path) !== path) throw new Error("Protected auth file required");
}

/** Value-free reason for a rejected stored record; never includes payload content or record ids. */
class AuthRecordError extends Error {
  constructor(kind: string, cause: unknown) {
    const issues = (cause as { issues?: Array<{ path?: unknown[]; code?: unknown }> } | null)?.issues;
    const reason = Array.isArray(issues)
      ? issues.slice(0, 5).map(issue => `${(issue.path ?? []).join(".").replace(/[^A-Za-z0-9_.]/gu, "?") || "record"}:${String(issue.code).replace(/[^A-Za-z0-9_]/gu, "?")}`).join(",")
      : cause instanceof SyntaxError ? "unparseable_json" : "unreadable";
    super(`Auth state unavailable: record kind=${kind} invalid (${reason})`);
  }
}

/** Single-owner durable auth state; never silently replace an invalid database. */
export class AuthStore {
  private readonly db: DatabaseSync;
  private sealed = false;
  private transactionActive = false;
  private readonly pendingRevocations = new Map<string, GrantRevocationNotice>();
  private grantRevocationListener: GrantRevocationListener | undefined;

  constructor(directory: string, initialize = false) {
    assertPrivateDirectory(directory);
    const path = join(directory, "auth.sqlite");
    if (initialize) closeSync(openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600));
    assertPrivateFile(path);
    for (const suffix of ["-journal", "-wal", "-shm"]) {
      try { assertPrivateFile(path + suffix); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    }
    this.db = new DatabaseSync(path);
    try {
      this.db.exec("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=3000; PRAGMA trusted_schema=OFF;");
      if (initialize) this.db.exec("CREATE TABLE records (kind TEXT NOT NULL, id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(kind,id)) STRICT; PRAGMA user_version=1;");
      if (this.db.prepare("PRAGMA user_version").get()?.user_version !== 1) throw new Error("Unsupported auth schema");
      if (this.db.prepare("PRAGMA quick_check").get()?.quick_check !== "ok") throw new Error("Invalid auth state");
      const rows = this.db.prepare("SELECT kind, id, payload FROM records LIMIT 8001").all();
      if (rows.length > 8000) throw new Error("Auth capacity exceeded");
      for (const row of rows) {
        if (typeof row.kind !== "string" || !Object.hasOwn(recordSchemas, row.kind) || typeof row.id !== "string" ||
            !/^[A-Za-z0-9._:-]{1,128}$/u.test(row.id) || typeof row.payload !== "string" || row.payload.length > 8192) throw new Error("Invalid auth state");
        try { recordSchemas[row.kind as Kind].parse(JSON.parse(row.payload)); }
        catch (error) { throw new AuthRecordError(row.kind, error); }
      }
    } catch (error) {
      this.db.close();
      throw error instanceof AuthRecordError ? error : new Error("Auth state unavailable");
    }
  }

  get<K extends Kind>(kind: K, key: string): RecordValue<K> | undefined {
    this.assertAvailable();
    let row: { payload?: unknown } | undefined;
    try { row = this.db.prepare("SELECT payload FROM records WHERE kind=? AND id=?").get(kind, key); }
    catch { this.sealed = true; throw new Error("Auth state unavailable"); }
    if (row === undefined) return undefined;
    try { return recordSchemas[kind].parse(JSON.parse(String(row.payload))) as RecordValue<K>; }
    catch (error) { this.sealed = true; throw new AuthRecordError(kind, error); }
  }

  browserGrants(): RecordValue<"browser_grant">[] {
    this.assertAvailable();
    try {
      return this.db.prepare("SELECT id, payload FROM records WHERE kind='browser_grant'").all().map(row => {
        const grant = recordSchemas.browser_grant.parse(JSON.parse(String(row.payload)));
        if (grant.id !== row.id) throw new Error("Browser grant identity mismatch");
        return grant;
      });
    } catch { this.sealed = true; throw new Error("Auth state unavailable"); }
  }

  desktopGrants(): RecordValue<"desktop_grant">[] {
    this.assertAvailable();
    try {
      return this.db.prepare("SELECT id, payload FROM records WHERE kind='desktop_grant'").all().map(row => {
        const grant = recordSchemas.desktop_grant.parse(JSON.parse(String(row.payload)));
        if (grant.id !== row.id) throw new Error("Desktop grant identity mismatch");
        return grant;
      });
    } catch { this.sealed = true; throw new Error("Auth state unavailable"); }
  }

  put<K extends Kind>(kind: K, key: string, value: RecordValue<K>): void {
    this.assertAvailable();
    const payload = JSON.stringify(recordSchemas[kind].parse(value));
    if (!/^[A-Za-z0-9._:-]{1,128}$/u.test(key) || payload.length > 8192) throw new Error("Invalid auth record");
    if (!this.get(kind, key) && Number(this.db.prepare("SELECT count(*) AS n FROM records WHERE kind=?").get(kind)?.n) >= 1000) {
      throw new Error("Auth capacity exceeded");
    }
    this.write(() => this.db.prepare("INSERT INTO records VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET payload=excluded.payload").run(kind, key, payload));
  }

  delete(kind: Kind, key: string): boolean {
    this.assertAvailable();
    return this.write(() => this.db.prepare("DELETE FROM records WHERE kind=? AND id=?").run(kind, key).changes === 1);
  }

  transaction<T>(operation: () => T): T {
    this.assertAvailable();
    if (this.transactionActive) return operation();
    this.write(() => this.db.exec("BEGIN IMMEDIATE"));
    this.transactionActive = true;
    try {
      const result = operation();
      this.write(() => this.db.exec("COMMIT"));
      this.transactionActive = false;
      const notices = [...this.pendingRevocations.values()];
      this.pendingRevocations.clear();
      for (const notice of notices) this.dispatchRevocation(notice);
      return result;
    } catch (error) {
      this.transactionActive = false;
      this.pendingRevocations.clear();
      try { this.db.exec("ROLLBACK"); } catch { this.sealed = true; }
      throw error;
    }
  }

  /**
   * Free registration slots by deleting the oldest clients that no grant references.
   * Anonymous registration cannot expire, so this keeps it from exhausting capacity.
   */
  evictUnusedClients(count: number): number {
    this.assertAvailable();
    return this.write(() => Number(this.db.prepare(
      "DELETE FROM records WHERE kind='client' AND id IN (SELECT c.id FROM records c WHERE c.kind='client' AND NOT EXISTS " +
      "(SELECT 1 FROM records g WHERE g.kind='grant' AND json_extract(g.payload,'$.clientId') = c.id) ORDER BY c.rowid LIMIT ?)"
    ).run(count).changes));
  }

  prune(): void {
    this.assertAvailable();
    this.write(() => this.db.prepare("DELETE FROM records WHERE kind != 'account' AND json_extract(payload,'$.expiresAt') <= ?").run(Date.now()));
  }

  revoke(grantId: string, clientId?: string): void {
    const grant = this.get("grant", grantId);
    if (grant && !grant.revoked && (clientId === undefined || grant.clientId === clientId)) {
      this.put("grant", grantId, { ...grant, revoked: true });
      this.queueRevocation({ grantId, principalId: grant.principalId, scopes: [...grant.scopes], expiresAtMs: grant.expiresAt });
    }
  }

  revokeAll(): void {
    this.assertAvailable();
    const grants = this.db.prepare("SELECT id, payload FROM records WHERE kind='grant'").all() as Array<{ id?: unknown; payload?: unknown }>;
    const notices = grants.flatMap(row => {
      if (typeof row.id !== "string" || typeof row.payload !== "string") return [];
      const grant = recordSchemas.grant.parse(JSON.parse(row.payload));
      return grant.revoked ? [] : [{ grantId: row.id, principalId: grant.principalId, scopes: [...grant.scopes], expiresAtMs: grant.expiresAt }];
    });
    this.write(() => this.db.exec("UPDATE records SET payload=json_set(payload,'$.revoked',json('true')) WHERE kind IN ('grant','browser_grant','desktop_grant'); DELETE FROM records WHERE kind IN ('session','approval_session','transaction','code');"));
    for (const notice of notices) this.queueRevocation(notice);
  }

  setGrantRevocationListener(listener: GrantRevocationListener | undefined): void {
    this.grantRevocationListener = listener;
  }

  close(): void {
    this.pendingRevocations.clear();
    this.grantRevocationListener = undefined;
    this.db.close();
  }
  private assertAvailable(): void { if (this.sealed) throw new Error("Auth state unavailable"); }
  private queueRevocation(notice: GrantRevocationNotice): void {
    if (this.transactionActive) this.pendingRevocations.set(notice.grantId, notice);
    else this.dispatchRevocation(notice);
  }
  private dispatchRevocation(notice: GrantRevocationNotice): void {
    const listener = this.grantRevocationListener;
    if (listener === undefined) return;
    queueMicrotask(() => {
      if (this.grantRevocationListener !== listener) return;
      void Promise.resolve().then(() => listener(notice)).catch(() => undefined);
    });
  }
  private write<T>(operation: () => T): T {
    this.assertAvailable();
    try { return operation(); } catch { this.sealed = true; throw new Error("Auth state unavailable"); }
  }
}
