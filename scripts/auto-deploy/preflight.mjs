// Startup preflight for the personal service: proves a built release can open a private copy of the live state
// before auto-deploy stops the running service. Only the Broker store is opened and nothing listens. No live file is
// modified; SQLite may create its -shm/-wal index files next to a database that is already in WAL mode.
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Mirrors openStore() in packages/auth/src/personal-service.ts, which runs the startup ledger and audit-anchor checks.
const PROBE = `
const { join } = await import("node:path");
const { readFileSync } = await import("node:fs");
const [packageRoot, data] = process.argv.slice(1);
const { BrokerStore } = await import(packageRoot + "/packages/broker/dist/index.js");
try {
  new BrokerStore(join(data, "broker.sqlite"), { runtimeFence: true,
    auditAnchor: { path: join(data, "audit.anchor"), keySource: { keyId: "personal-audit-1", loadKey: () => readFileSync(join(data, "audit.key")) } } }).close();
} catch (error) {
  console.log(String(error?.message ?? error).slice(0, 300));
  process.exit(1);
}
`;

/** Copies only what the store needs into a private scratch directory; the anchor goes first so it cannot be newer than the database. */
function copyState(stateRoot, scratch) {
  const live = join(stateRoot, "personal");
  const data = join(scratch, "personal");
  mkdirSync(data, { mode: 0o700 });
  // A store that has never appended an audit event has no anchor yet; the key is always required.
  for (const name of ["audit.anchor", "audit.key"]) {
    if (name === "audit.anchor" && !existsSync(join(live, name))) continue;
    copyFileSync(join(live, name), join(data, name));
    chmodSync(join(data, name), 0o600);
  }
  const source = new DatabaseSync(join(live, "broker.sqlite"), { readOnly: true });
  try { source.exec(`VACUUM INTO '${join(data, "broker.sqlite").replaceAll("'", "''")}'`); } finally { source.close(); }
  chmodSync(join(data, "broker.sqlite"), 0o600);
  return data;
}

function attempt({ packageRoot, stateRoot, nodePath }) {
  const scratch = realpathSync(mkdtempSync(join(tmpdir(), "mop-preflight-")));
  try {
    const data = copyState(stateRoot, scratch);
    const probe = spawnSync(nodePath, ["--input-type=module", "-e", PROBE, packageRoot, data],
      { encoding: "utf8", timeout: 120_000, env: { ...process.env, NODE_NO_WARNINGS: "1" } });
    if (probe.status === 0) return { ok: true };
    return { ok: false, why: (probe.stdout || probe.stderr || `probe exited ${probe.status}`).trim().slice(0, 300) };
  } catch (error) {
    return { ok: false, why: String(error?.message ?? error).slice(0, 300) };
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

/** One retry absorbs a write that lands between copying the anchor and the database from a running service. */
export function preflightState({ packageRoot, stateRoot, nodePath = process.execPath }) {
  const first = attempt({ packageRoot, stateRoot, nodePath });
  return first.ok ? first : attempt({ packageRoot, stateRoot, nodePath });
}
