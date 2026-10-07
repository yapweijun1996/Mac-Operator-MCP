import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { BrokerStore } from "../packages/broker/dist/index.js";
import { preflightState } from "./auto-deploy/preflight.mjs";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

const scratchDirs = () => readdirSync(tmpdir()).filter(name => name.startsWith("mop-preflight-")).length;

test("preflight accepts a state the new build can open and leaves the live files untouched", () => {
  const stateRoot = realpathSync(mkdtempSync(join(tmpdir(), "mop-preflight-test-")));
  const data = join(stateRoot, "personal");
  mkdirSync(data, { mode: 0o700 });
  const key = randomBytes(32);
  writeFileSync(join(data, "audit.key"), key, { mode: 0o600 });
  new BrokerStore(join(data, "broker.sqlite"), { runtimeFence: true,
    auditAnchor: { path: join(data, "audit.anchor"), keySource: { keyId: "personal-audit-1", loadKey: () => key } } }).close();
  const files = () => readdirSync(data).filter(name => !name.endsWith("-shm") && !name.endsWith("-wal")).sort();
  const before = files();
  try {
    const outcome = preflightState({ packageRoot, stateRoot });
    assert.deepEqual(outcome, { ok: true });
    assert.deepEqual(files(), before);
  } finally { rmSync(stateRoot, { recursive: true, force: true }); }
});

test("preflight rejects an unreadable database and removes its scratch copy of the audit key", () => {
  const stateRoot = realpathSync(mkdtempSync(join(tmpdir(), "mop-preflight-test-")));
  const data = join(stateRoot, "personal");
  mkdirSync(data, { mode: 0o700 });
  writeFileSync(join(data, "audit.key"), randomBytes(32), { mode: 0o600 });
  writeFileSync(join(data, "audit.anchor"), "{}", { mode: 0o600 });
  writeFileSync(join(data, "broker.sqlite"), "not a database", { mode: 0o600 });
  const scratchBefore = scratchDirs();
  try {
    const outcome = preflightState({ packageRoot, stateRoot });
    assert.equal(outcome.ok, false);
    assert.equal(typeof outcome.why, "string");
    assert.equal(scratchDirs(), scratchBefore);
  } finally { rmSync(stateRoot, { recursive: true, force: true }); }
});

test("preflight rejects a state that is missing required files", () => {
  const stateRoot = realpathSync(mkdtempSync(join(tmpdir(), "mop-preflight-test-")));
  mkdirSync(join(stateRoot, "personal"), { mode: 0o700 });
  try { assert.equal(preflightState({ packageRoot, stateRoot }).ok, false); }
  finally { rmSync(stateRoot, { recursive: true, force: true }); }
});
