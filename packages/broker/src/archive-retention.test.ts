import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { pruneArchiveArtifacts } from "./archive-retention.js";

function archivePath(directory: string, kind: "audit" | "ledger", createdAtMs: number, suffix: string): string {
  return join(directory, `${kind}-export-${createdAtMs}-${suffix}.json.enc`);
}

async function createArchiveFixture(path: string): Promise<void> {
  const kind = path.includes("/audit-export-") ? "audit" : "ledger";
  const magic = Buffer.from(kind === "audit" ? "MOPSAUD1" : "MOPSLDG1", "ascii");
  const keyId = Buffer.from("key-1", "ascii");
  const prefix = Buffer.alloc(11);
  magic.copy(prefix, 0);
  prefix.writeUInt8(1, 8);
  prefix.writeUInt16BE(keyId.byteLength, 9);
  await writeFile(path, Buffer.concat([prefix, keyId, Buffer.alloc(12), Buffer.from("ciphertext"), Buffer.alloc(16)]), { mode: 0o600 });
}

test("archive pruning retains recent artifacts and the newest bounded set per archive kind", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-broker-archive-retention-"));
  const suffix = "a".repeat(24);
  const auditOldest = archivePath(directory, "audit", 1_000, suffix);
  const auditOlder = archivePath(directory, "audit", 2_000, "b".repeat(24));
  const auditNewestEligible = archivePath(directory, "audit", 3_000, "c".repeat(24));
  const auditRecent = archivePath(directory, "audit", 9_500, "d".repeat(24));
  const ledgerOldest = archivePath(directory, "ledger", 1_000, "e".repeat(24));
  const ledgerNewest = archivePath(directory, "ledger", 2_000, "f".repeat(24));
  try {
    for (const path of [auditOldest, auditOlder, auditNewestEligible, auditRecent, ledgerOldest, ledgerNewest]) {
      await createArchiveFixture(path);
    }
    const result = await pruneArchiveArtifacts(directory, {
      retainAuditCount: 1,
      retainLedgerCount: 0,
      minAgeMs: 1_000,
      nowMs: 10_000
    });
    assert.deepEqual(result.removedAudit, [auditOldest, auditOlder]);
    assert.deepEqual(result.removedLedger, [ledgerOldest, ledgerNewest]);
    assert.deepEqual(result.retainedAudit, [auditRecent, auditNewestEligible]);
    assert.deepEqual(result.retainedLedger, []);
    assert.ok((await readFile(auditRecent)).byteLength > 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("archive pruning fails closed on symlink candidates and unfinished artifacts", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-broker-archive-retention-unsafe-"));
  const suffix = "1".repeat(24);
  const target = join(directory, "target.bin");
  const symlinked = archivePath(directory, "audit", 1_000, suffix);
  const temporary = join(directory, `.ledger-export-1000-${"a".repeat(24)}.json.enc.tmp-${"b".repeat(24)}`);
  const ledger = archivePath(directory, "ledger", 1_000, "2".repeat(24));
  try {
    await writeFile(target, "must-survive", { mode: 0o600 });
    await symlink(target, symlinked);
    await assert.rejects(
      pruneArchiveArtifacts(directory, { retainAuditCount: 0, retainLedgerCount: 0, minAgeMs: 0, nowMs: 2_000 }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    assert.equal(await readFile(target, "utf8"), "must-survive");

    await rm(symlinked);
    await createArchiveFixture(ledger);
    await writeFile(temporary, "unfinished", { mode: 0o600 });
    await assert.rejects(
      pruneArchiveArtifacts(directory, { retainAuditCount: 0, retainLedgerCount: 0, minAgeMs: 0, nowMs: 2_000 }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    assert.ok((await readFile(ledger)).byteLength > 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("archive pruning rejects malformed retention options", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-broker-archive-retention-options-"));
  try {
    await assert.rejects(
      pruneArchiveArtifacts(directory, { retainAuditCount: -1, retainLedgerCount: 0, minAgeMs: 0, nowMs: 1_000 }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
