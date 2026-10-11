import assert from "node:assert/strict";
import fs from "node:fs";
import { mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
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

for (const kind of ["audit", "ledger"] as const) {
  for (const prefix of ["", "."]) {
    test(`archive pruning rejects ${prefix ? "legacy" : "current"} ${kind} quarantine artifacts before deleting archives`, async () => {
      const directory = await mkdtemp(join(tmpdir(), "mac-broker-archive-quarantine-"));
      const archive = archivePath(directory, kind, 1_000, "a".repeat(24));
      const quarantine = join(directory, `${prefix}${kind}-export-500-${"b".repeat(24)}.json.enc.prune-1000-${"c".repeat(24)}`);
      try {
        await createArchiveFixture(archive);
        const original = await readFile(archive);
        await writeFile(quarantine, "unfinished", { mode: 0o600 });
        await assert.rejects(
          pruneArchiveArtifacts(directory, { retainAuditCount: 0, retainLedgerCount: 0, minAgeMs: 0, nowMs: 2_000 }),
          (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE" && /unfinished/u.test(error.message)
        );
        assert.deepEqual(await readFile(archive), original);
        assert.equal(await readFile(quarantine, "utf8"), "unfinished");
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    });
  }
}

test("archive pruning fails closed on retry after deletion and restoration both fail", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "mac-broker-archive-quarantine-fault-"));
  const archive = archivePath(directory, "audit", 1_000, "a".repeat(24));
  const originalUnlink = fs.promises.unlink;
  const originalLink = fs.promises.link;
  try {
    await createArchiveFixture(archive);
    const original = await readFile(archive);
    t.mock.method(fs.promises, "unlink", async (path: Parameters<typeof originalUnlink>[0]) => {
      if (String(path).includes(".prune-")) throw Object.assign(new Error("synthetic deletion failure"), { code: "EIO" });
      return originalUnlink(path);
    });
    t.mock.method(fs.promises, "link", async (from: Parameters<typeof originalLink>[0], to: Parameters<typeof originalLink>[1]) => {
      if (String(from).includes(".prune-")) throw Object.assign(new Error("synthetic restoration failure"), { code: "EIO" });
      return originalLink(from, to);
    });
    syncBuiltinESMExports();
    const options = { retainAuditCount: 0, retainLedgerCount: 0, minAgeMs: 0, nowMs: 2_000 };
    await assert.rejects(
      pruneArchiveArtifacts(directory, options),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    t.mock.restoreAll();
    syncBuiltinESMExports();
    const remnants = await readdir(directory);
    assert.equal(remnants.length, 1);
    assert.match(remnants[0]!, /^audit-export-1000-[a-f0-9]{24}\.json\.enc\.prune-\d+-[a-f0-9]{24}$/u);
    const quarantine = join(directory, remnants[0]!);
    assert.deepEqual(await readFile(quarantine), original);
    await assert.rejects(readFile(archive), (error: unknown) => (error as NodeJS.ErrnoException).code === "ENOENT");
    await assert.rejects(
      pruneArchiveArtifacts(directory, options),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE" && /unfinished/u.test(error.message)
    );
    assert.deepEqual(await readFile(quarantine), original);
  } finally {
    t.mock.restoreAll();
    syncBuiltinESMExports();
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
