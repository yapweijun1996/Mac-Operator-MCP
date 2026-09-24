import assert from "node:assert/strict";
import test from "node:test";
import { parseAuditArchiveCliArgs } from "./audit-archive-cli.js";

const CONFIG = "/Users/operator/Library/Application Support/MacOperator/broker-service.json";
const ARCHIVE = "/Users/operator/Library/Application Support/MacOperator/data/audit-exports/audit-export-1700000000000-aaaaaaaaaaaaaaaaaaaaaaaa.json.enc";

test("audit archive CLI requires explicit operation confirmation and fixed config", () => {
  assert.deepEqual(parseAuditArchiveCliArgs(["export", "--config", CONFIG, "--confirm", "export"]), {
    kind: "export",
    configPath: CONFIG,
    confirmation: "export"
  });
  assert.deepEqual(parseAuditArchiveCliArgs(["inspect", "--config", CONFIG, "--archive", ARCHIVE, "--confirm", "inspect"]), {
    kind: "inspect",
    configPath: CONFIG,
    archivePath: ARCHIVE,
    confirmation: "inspect"
  });
  assert.deepEqual(parseAuditArchiveCliArgs(["ledger-export", "--config", CONFIG, "--confirm", "ledger-export"]), {
    kind: "ledger-export",
    configPath: CONFIG,
    confirmation: "ledger-export"
  });
  const ledgerArchive = ARCHIVE.replace("audit-export", "ledger-export");
  assert.deepEqual(parseAuditArchiveCliArgs(["ledger-inspect", "--config", CONFIG, "--archive", ledgerArchive, "--confirm", "ledger-inspect"]), {
    kind: "ledger-inspect",
    configPath: CONFIG,
    archivePath: ledgerArchive,
    confirmation: "ledger-inspect"
  });
  assert.deepEqual(parseAuditArchiveCliArgs([
    "ledger-rotate",
    "--config", CONFIG,
    "--retain-requests", "10000",
    "--retain-jobs", "5000",
    "--min-age-ms", "86400000",
    "--confirm", "ledger-rotate"
  ]), {
    kind: "ledger-rotate",
    configPath: CONFIG,
    retainRequestCount: 10000,
    retainJobCount: 5000,
    minAgeMs: 86400000,
    confirmation: "ledger-rotate"
  });
  assert.deepEqual(parseAuditArchiveCliArgs([
    "archive-prune",
    "--config", CONFIG,
    "--retain-audit", "7",
    "--retain-ledger", "3",
    "--min-age-ms", "86400000",
    "--confirm", "archive-prune"
  ]), {
    kind: "archive-prune",
    configPath: CONFIG,
    retainAuditCount: 7,
    retainLedgerCount: 3,
    minAgeMs: 86400000,
    confirmation: "archive-prune"
  });
});

test("audit archive CLI rejects missing confirmation, unsupported fields, and non-canonical paths", () => {
  assert.throws(
    () => parseAuditArchiveCliArgs(["export", "--config", CONFIG]),
    /requires --confirm export/u
  );
  assert.throws(
    () => parseAuditArchiveCliArgs(["export", "--config", CONFIG, "--archive", ARCHIVE, "--confirm", "export"]),
    /unsupported field/u
  );
  assert.throws(
    () => parseAuditArchiveCliArgs(["inspect", "--config", CONFIG, "--archive", "/Users/operator/data/../audit.enc", "--confirm", "inspect"]),
    /canonical absolute path/u
  );
  assert.throws(
    () => parseAuditArchiveCliArgs(["ledger-rotate", "--config", CONFIG, "--retain-requests", "0", "--retain-jobs", "0", "--confirm", "ledger-rotate"]),
    /--min-age-ms must be a non-negative integer/u
  );
  assert.throws(
    () => parseAuditArchiveCliArgs([
      "ledger-rotate", "--config", CONFIG, "--retain-requests", "-1", "--retain-jobs", "0", "--min-age-ms", "0", "--confirm", "ledger-rotate"
    ]),
    /--retain-requests must be a non-negative integer/u
  );
  assert.throws(
    () => parseAuditArchiveCliArgs([
      "archive-prune", "--config", CONFIG, "--retain-audit", "0", "--retain-ledger", "0", "--min-age-ms", "-1", "--confirm", "archive-prune"
    ]),
    /--min-age-ms must be a non-negative integer/u
  );
});
