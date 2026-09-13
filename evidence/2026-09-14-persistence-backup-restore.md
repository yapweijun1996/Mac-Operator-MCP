# Persistence Backup and Restore Evidence

Status: Implemented, host-only, disabled as an MCP capability

## Scope

This slice adds protected recovery primitives around the Broker-owned SQLite
ledger. It does not expose backup, restore, or retention as an MCP tool and it
does not select external storage, encryption, or automatic scheduling.

## Boundary

- `BrokerStore.backupTo(directory, options)` calls SQLite's bounded backup API,
  writes a same-directory temporary file, applies owner-only `0600` mode,
  fsyncs the file and directory, then atomically publishes the generated
  `broker-backup-<timestamp>-<random>.sqlite` name.
- Publication and final readback require SQLite `quick_check`, a recomputed
  SHA-256 audit-event chain, a bounded file size, owner identity, exact file
  mode, and a stable device/inode/size/mtime identity.
- `BrokerStore.restoreBackup(source, destination)` verifies the source again,
  copies it to a protected temporary file, checks the source identity again,
  fsyncs and atomically publishes only to a new destination. Existing targets,
  symlinks, malformed names, unsafe parents, and changed source identities are
  rejected.
- `BrokerStore.pruneBackups(directory, retainCount)` matches only the exact
  generated filename shape, orders by numeric timestamp, retains a bounded
  newest set, and refuses unsafe entries before deleting any file.

## Tests

`packages/broker/src/persistence.test.ts` covers:

1. owner-only backup mode, audit-tail manifest, restore into a fresh target,
   restart readback, and matching SHA-256;
2. numeric retention and symlink-entry rejection; and
3. audit-chain modification rejection during restore.

The focused persistence suite passes 29/29 tests after this slice. Full-suite
counts and the exact local commit are recorded in `PROGRESS.md` and
`VERIFICATION.md` after the final verification run.

## Remaining acceptance work

This evidence does not prove encrypted or Keychain-protected backup storage,
disk quota/exhaustion behavior, crash injection across every filesystem
boundary, multi-process ownership, external audit anchoring, general schema
migration policy, or a production rollback/runbook decision. ADR-0005 remains
`Proposed`, and the primitives remain host-only and disabled by default.
