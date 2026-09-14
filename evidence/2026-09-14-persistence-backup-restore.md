# Persistence Backup and Restore Evidence

> Superseded by `evidence/2026-09-14-encrypted-backup.md`. This record is
> retained as historical evidence for the pre-encryption implementation.

Status: Implemented, host-only, disabled as an MCP capability

## Scope

This slice adds protected recovery primitives around the Broker-owned SQLite
ledger. It does not expose backup, restore, or retention as an MCP tool and it
does not select external storage, encryption, or automatic scheduling.

## Boundary

- `BrokerStore.backupTo(directory, options)` calls SQLite's bounded backup API,
  writes a protected raw snapshot, streams it through the Broker-owned
  encryption envelope, applies owner-only `0600` mode, fsyncs the encrypted
  file and directory, then atomically publishes the generated
  `broker-backup-<timestamp>-<random>.sqlite.enc` name.
- Publication and final readback require SQLite `quick_check`, a recomputed
  SHA-256 audit-event chain, a bounded file size, owner identity, exact file
  mode, and a stable device/inode/size/mtime identity.
- `BrokerStore.restoreBackup(source, destination, keySource)` verifies and
  authenticates the encrypted source, decrypts it to a protected temporary
  file, checks the source identity again, fsyncs and atomically publishes only
  to a new destination. Existing targets, symlinks, malformed names, unsafe
  parents, key mismatches, and changed source identities are rejected.
- `BrokerStore.pruneBackups(directory, retainCount)` matches only the exact
  generated filename shape, orders by numeric timestamp, retains a bounded
  newest set, and refuses unsafe entries before deleting any file.

## Tests

`packages/broker/src/persistence.test.ts` covers:

1. owner-only backup mode, audit-tail manifest, restore into a fresh target,
   restart readback, and matching SHA-256;
2. numeric retention and symlink-entry rejection; and
3. audit-chain modification rejection during restore;
4. a child process killed after SQLite backup publication, followed by stale
   temporary-artifact and WAL/SHM sidecar cleanup; and
5. two independent Broker processes appending audit events concurrently while
   preserving the hash chain; and
6. a simulated `ENOSPC` publication failure mapping to retryable
   `AUDIT_UNAVAILABLE` without leaving temporary files; and
7. a deterministic insufficient-capacity preflight that fails before any
   temporary file is created.

The focused persistence suite passed 33/33 tests for the pre-encryption slice. Full-suite
counts and the exact local commit are recorded in `PROGRESS.md` and
`VERIFICATION.md` after the final verification run.

The final default suite reports 416 tests: 413 passed, 0 failed, and 3 opt-in
sandbox tests skipped. On the physical macOS host, `MOPS_REAL_SANDBOX=1 npm
test` reports 416 passed, 0 failed, and 0 skipped, including the real macOS
sandbox, process-group cancellation, service-lock, launchd read-only, and
authenticated Edge/Broker integration checks. This host run does not claim
kernel-level quota exhaustion or an installed production launchd service.

## Remaining acceptance work

This historical evidence does not prove live Keychain-protected backup storage,
disk quota/exhaustion behavior, crash injection across every filesystem
boundary, multi-process ownership, external audit anchoring, general schema
migration policy, corruption handling, or a production rollback/runbook decision.
See the superseding encrypted-backup evidence for current backup behavior.
