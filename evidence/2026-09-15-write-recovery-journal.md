# Write Cleanup Job-Recovery Evidence

- Source revision: `def8e82`
- Date: 2026-09-15
- Scope: Durable Job metadata and Broker restart reconciliation for atomic-write temporary artifacts

## Implementation

The write Job ledger now accepts an optional recovery record containing the
temporary basename, device, inode, and Broker timestamp. During restart
reconciliation, the Broker inspects a regular non-symlink temporary artifact
and persists its device/inode in one guarded Job revision update before the
native unlink boundary is entered. The update is owned by the Job principal,
requires the restart-unknown state and cancellation marker, and is idempotent
only for the same identity pair.

If the native unlink has already renamed the file into its private quarantine,
the next reconciliation derives the temporary path from the persisted Job
path and basename, then invokes the existing explicit native recovery boundary.
Only a unique stale quarantine whose device/inode exactly match the journal is
removed. Recent, ambiguous, replacement, or unproven artifacts remain
untouched; an absent quarantine does not authorize deleting a replacement
temporary path. Completion evidence records `TEMPORARY_REMOVED`,
`TEMPORARY_RECOVERED`, `TEMPORARY_ABSENT`, or the stable skipped result.

## Verification

- `npm run build`: passed, including the Darwin native adapter.
- `npm run lint`: passed across 664 tracked files.
- `node --test packages/broker/dist/write-recovery-journal.test.js`: passed 2/2.
- `node --test packages/broker/dist/filesystem-inspector.test.js packages/broker/dist/write-recovery-journal.test.js`: passed 38/38.
- The two physical Darwin integration tests cover journaling before unlink and
  stale quarantine recovery after a simulated Broker restart.
- Existing long-running Broker, persistence, and privileged-helper suites
  were not interrupted or rerun.

Production crash/remount injection, installed-service lifecycle evidence, and
cross-process audit-anchor readback remain release gates.
