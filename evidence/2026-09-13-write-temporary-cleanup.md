# Write temporary cleanup evidence

Date: 2026-09-13  
Host: macOS arm64 development host  
Scope: local synthetic fixtures only; no production roots or user data

## Boundary exercised

Each newly admitted `mac_write_file_atomic` Job now records one generated,
same-directory temporary filename in its bounded non-secret descriptor. Legacy
descriptors without this field remain readable but are not eligible for
cleanup. The Broker exposes an explicit host-startup recovery hook that selects
only `UNKNOWN` write Jobs marked `BROKER_RESTART`; it never scans a directory or
deletes by filename prefix.

Cleanup derives exactly one temporary path from the recorded target parent and
name, revalidates the signed write root, rejects deny-zone and symlink escapes,
requires a regular non-symlink file, and deletes it only with the observed
device/inode identity through native descriptor-relative `unlinkat`, parent
`fsync`, and absence readback. Missing artifacts are an audited no-op. A
mutations/global kill switch skips cleanup. Intent and completion evidence are
redacted and hash-chained in the Broker audit ledger.

## Tests

- A synthetic orphan temporary file is removed, a second reconciliation is
  idempotent, and no directory-prefix scan occurs.
- A temporary symlink to an outside canary is rejected; the canary remains
  unchanged and the symlink remains present.
- The temporary filename survives Job Ledger close/reopen and appears in the
  restart-unknown candidate query without persisting requested content.
- A Broker restart candidate is removed only after the exact root identity and
  temporary filename are revalidated; cleanup emits `INTENT_RECORDED` followed
  by `TEMPORARY_REMOVED` audit events.

Observed verification on this revision: `npm test` passed with 245 tests;
`npm run typecheck` passed; `npm run verify:contracts` validated 44 contracts;
`git diff --check` passed.

## Limits and next gate

The hook is intentionally not an MCP tool and must run only after the host has
proved that the previous Broker instance no longer owns active workers. SQLite
lease/process ownership, concurrent multi-Broker exclusion, remount durability,
and exhaustive crash-point coverage remain release-gate work. Legacy Jobs with
no recorded temporary name remain untouched.
