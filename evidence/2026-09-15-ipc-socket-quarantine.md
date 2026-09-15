# IPC Socket Quarantine Evidence

- Source revision: `6e246bf`
- Date: 2026-09-15
- Scope: Broker Unix-socket stale and close cleanup

## Decision

Broker socket cleanup no longer unlinks the public pathname immediately after
an identity check. It atomically renames the exact checked socket into a
private same-directory quarantine name, rechecks device/inode identity, and
only then unlinks the quarantine. If a replacement appears before the rename,
the identity mismatch fails closed and the replacement is not deleted.

## Verification

- `npm run build`: passed, including native artifacts and TypeScript.
- `npm run lint`: passed across 648 tracked files.
- `npm run typecheck`: passed.
- `git diff --check`: passed.
- Focused Broker IPC suite: 10 passed, 0 failed.

The long-running Broker/Persistence and helper IPC test processes were left
untouched. Crash recovery for orphaned socket quarantine artifacts and
production installed-service readback remain open.
