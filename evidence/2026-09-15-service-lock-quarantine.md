# Service Instance Lock Quarantine Evidence

- Source revision: `d3ca767`
- Date: 2026-09-15
- Scope: Broker startup-lock stale-owner reclamation and close

## Decision

Exact service-lock removal now atomically renames the checked owner-only lock
to a private same-directory quarantine, rechecks its device/inode/type, and
only then unlinks the quarantine. A changed pathname fails closed before the
rename, while a changed quarantine identity is retained and reported instead
of deleting an unrelated lock.

## Verification

- `npm run build`: passed, including native artifacts and TypeScript.
- `npm run lint`: passed across 649 tracked files.
- `npm run typecheck`: passed.
- `git diff --check`: passed.
- Focused Broker service-instance-lock suite: 5 passed, 0 failed.

The long-running Broker/Persistence and helper IPC test processes were left
untouched. Durable cleanup/recovery of orphaned lock quarantine artifacts and
installed-service readback remain open.
