# Audit Anchor Lock Quarantine Evidence

- Source revision: `61e6acb`
- Date: 2026-09-15
- Scope: Broker keyed audit-anchor lock setup and release

## Decision

Normal audit-anchor lock cleanup now atomically renames the exact checked lock
to a private sibling quarantine, rechecks device/inode/type, and only then
unlinks the quarantine. A lock pathname replacement is rejected before or
during removal, leaving the unexpected artifact for explicit recovery. The
separately gated stopped-service recovery path remains native and unchanged.

## Verification

- `npm run build`: passed, including native artifacts and TypeScript.
- `npm run lint`: passed across 650 tracked files.
- `npm run typecheck`: passed.
- `git diff --check`: passed.
- Focused audit-anchor and read-only outage suite: 9 passed, 0 failed.

The long-running Broker/Persistence and helper IPC test processes were left
untouched. Crash recovery for orphaned anchor-lock quarantine artifacts and
installed-service readback remain open.
