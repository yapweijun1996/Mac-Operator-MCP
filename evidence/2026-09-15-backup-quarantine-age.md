# Backup Quarantine Age Evidence

- Source revision: `8119e94`
- Date: 2026-09-15
- Scope: Backup quarantine concurrency and stale-age determination

## Decision

Backup cleanup quarantine names now include a bounded millisecond creation
timestamp. Recovery uses that timestamp rather than the original file `mtime`,
which may be old even while an active deletion is between rename and unlink.
Recent quarantines are therefore protected from concurrent recovery; only
quarantines older than the cleanup threshold are eligible for the existing
identity-fenced removal.

## Verification

- `npm run build`: passed, including native artifacts and TypeScript.
- `npm run lint`: passed across 657 tracked files.
- `npm run typecheck`: passed.
- `git diff --check`: passed.
- Dedicated backup-quarantine regression: 1 passed, 0 failed.

The long-running Broker/Persistence and helper IPC test processes were left
untouched. Native unlink quarantine recovery and production crash/remount
evidence remain open.
