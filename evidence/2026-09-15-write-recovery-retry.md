# UNKNOWN Write Temporary Recovery Retry Evidence

- Source revision: `2fadf8a`
- Date: 2026-09-15
- Scope: Restart cleanup of Broker-owned atomic-write temporaries

## Decision

`TEMPORARY_CLEANUP_SKIPPED` is now treated as retryable recovery uncertainty.
The Broker retries only the persisted root, target, and exact temporary name;
`cleanupWriteTemporary` continues to enforce root, symlink, and device/inode
identity checks before unlinking. No write is replayed and no Job is promoted
to success. Definitive removed/absent outcomes remain terminal for that
recovery record.

## Verification

- `npm run build`: passed, including native artifact builds and TypeScript.
- `npm run lint`: passed.
- `npm run typecheck`: passed.
- Physical-host recovery probe: a symlinked temporary first produced
  `TEMPORARY_CLEANUP_SKIPPED`; after the artifact was safely replaced with a
  regular file, the next reconciliation removed only that exact file and left
  the outside target unchanged.
- Added regression coverage: `restart write recovery retries a previously
  skipped temporary cleanup` in `packages/broker/src/broker.test.ts`.

The long-running Broker/Persistence and helper IPC test processes were left
untouched.
