# Privileged Helper Runtime Disposal Evidence

- Source revisions: `2ce0945` (runtime), `ccb248b` (failed-cleanup test)
- Date: 2026-09-15
- Scope: authority-poller lifecycle ownership in `PrivilegedHelperRuntime`

## Change

The helper runtime now owns one idempotent authority-poller disposal path.
Startup failure disposes the poller after listener cleanup (including cleanup
failure), close-before-start disposes it, and normal close disposes it in a
`finally` path. A runtime with a disposed poller rejects restart so cleared
authentication material cannot be reused.

## Verification

- Focused runtime suite: 6/6 passed.
- Physical non-overlapping built suite:
  `MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1 MOPS_REAL_SANDBOX=1 node --test --test-timeout=120000 $(find packages -path '*/dist/*.test.js' ! -name broker.test.js ! -name persistence.test.js | sort)`
- Physical result: 616/616 passed, 0 skipped, 0 failed.
- `npm run typecheck`: passed.
- `npm run lint -- --files packages/broker/src/privileged-helper-runtime.ts packages/broker/src/privileged-helper-runtime.test.ts`: passed across 633 tracked files.
- `git diff --check`: passed before commit.

The existing long-running Broker/Persistence test process was not restarted.
This evidence does not claim root-domain installation, Developer ID signing,
or privileged operation enablement.
