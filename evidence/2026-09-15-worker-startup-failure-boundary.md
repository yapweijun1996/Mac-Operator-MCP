# Worker startup failure boundary evidence

Date: 2026-09-15
Source revision: `4d2ee44`

## Boundary

`BoundedWorkerExecutor.run` now catches synchronous exceptions from the
Broker-owned worker factory and maps them to the stable `EXECUTION_FAILED`
error class. No worker slot is counted when construction fails, and no raw
factory error text is returned to an MCP caller.

## Verification

- `npm run build` — pass.
- `node --test --test-concurrency=1 packages/broker/dist/worker-executor.test.js` — 8/8 pass.
- Non-overlapping package regression (excluding the two pre-existing long-running broker test processes) — 492 total, 486 pass, 6 skipped, 0 fail.
- `npm run typecheck` — pass.
- `npm run lint` — pass.
- `git diff --check` — pass.

This closes only synchronous worker-construction error normalization. It does
not prove worker sandboxing, filesystem or network isolation, credential
separation, or production task-runner enablement.

## Rollback

Revert the source/test commit that introduced this boundary; no runtime data
or host configuration is changed.
