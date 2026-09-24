# Semantic Resource Budgets

Date: 2026-09-23

Status: `PASS` for the implemented local Broker planning, admission, and
stopped-service ledger-rotation boundaries; physical disk exhaustion,
kernel-level cancellation, archive artifact lifecycle, and production
Request/Job retention evidence remain open.

## Implemented boundary

`packages/broker/src/resource-budget.ts` defines fixed, reviewable semantic
budgets for operations whose work expands across authorized roots or depth:

- file search and recent-file search: root count × result slots;
- project discovery: root count × result slots;
- directory trees: depth × entry slots;
- storage analysis: resolved-root count × ranking slots × depth.

The Broker applies these checks during `planExecution`, before filesystem
planning, authorization of additional targets, approval consumption, Job
creation, or adapter dispatch. Existing per-field validators remain the source
of individual type and range checks; the shared budget prevents a valid request
from multiplying those limits into an unbounded fan-out.

## Verification

- Focused semantic-budget regression: 3 passed, 0 failed, 0 skipped.
- Broker task-family admission regression: 1 passed, 0 failed, 0 skipped.
- Full repository regression: 1,161 total; 1,146 passed, 15 skipped, 0 failed.
- Encrypted terminal Request/Job export, inspection, and tombstone rotation:
  5 passed, 0 failed, 0 skipped.
- Encrypted archive artifact retention: 3 passed, 0 failed, 0 skipped.
- Encrypted archive capacity preflight: 2 passed, 0 failed, 0 skipped; both
  paths reject insufficient capacity before temporary-file creation.
- `npm run build` and `npm run typecheck`: passed.
- `git diff --check`: passed.

## Remaining limits

These are deterministic Broker admission budgets, not kernel quotas. They do
not prove physical disk-full behavior, interruption of a kernel-blocked I/O
call, process-level resource isolation, or resource policy for every future
general job adapter. The separate encrypted terminal Request/Job archive now
has a bounded, stopped-service rotation contract: it publishes the archive
first, retains status/replay/idempotency tombstones, and never selects active
or `unknown` work. It does not prove physical disk-full behavior, archive
  artifact retention/rotation, or production storage policy. The export
  capacity preflight is a bounded admission guard, not proof of physical
  disk-full or kernel-blocked I/O behavior. Those release gates remain
  fail-closed.

## Rollback

Revert `packages/broker/src/resource-budget.ts`, its test and export, the
Broker planning hooks, and this evidence record together. No host service,
permission, credential, or persistent runtime state was changed.
