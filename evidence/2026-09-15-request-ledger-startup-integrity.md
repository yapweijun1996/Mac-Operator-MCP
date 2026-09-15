# Request Ledger Startup Integrity

Status: PARTIAL MOP-071 evidence; capability enablement remains gated

Date: 2026-09-15

## Scope

Broker startup now validates every persisted Request row before restart
reconciliation can inspect or mutate it. The check reuses the durable Request
state machine and capability-family decoder, and therefore fails closed on
malformed lifecycle state as well as forged request identity.

Persisted Request identity is required to use the bounded Broker formats for
the request ID, Edge ID, principal/session, tool, policy version, and payload
digest. State/result relationships, mutation approval and Job links, target
text, timestamps, revisions, and capability-family storage must remain
coherent before startup continues.

## Verification

- Focused Request-state and startup-integrity tests: 4 passed, 0 failed.
- Non-overlapping package regression: 587 total, 581 passed, 6 skipped, 0 failed.
- `npm run build`: passed.
- `npm run lint`: passed for 594 tracked files.
- `git diff --check`: passed.

The long-running `broker.test.js` and `persistence.test.js` suites were already
active in another process and were intentionally not restarted or terminated.

## Remaining limits

This is persisted-ledger and startup fencing evidence only. It does not prove
physical crash recovery, OS process ownership after an unobserved Broker
crash, credential rotation on an installed host, disk/remount durability, or
production task-runner enablement.
