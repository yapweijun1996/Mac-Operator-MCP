# Restart Reconciliation Clock-Order Evidence

Date: 2026-09-15

Source revision: `5148a8b`

Command:

```text
npm run build && node --test \
  packages/broker/dist/reconciliation-clock.test.js \
  packages/broker/dist/runtime.test.js
9 tests, 9 passed, 0 failed, 0 skipped
```

## Decision

Restart recovery must not move durable lifecycle timestamps backwards. A
recovery timestamp earlier than a Request's received/updated time or a Job's
created/start/heartbeat time is rejected before any state transition.

## Implemented boundary

`BrokerStore.reconcileInterruptedRequests` and
`BrokerStore.reconcileInterruptedJobs` now compare the recovery clock with the
persisted lifecycle timestamps before writing failure, cancellation, or
unknown outcomes. The check returns the stable malformed-input boundary
(`PRECONDITION_FAILED`) and leaves the durable record unchanged. This also
protects startup recovery from publishing a timestamp-regressed audit event
or Job terminal state when the host clock moves backwards.

Focused tests cover received Requests, queued Jobs, and running Jobs with
start/heartbeat timestamps. The latest non-overlapping package regression
reports 582 tests total (576 passed, 6 explicitly skipped, 0 failed). The
existing `broker.test.js` and `persistence.test.js` processes were excluded
because they were already running; this is bounded local evidence, not a
fresh run of those two suites.

No external authority, privileged action, or destructive operation was
invoked. Crash ownership, real clock/rollback behavior, production Keychain,
installed recovery, and independent release review remain open.
