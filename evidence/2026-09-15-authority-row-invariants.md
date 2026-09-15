# Authority Row Invariant Evidence

Date: 2026-09-15

Source revision: `e11127e`

Command:

```text
npm run build && node --test \
  packages/broker/dist/authority-row-invariants.test.js \
  packages/broker/dist/policy.test.js \
  packages/broker/dist/authority-control-ipc.test.js
15 tests, 15 passed, 0 failed, 0 skipped
```

## Decision

Persisted revocations and kill-switch rows are treated as authority inputs,
not ordinary metadata. A malformed row fails closed as
`AUDIT_UNAVAILABLE` before it can affect policy, Job cancellation, or runtime
capability evaluation.

## Implemented boundary

`BrokerStore.isRevoked` now validates the query identity and the returned
revocation row's kind, subject, timestamp, and reason. `isSwitchDisabled` now
validates the switch name and persisted disabled flag, change timestamp, and
reason. Invalid query inputs return `PRECONDITION_FAILED`; corrupted stored
rows return `AUDIT_UNAVAILABLE`.

The focused tests mutate each authority table through a separate SQLite
connection and confirm fail-closed readback. Existing Authority Control IPC
and policy tests remain green. No external authority, privileged action, or
destructive operation was invoked.

The non-overlapping package regression after the authority-row change reports
565 tests total (559 passed, 6 explicitly skipped, 0 failed). The existing
`broker.test.js` and `persistence.test.js` processes were excluded because
they were already running; no test process was restarted or killed. This is a
bounded regression result, not a claim about a fresh run of those two suites.

This closes only the revocation/switch representation boundary. Production
Keychain distribution, installed operator recovery, external rollback
detection, and architecture acceptance remain open.
