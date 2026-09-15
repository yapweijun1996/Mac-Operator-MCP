# Replay Ledger Invariant Evidence

Date: 2026-09-15

Source revision: `100133e`

Command:

```text
npm run build && node --test \
  packages/broker/dist/replay-row-invariants.test.js \
  packages/broker/dist/authority-row-invariants.test.js \
  packages/broker/dist/approval-row-invariants.test.js
12 tests, 12 passed, 0 failed, 0 skipped
```

## Decision

Every durable replay ledger is treated as authority state. A malformed row
must not be interpreted as an accepted nonce or request after a restart.

## Implemented boundary

Broker startup now scans the request, authenticated approval, policy-signer,
authority-control, privileged-helper, Broker-status, and virtualization-guest
replay tables after schema migration. It validates the ledger-specific nonce
and request identities, accepted/expiry ordering, bounded values, and guest
ledger capacity. Any malformed row fails closed with `AUDIT_UNAVAILABLE`
before runtime fences, authority restoration, or request admission proceed.

The focused replay corruption tests mutate each table through a separate
SQLite connection and verify startup rejection. Existing Approval and
revocation/kill-switch row-invariant tests remain green. No external authority,
privileged action, or destructive operation was invoked.

The non-overlapping package regression after the replay-row change reports
572 tests total (566 passed, 6 explicitly skipped, 0 failed). The existing
`broker.test.js` and `persistence.test.js` processes were excluded because
they were already running; this is bounded local evidence, not a fresh run of
those two suites.

This closes only the persisted replay representation boundary. Broader
canonicalization, retention, production Keychain distribution, installed
operator recovery, external rollback detection, and ADR acceptance remain
open.
