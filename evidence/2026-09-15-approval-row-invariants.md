# Approval Row Invariant Evidence

Date: 2026-09-15

Source revision: `28b26db`

Command:

```text
npm run build && node --test \
  packages/broker/dist/approval-row-invariants.test.js \
  packages/broker/dist/approval-authority.test.js
14 tests, 14 passed, 0 failed, 0 skipped
```

## Decision

BrokerStore treats a malformed persisted Approval as unavailable authority.
The row is rejected before intent admission, approval consumption, status
readback, or revocation can use it.

## Implemented boundary

Approval readback now validates bounded identities, tool and contract formats,
target binding, payload and policy digests, approval class, timestamps,
single-use counters, consumption fields, revocation pairing, and revision
monotonicity. The validator maps corruption to stable `AUDIT_UNAVAILABLE`.

The focused suite injects corrupted consumption, expiry, and revocation rows
through a separate SQLite connection and confirms fail-closed readback. The
existing authenticated approval authority tests remain green. No production
approval, privileged action, or external system was invoked.

This closes only the Approval row representation boundary. Protected
production Keychain/cross-process approval storage, human approval UI,
unattended ownership, and architecture-acceptance gates remain open.
