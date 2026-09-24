# Job terminal invariants

## Decision

The Broker-owned Job ledger now requires every `cancelled` terminal row to
carry the durable cancellation marker that caused the terminal transition.
`BrokerStore.finishJob` rejects a cancellation outcome when the current
revision has no cancellation request, and startup validation rejects a
persisted `cancelled` row whose `cancel_requested` flag or reason is missing.
This keeps a worker result from manufacturing a terminal cancellation that is
not attributable to a Broker-owned authority change.

## Evidence

- Runtime fence: a running Job cannot be finished as `cancelled` until a
  durable cancellation request has incremented its revision.
- Startup fence: a tampered `cancelled` row without its durable cancellation
  marker fails closed with `AUDIT_UNAVAILABLE` before restart reconciliation.
- Focused persistence, Job-state, and row-invariant coverage: 69 passed, 0
  failed, 0 skipped.
- Full repository regression on macOS 26.2 arm64, UID 501: 1,179 total,
  1,164 passed, 15 skipped, 0 failed.
- `npm run typecheck` and `git diff --check` passed.
- No host LaunchAgent, privilege, permission, or service state was changed.

## Limits

This closes the local persisted `cancelled`-row invariant only. It does not
prove physical process termination, post-snapshot descendant attribution,
disk-full/remount durability, external actor attribution, broader partial
mutation recovery, installed service recovery, or production acceptance.
Those VT-REL-01 cases remain open.
