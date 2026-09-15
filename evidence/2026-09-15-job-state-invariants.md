# BrokerStore Job state invariant evidence

Date: 2026-09-15
Source revision: `9f8a927`

## Decision

Treat the persisted Job Ledger as an authority boundary, not just a storage
format. `BrokerStore` now validates state/result-class combinations, lifecycle
timestamps, lease shape, output flags, and cancellation markers before mapping
a row into Broker logic.

## Enforced invariants

- `queued` Jobs have `queued` result class and no start/finish timestamp.
- `running` Jobs have `accepted` result class, a start timestamp, and no finish
  timestamp; leases are either absent (legacy/test adapter) or complete.
- `completed`, `failed`, `cancelled`, and `unknown` Jobs require terminal
  result classes and bounded finish timestamps consistent with their start.
- Lease fields cannot be partially populated, and non-running Jobs cannot retain
  an active lease.
- Cancellation markers are paired: `cancel_requested=1` requires a bounded
  reason, while an unset marker cannot retain one.
- A running Job whose cancellation revision has won cannot be persisted as
  `completed/success`; it must remain recoverable as `UNKNOWN`.
- Any mismatch fails closed as `AUDIT_UNAVAILABLE` before readback or recovery.

## Verification

- `npm run build`
- Focused invariant/corruption tests: 2/2 passed
- Existing persistence suite: 56/56 passed
- `npm run lint`
- `git diff --check`

## Remaining evidence

This closes a local persistence-state boundary only. Kernel-level disk
exhaustion, production Keychain/code-signing identity, external rollback
resistance, and final ADR-0005 acceptance remain open.
