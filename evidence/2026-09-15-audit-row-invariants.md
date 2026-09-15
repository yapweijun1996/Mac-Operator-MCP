# Audit Row Invariants Evidence

Date: 2026-09-15

Source revision: `3cc9c80`

`BrokerStore` now validates audit events before write and persisted audit
records before readback or hash-chain verification. Sequence numbers must be
strictly increasing; request/principal/tool/target/policy/result text is
bounded and NUL-free; event type and decision values are allowlisted;
timestamps and SHA-256 hash fields are validated; and evidence JSON must be
strictly parseable and bounded.

Focused tests:

- `packages/broker/src/audit-row-invariants.test.ts`: 1/1 passed.
- A corrupted tool identity fails closed as `AUDIT_UNAVAILABLE` before caller
  readback.
- `packages/broker/src/audit-write-boundary.test.ts`: 1/1 passed.
- A malformed event is rejected before any audit row is persisted.

Regression:

- Build and typecheck passed.
- Lint passed for 573 tracked files.
- Contract verification passed for 44 tool contracts and the ledger schema.
- Non-overlapping package regression: 560 total, 554 passed, 6 skipped, 0
  failed. The existing long-lived broker/persistence test process was left
  untouched.

This hardens local persistence readback; it does not by itself provide an
external rollback-resistant audit anchor or production Keychain/code-signing
identity.
