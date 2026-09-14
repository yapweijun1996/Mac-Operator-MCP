# Audit-anchor publication outage evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Status: partial MOP-015/MOP-071 evidence; production enablement remains gated

## Boundary

`BrokerStore` commits SQLite state before publishing the keyed audit-tail
sidecar. If the sidecar publication is unavailable, the caller receives the
stable retryable `AUDIT_UNAVAILABLE` error even though the database now
contains the audit row. The sidecar remains at its prior tail, and the next
BrokerStore startup rejects the database/anchor mismatch rather than treating
the audit state as trustworthy.

## Verification

- A real owner-only sidecar lock blocks the second publication.
- The second audit row is durably present in SQLite, but its append call fails
  with `AUDIT_UNAVAILABLE`.
- After the lock is removed, the same BrokerStore remains write-frozen and
  rejects a retry until the process is restarted.
- After the lock is removed, reopening the same database fails with an audit
  anchor mismatch.
- Persistence suite: 41/41 passed.
- Full `MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test`: 480 tests, 479
  passed, 0 failed, 1 explicit opt-in install skip.

## Limits

This proves local crash/outage fail-closed behavior only. It does not provide
an external immutable anchor, rollback-resistant storage, physical disk-full
evidence, or production Keychain rotation.
