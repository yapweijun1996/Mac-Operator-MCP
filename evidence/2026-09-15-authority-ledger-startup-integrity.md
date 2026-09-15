# Authority Ledger Startup Integrity

Status: PARTIAL MOP-071 evidence; capability enablement remains gated

Date: 2026-09-15

## Scope

Broker startup now scans every persisted Approval, Revocation, and
Kill-switch row before policy evaluation, request admission, or restart
reconciliation. Approval lifecycle counters, expiry, consumption and
revocation pairing, bounded identities and targets, revocation subjects, and
switch state/reason fields all fail closed as `AUDIT_UNAVAILABLE` when
malformed.

## Verification

- Focused Approval and authority-row corruption tests: 5 passed, 0 failed.
- Combined Request/Job/Approval/authority startup-integrity slice: 15 passed, 0 failed.
- Non-overlapping package regression: 587 total, 581 passed, 6 skipped, 0 failed.
- `npm run build`: passed.
- `npm run lint`: passed for 595 tracked files.
- `git diff --check`: passed.

The long-running `broker.test.js` and `persistence.test.js` suites were already
active in another process and were intentionally not restarted or terminated.

## Remaining limits

This is persisted authority-ledger fencing evidence only. It does not prove
production Keychain distribution, external rollback detection, physical crash
recovery, installed operator recovery, or human approval UI behavior.
