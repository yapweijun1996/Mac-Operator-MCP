# Core Ledger Schema Layout

Status: PARTIAL MOP-004/MOP-071 evidence; capability enablement remains gated

Date: 2026-09-15

## Scope

Broker startup now verifies the complete column set of every Broker persistence
table after migrations, including nonce ledgers, runtime fence, active/history
configuration, Request/Approval/Job ledgers, audit events, revocations, and
kill-switches. Unknown or missing columns fail closed as `AUDIT_UNAVAILABLE`,
preventing a newer or tampered writer from adding state that the current
runtime would silently ignore. Legacy migrations remain compatible because the
check compares the post-migration column set.

## Verification

- Schema-layout startup test: 1 passed, 0 failed.
- Request/link/Job focused slice: 12 passed, 0 failed.
- Non-overlapping package regression: 592 total, 586 passed, 6 skipped, 0 failed.
- `npm run build`: passed.
- `npm run lint`: passed for 602 tracked files before this evidence file was added.
- `git diff --check`: passed.

The long-running `broker.test.js` and `persistence.test.js` suites were already
active in another process and were intentionally not restarted or terminated.

## Remaining limits

This verifies core table shape only; it does not prove physical crash recovery,
production Keychain/signing, installed lifecycle, process/credential
isolation, disk exhaustion behavior, or independent P0/P1 review.
