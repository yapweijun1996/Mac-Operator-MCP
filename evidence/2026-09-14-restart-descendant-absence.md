# Restart descendant-absence recovery evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Status: partial MOP-071/MOP-086 evidence; task capability remains disabled

## Boundary

After a Broker restart, a persisted task process identity is only an ownership
hint. If the recorded root has exited and the previously observed descendants
are no longer present, the Broker cannot prove that a descendant was not
created after the final persisted snapshot and escaped into another process
group. Recovery therefore remains `UNKNOWN_OUTCOME` with
`terminationObserved: false`; it never publishes `PROCESS_ABSENT` from that
incomplete census.

## Verification

- The Darwin regression starts a real Python root, persists a live descendant,
  waits for that descendant to exit and be reaped, then kills the root before
  invoking restart recovery.
- The recovery result remains `unknown` even though the root and recorded
  descendant are gone.
- Focused process-supervisor suite: 21/21 passed.
- Full `MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test`: 479 tests, 478
  passed, 0 failed, 1 explicit opt-in install skip.

## Limits

This is a conservative attribution guard, not kernel-held process-tree
containment. A production task runner still requires credential isolation,
remount resistance, post-snapshot escape prevention, and independent review.
