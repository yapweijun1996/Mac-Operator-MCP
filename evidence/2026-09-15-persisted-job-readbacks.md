# Persisted Job Readback Evidence

Date: 2026-09-15
Source revisions: `2cc1db7`, `937ffcd`, `5f4980d`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T05:29:48Z
Artifact hashes: `packages/broker/src/broker.ts` SHA-256
`cc4a9ad9fe7f1eec7b8bde9e90857d2b2b6cb7ab62c9b0b3ae32dd1f492e548d`;
`packages/broker/src/broker-result-boundary.test.ts` SHA-256
`01ff3d8c4fe8ca957d51792e3fdb93972d663a893aaaec59e456b1acc8d88926`.

## Decision

Completed mutation and app/UI Job results are persisted as bounded JSON and
may be read after restart for idempotent reuse or postcondition recovery.
Persisted bytes are not trusted merely because they parse as JSON.

## Implemented controls

- Stored app-open, app-focus, UI-action, filesystem-write, and filesystem-
  patch envelopes require plain records with exact declared fields.
- Nested app targets, UI reobservations, write preconditions, patch
  preconditions, and patch-file records have independent exact field sets.
- Unknown, inherited, symbolic, accessor, and malformed fields fail closed as
  `UNKNOWN_OUTCOME` before a completed Job is reused or a verified readback is
  emitted.
- Parsers copy only validated fields into fresh result records, preserving
  target and postcondition identities while avoiding persistence metadata
  leakage.

## Verification

Focused command:

```text
npm run build && node --test packages/broker/dist/broker-result-boundary.test.js
```

Result: 2 tests passed, 0 failed, 0 skipped. Hostile fixtures cover unknown
top-level and nested target/precondition/reobserved/file fields across all
stored mutation and app result families.

Non-overlapping package regression (excluding the two pre-existing long-lived
broker/persistence test processes): 527 tests total, 521 passed, 6 skipped,
0 failed.

## Boundary status

This proves persisted result-shape integrity only. It does not prove SQLite
corruption recovery, crash-window ownership, disk exhaustion, audit-anchor
availability, installed-service recovery, or production capability
enablement. Those gates remain fail-closed and incomplete.
