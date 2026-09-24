# Process final cancellation fence

## Decision

The shared `ProcessSupervisor` must re-evaluate its Broker-owned cancellation
callback after the child has closed and immediately before publishing a
terminal result. Periodic polling protects active work, but a kill switch or
session revocation can change between the last poll and final readback. In
that window, a successful child exit must not be published as `SUCCEEDED`.

The supervisor now maps that final positive cancellation result to
`CANCELLED`, while preserving the existing process-group drain and
fail-closed `UNKNOWN_OUTCOME` behavior when cleanup or observation is
uncertain.

## Evidence

- Focused ProcessSupervisor regression: 47/47 passed on macOS arm64.
- The new regression runs `/usr/bin/true` with a bounded callback that becomes
  revoked only at final close; the result is `CANCELLED`, never `SUCCEEDED`.
- Full repository regression: 1,179 total, 1,164 passed, 15 skipped, 0 failed.
- `npm run build --silent` passed.
- No host service, permission, credential, or production capability state was
  changed.

## Limits

This closes the local final-publication race at the shared process boundary.
It does not prove kernel-level cancellation, physical disk exhaustion,
post-snapshot descendant attribution, installed operator recovery, remote
issuer propagation, or production task-runner ownership.
