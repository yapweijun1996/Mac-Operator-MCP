# Persisted Job Output Integrity

Status: PARTIAL MOP-071 evidence; capability enablement remains gated

Date: 2026-09-15

## Scope

Persisted Job output is now treated as untrusted recovery/status input. The
Broker rejects non-string or oversized stdout/stderr, secret-shaped output,
invalid exit codes, malformed cancellation reasons, and non-string metadata
columns before a Job can influence recovery or status publication. The same
256 KiB per-stream bound and secret classifier used at write time is enforced
again at startup.

## Verification

- Job-row and Job-state focused tests: 7 passed, 0 failed.
- Request-link focused tests: 3 passed, 0 failed.
- Non-overlapping package regression: 591 total, 585 passed, 6 skipped, 0 failed.
- `npm run build`: passed.
- `npm run lint`: passed for 598 tracked files.
- `git diff --check`: passed.

The long-running `broker.test.js` and `persistence.test.js` suites were already
active in another process and were intentionally not restarted or terminated.

## Remaining limits

This is local persisted-output fencing evidence only. It does not prove
physical crash recovery, old-worker process ownership, disk/remount durability,
production credential rotation, installed operation, or independent P0/P1
security review.
