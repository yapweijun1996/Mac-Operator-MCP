# Signed request data-shape evidence

Date: 2026-09-15
Source commit: `14d3cc0`
Host: physical Darwin arm64 development host

## Boundary

Canonical request authentication must cover every value that Broker planning
can read. Direct callers must not smuggle authority or target data through
non-enumerable properties, accessors, sparse arrays, cycles, or nested objects
whose representation differs from canonical JSON.

## Implementation

The Broker now shares `isPlainDataRecord()` for policy and request boundaries.
Request validation walks the complete request value with bounded depth and
node count, requiring ordinary or null-prototype data-only records and dense
arrays. Symbols, hidden properties, accessors, unsupported values, cycles, and
oversized object graphs fail closed as `AUTH_INVALID` before authentication or
execution.

## Verification

- The security-fuzz suite passes 8/8, including inherited, hidden, accessor,
  and sparse-array request mutations.
- The non-overlapping package regression passes 498 total (492 pass,
  6 skipped, 0 fail).
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This evidence covers direct local request data-shape integrity. It does not
prove production transport packaging, VM isolation, credential isolation,
privileged helper installation, or capability enablement.

## Rollback

Revert commit `14d3cc0`. The change is parser-side and does not alter wire
schemas or persisted records.
