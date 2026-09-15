# Authenticated IPC data-shape evidence

Date: 2026-09-15
Source commit: `27e102b`
Host: physical Darwin arm64 development host

## Boundary

Authenticated local channels must process only data represented by the signed
wire envelope. Accessors, hidden properties, or prototype-provided values must
not be able to influence command, status, helper, or guest authentication
logic.

## Implementation

Authority Control, Broker Status, Privileged Helper, and Virtualization Guest
transport parsers now use the shared `isPlainDataRecord()` guard. Root
envelopes and response objects with non-data properties fail closed before
proof verification, replay admission, dispatch, or status access.

## Verification

- The four focused IPC suites pass 32/32, including accessor-field rejection
  regressions for each authenticated channel.
- The non-overlapping package regression passes 502 total (496 pass,
  6 skipped, 0 fail).
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This evidence covers local parser data-shape integrity only. It does not prove
OS peer identity, production packaging, VM isolation, credential isolation,
privileged helper installation, or capability enablement.

## Rollback

Revert commit `27e102b`. No wire schema or persisted record changes are
introduced.
