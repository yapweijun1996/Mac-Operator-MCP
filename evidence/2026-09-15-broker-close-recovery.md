# Broker shutdown recovery evidence

Date: 2026-09-15
Source commit: `505d28a`
Host: physical Darwin arm64 development host

## Boundary

Broker shutdown must fence new requests immediately, but a failure in one
owned resource must not make the cleanup result permanently unrecoverable.
Workers, process supervision, and task runners can have independent close
boundaries, so a rejected aggregate close must remain explicitly retryable.

## Implementation

`Broker.close()` keeps `closing` asserted after shutdown begins, preventing new
requests from being admitted. It still closes every owned resource and
preserves the first failure. When a resource close fails, the rejected Promise
cache is cleared so a later host lifecycle call can retry cleanup; successful
close remains idempotent through the resolved Promise. The Broker is never
reopened after a failed close.

## Verification

- Broker close tests pass 2 close-focused cases; the new regression injects a
  task-runner cleanup failure, observes a `CANCELLED` request result, and then
  completes a second explicit close.
- The non-overlapping package regression passes 495 total (489 pass, 6
  skipped, 0 fail).
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This evidence covers Broker-owned shutdown retry semantics only. It does not
prove installed launchd recovery, VM isolation, credential isolation,
privileged-helper operation, or production capability enablement.

## Rollback

Revert commit `505d28a`. No wire contract, persisted state, or capability
advertisement changes are involved.
