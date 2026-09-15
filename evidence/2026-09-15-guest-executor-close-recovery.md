# Guest executor close-recovery evidence

Date: 2026-09-15
Source commit: `3245482`
Host: physical Darwin arm64 development host

## Boundary

The guest-side profile executor must stop accepting work immediately, cancel
active adapters, and wait for all active executions even if adapter cleanup
itself fails. A cleanup exception must not skip the drain or make a later host
shutdown retry impossible.

## Implementation

`VirtualizationGuestProfileExecutor.close()` now caches an in-flight close,
aborts every active controller, captures adapter cleanup failures, and always
awaits all active execution promises. A failed cleanup clears only the rejected
Promise cache while keeping the executor permanently fenced against new work,
so an explicit retry can repeat adapter cleanup after the drain. Successful
close remains idempotent through the resolved Promise.

## Verification

- Guest executor tests pass 10/10.
- The regression holds an active adapter open, injects one cleanup failure,
  confirms cancellation and drain before the failure is returned, then
  successfully retries cleanup.
- The non-overlapping package regression passes 496 total (490 pass, 6
  skipped, 0 fail).
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This evidence covers guest executor shutdown semantics only. It does not prove
a bootable VM, guest filesystem/network/credential isolation, native
attestation production, or `mac_task_run` enablement.

## Rollback

Revert commit `3245482`. No wire contract, persisted state, or capability
advertisement changes are involved.
