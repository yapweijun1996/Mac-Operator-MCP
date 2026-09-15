# Virtualization guest executor close-drain evidence

Date: 2026-09-15
Source commit: `9f772fe`
Host: physical Darwin arm64 development host
Scope: guest executor shutdown draining; no VM boot

## Decision

Guest executor shutdown is complete only after active adapter promises have
settled. Sending cancellation and returning immediately would leave an
unbounded adapter running beyond the kill-switch/close boundary.

## Implementation

`VirtualizationGuestProfileExecutor` tracks every adapter execution promise.
`close()` marks the executor closed, aborts all active controllers, invokes the
adapter close hook, and awaits `Promise.allSettled` for the tracked executions.
The existing cancellation gate still converts a late adapter success into a
stable cancelled result, so shutdown cannot publish guest success after close.

## Verification

- Guest executor tests pass 8/8; the close regression proves `close()` remains
  pending until the adapter promise settles after abort.
- The combined guest/transport/lifecycle/startup/native focused suite passes
  53/53 with 0 skipped tests.
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This evidence does not claim a production AF_VSOCK service, bootable image,
guest filesystem/network/credential isolation, or `mac_task_run` enablement.
Those independent gates remain open.

## Rollback

Revert commit `9f772fe`. No persisted state, wire contract, or MCP capability
advertisement changes are involved.
