# Virtualization guest executor admission-concurrency evidence

Date: 2026-09-15
Source commit: `eb9aa47`
Host: physical Darwin arm64 development host
Scope: guest executor concurrency admission; no VM boot

## Decision

The guest executor's concurrency budget covers both active adapter runs and
requests waiting for asynchronous manifest readback. A capacity check that
counts only already-started adapters can be bypassed by concurrent admissions.

## Implementation

`VirtualizationGuestProfileExecutor` now reserves a slot synchronously before
calling the asynchronous registry resolver and checks `active + inFlight`
against `maxConcurrent`. The reservation is released on every resolver,
policy, cancellation, and adapter completion path. The executor still exposes
only fixed startup-owned profile material and retains its existing bounded
adapter/ledger behavior.

## Verification

- Guest executor tests pass 8/8, including a `maxConcurrent: 1` concurrent
  admission regression whose second request is rejected while the first is
  still resolving/running.
- The combined guest/transport/lifecycle/startup/native focused suite passes
  53/53 with 0 skipped tests.
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This evidence does not claim a production AF_VSOCK service, bootable image,
guest filesystem/network/credential isolation, or `mac_task_run` enablement.
Those independent gates remain open.

## Rollback

Revert commit `eb9aa47`. No persisted state, wire contract, or MCP capability
advertisement changes are involved.
