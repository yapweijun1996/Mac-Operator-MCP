# Virtualization guest runtime close-recovery evidence

Date: 2026-09-15
Source commit: `d68176b`
Host: physical Darwin arm64 development host

## Boundary

`VirtualizationGuestRuntimeImpl.close()` must not convert an uncertain or
failed shutdown into a permanent closed state. Transport drain, task-runner
shutdown, or lifecycle stop can fail independently; the Broker must retain an
explicit retry path and require the existing lifecycle status/readback fence
before recovery proceeds.

## Implementation

The runtime still attempts connection, task-runner, and lifecycle shutdown in
order and preserves the first failure for stable error mapping. When any
shutdown step fails, it now clears the cached close promise and leaves the
runtime open for an explicit retry. Only a fully successful close marks the
runtime closed. This avoids caching a rejected promise and avoids claiming
that an unconfirmed VM transition is complete.

## Verification

- Virtualization guest startup tests pass 3/3.
- The regression injects one close failure, observes `UNKNOWN_OUTCOME`,
  confirms the lifecycle readback remains `stopped`, and successfully retries
  `close()`.
- The non-overlapping package regression passes 494 total (488 pass, 6
  skipped, 0 fail).
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This evidence covers runtime close-state recovery only. It does not prove a
bootable Virtualization.framework guest, guest filesystem/network/credential
isolation, production code signing, or `mac_task_run` enablement. Those gates
remain open.

## Rollback

Revert commit `d68176b`. No wire contract, persisted state, or capability
advertisement changes are involved.
