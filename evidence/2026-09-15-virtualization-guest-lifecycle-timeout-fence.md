# Virtualization guest lifecycle timeout fence evidence

Date: 2026-09-15
Source commit: `ea85237`
Host: physical Darwin arm64 development host
Scope: VM lifecycle timeout, cancellation, and serialized transition safety

## Finding

The VM lifecycle deadline raced only the caller-visible promise. If a native
adapter ignored `AbortSignal` after a timeout, the serialized queue could admit
a later status or transition while the timed-out start/stop call was still
mutating the VM. That overlap could turn an unknown mutation into an unsafe
second operation.

## Implementation

`VirtualizationGuestVmLifecycle` now retains the active native operation until
its promise settles. A later lifecycle operation fails closed with retryable
`UNKNOWN_OUTCOME` while that operation remains unresolved. Once the native
promise settles, status recovery can run normally. The existing deadline,
cancellation, identity, boot-ID, and sticky-unknown rules remain unchanged.

## Verification

- Virtualization guest lifecycle tests pass 7/7, including a delayed native
  start that times out, rejects overlapping status, then permits status
  recovery after the native promise settles.
- The focused guest/transport/lifecycle/startup/native/task-runner suite passes
  86/86 with 0 skipped tests.
- The physical-Darwin regression over all non-overlapping test files passes
  486/486 with 0 skipped tests. The repository already had a separate
  long-running `broker.test.js`/`persistence.test.js` process, so those two
  files were excluded rather than duplicated.
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

## Boundary

This closes lifecycle operation overlap after a timeout or cancellation. It
does not prove Virtualization.framework VM boot, guest credential/filesystem/
network isolation, mount/remount resistance, or production `mac_task_run`
enablement; those remain separately gated.

## Rollback

Revert commit `ea85237`. No persisted schema, wire contract, or capability
advertisement changes are involved.
