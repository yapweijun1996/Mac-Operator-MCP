# Virtualization Per-Task Fence Review — 2026-09-23

Status: SOURCE-LEVEL TASK-LIFECYCLE CANDIDATE IMPLEMENTED. No native VM was
booted and no production task gate changed. See
[`virtualization-task-scoped-lifecycle.md`](2026-09-23-virtualization-task-scoped-lifecycle.md)
for implementation and regression evidence.

## Verified source and platform facts

- The native VM configuration attaches one `VZDiskImageStorageDeviceAttachment`
  with `readOnly:YES`. It configures no network, directory-sharing, or serial
  devices; the only other device is one virtio socket.
- The native stop path closes active virtio connections and calls
  `stopWithCompletionHandler:`. It reports success only when Virtualization.framework
  reports the VM stopped.
- Apple documents `stop` as destructive: it stops a running or paused VM
  without giving the guest a chance to shut down cleanly. This is a stronger
  process-lifetime boundary than sampled host process-group cleanup.
- `VirtualizationGuestProfileExecutor` keeps its bounded task-status ledger in
  an in-memory `Map`. Broker restart recovery later asks the guest for a signed
  status response, so that lookup depends on the guest still retaining its
  ledger entry.
- The physical double-fork/`setsid` probe reproduced a guest-process-tree
  escape on the current App Sandbox helper. Its exact process identity was
  cleaned up by the probe, but only after the executor returned
  `UNKNOWN_OUTCOME`.

Sources: [`virtualization_guest_lifecycle.cc`](../packages/broker/native/virtualization_guest_lifecycle.cc),
[`virtualization-guest-executor.ts`](../packages/broker/src/virtualization-guest-executor.ts),
[`app-sandbox-executor-rerun.md`](2026-09-23-app-sandbox-executor-rerun.md),
[Apple `VZVirtualMachine.stop`](https://developer.apple.com/documentation/virtualization/vzvirtualmachine/stop%28completionhandler%3A%29),
[Apple read-only disk attachment](https://developer.apple.com/documentation/virtualization/vzdiskimagestoragedeviceattachment/isreadonly?language=objc).

## Candidate and unresolved recovery boundary

A task-scoped VM lifecycle is a promising containment candidate: boot the
read-only image for one named task, accept only its authenticated bounded
result, then hard-stop before allowing another task. The Broker now implements
that serialized source-level cycle through one startup-created native handle,
but replaces the underlying `VZVirtualMachine` object before every task after a
confirmed stop. It restores configured virtio listeners and closes prior
connections and pending accepts. The read-only disk and absence of host
directory/network devices reduce guest persistence paths. This remains an
inference, not demonstrated isolation: the current host has no approved
bootable guest image, the native adapter has not booted a VM, and real
task-scoped restart behavior has not been exercised. Reset of all mutable
framework and guest state remains unproven.

Hard-stopping a VM also destroys its in-memory status ledger. The Broker now
durably journals authenticated terminal results before teardown. If transport
fails or the Broker restarts before that journal is written, the Broker cannot
safely recover the result from the stopped guest; the task remains `UNKNOWN`
and is never replayed merely to recover a result.

## Release gate

Keep `mac_task_run` and both VT-SBX gates closed until a bootable, entitled,
reviewed guest demonstrates repeated start/run/hard-stop cycles; an adversarial
double-fork/`setsid` descendant is gone before the next task is admitted;
read-only image and no-host-sharing properties are verified at runtime; and
crash/transport-loss recovery preserves durable terminal results or remains
fail-closed as `UNKNOWN` without replay. The existing App Sandbox escape is
not repaired by this design review.
