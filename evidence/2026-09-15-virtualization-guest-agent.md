# Virtualization Guest Agent Protocol Service

Date: 2026-09-15
Source commit: `c8a856e`
Host: physical Darwin arm64 development host
Scope: guest-side protocol service and bounded response binding; no VM boot

## Implementation

`VirtualizationGuestAgent` accepts one bounded JSON frame at a time. It verifies
the domain-separated HMAC request, freshness, guest identity, sandbox/profile
digest, and replay identity before invoking a guest-owned executor. It signs
only a response bound to the admitted request (or a status response bound to
the original task request), enforces the response byte budget, and disposes the
guest-only authentication key on close.

The executor receives the validated envelope containing only guest identity,
profile/task digests, process-tree policy, and budgets. Host paths, executable
names, raw arguments, credentials, and arbitrary commands are not part of the
service API. The agent now tracks each admitted handler with a Broker-owned
abort controller, propagates caller cancellation, aborts active handlers on
close, and checks the close state before signing or publishing a response.

## Verification

Focused guest-agent tests pass 4/4, covering task authentication and replay
denial, authenticated status recovery, response identity tampering, and close
cancellation before signed-success publication. The full physical-Darwin
regression passes 570/570 with 0 skipped tests.

## Boundary

This service is a protocol implementation that a future native
Virtualization.framework/virtio adapter can host. It does not itself create or
boot a VM, provide a guest image, install a guest executable, prove credential
or filesystem/network/process isolation, or enable `mac_task_run`. Those
independent gates and native guest deployment evidence remain open.
