# Virtualization Guest Lifecycle Evidence

Date: 2026-09-15
Host: physical Darwin arm64 development host
Implementation commit: `042517a`

## Scope

`VirtualizationGuestVmLifecycle` adds the Broker-owned lifecycle boundary for a
future native `Virtualization.framework` adapter. The state machine is
disabled unless the host evidence gate, expected immutable guest identity, and
an available adapter all match. Start, stop, and status operations are
serialized, bounded by caller cancellation and deadlines, and validate guest
identity plus boot ID before changing state. Failed or ambiguous operations
remain `unknown`; recovery requires a fresh status readback. Close drains an
active VM through the same guarded stop path and rejects new work.

The adapter interface is intentionally a seam. This implementation does not
boot a VM, provide a virtio server, install a guest image, or claim filesystem,
network, credential, or process isolation. `mac_task_run` remains disabled.

## Verification

Focused lifecycle tests: 5/5 pass.

Full physical-Darwin regression:

```text
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
tests 547
pass 547
fail 0
cancelled 0
skipped 0
```

Static checks: `npm run typecheck` and `npm run lint` pass.

## Remaining release evidence

An independently reviewed native adapter must still demonstrate real VM boot
and shutdown, authenticated virtio guest serving, signed attestation
production, and independent filesystem/network/credential/process isolation
on the target Mac before the lifecycle can be enabled or the capability
release gate can close.
