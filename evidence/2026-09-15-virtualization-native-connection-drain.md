# Virtualization Guest Native-Connection Drain Evidence

Date: 2026-09-15
Source commit: `d32e33a`
Host: physical Darwin arm64 development host

## Implemented boundary

The Native Virtualization.framework VM handle now tracks every Broker-owned
Virtio exchange. A VM stop closes the tracked connections before requesting
the machine transition, and VM close closes any remaining tracked connection.
Connection callbacks that arrive after shutdown was marked close immediately
and do not enter the active set. The close path snapshots extra Objective-C
references before issuing close calls, then releases them independently from
the operation-owned references; ordinary operation completion removes its
entry before releasing the retained connection.

This gives the host a bounded active-I/O shutdown boundary without exposing a
raw socket or cancellation primitive to MCP arguments.

## Verification

- Native lifecycle build: `npm run build:native:virtualization-guest-lifecycle --workspace @mac-operator/broker` passed with strict warnings and codesign verification.
- Focused VM-native suite: 7/7 pass.
- Complete physical-Darwin regression with install, sandbox, and Keychain gates: 576/576 pass, 0 skipped, 0 failed.
- Typecheck, lint, contract verification, and `git diff --check` pass.

## Remaining boundary

This proves only host-side Native Virtio connection cleanup. It does not prove
a bootable approved guest image, guest filesystem/network/credential/process
isolation, signed attestation production, Developer ID installation, or
`mac_task_run` enablement.

## Rollback

Revert commit `d32e33a`; the prior Native VM lifecycle no longer tracked or
drained active Virtio exchanges on stop/close.
