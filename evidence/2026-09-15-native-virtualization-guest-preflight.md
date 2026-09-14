# Native Virtualization Guest Preflight

Date: 2026-09-15
Source commit: `7de8385`
Host: physical Darwin arm64 development host
Scope: native image/configuration preflight only; no VM boot or capability enablement

## Commands

```text
npm run build:native:virtualization-guest --workspace @mac-operator/broker
npm run build
node --test packages/broker/dist/virtualization-guest-native.test.js
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
```

## Observed result

The protected `virtualization_guest.node` artifact loads through a canonical,
owner-only, size-bounded and device/inode/digest-stable path. Its N-API
`inspectGuestConfiguration` entry point opens only the startup-bound image,
hashes it through a bounded descriptor, and constructs a
`VZDiskImageStorageDeviceAttachment` with `readOnly=true`. The configuration
contains no network, directory-sharing, serial, or socket devices and never
boots a VM.

The focused native test passes 2/2. A 1 MiB protected raw fixture produces the
following bounded readback (the fixture is intentionally not a bootable guest,
so Virtualization.framework reports `configurationValid=false`):

```json
{"readOnlyAttachment":true,"configurationValid":false,"vmBootAttempted":false,"hostNetworkAttached":false,"hostDirectorySharingAttached":false}
```

The full physical-Darwin regression passes 539/539 with 0 skipped tests.

## Boundary and remaining gate

Symlinked, non-canonical, mismatched, changed, foreign-owned, or weakly
protected images fail closed before the Virtualization.framework call. The
artifact is a native preflight seam, not a guest executor: it does not boot a
VM, serve the authenticated guest channel, produce signed guest attestations,
prove guest filesystem/network/process or credential isolation, or enable
`mac_task_run`. Developer ID provenance, notarization, a valid production guest
image, VM lifecycle, and independent isolation evidence remain required.
