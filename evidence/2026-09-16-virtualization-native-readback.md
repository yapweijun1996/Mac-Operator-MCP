# Virtualization.framework native adapter readback

- Date: 2026-09-16
- Source revision: `cb0e59e`
- Host: Mac mini, macOS `26.2` build `25C56`, arm64, Node `v25.5.0`
- Scope: native guest image/configuration and lifecycle/channel boundaries

## Verification

Commands run on the physical Darwin host:

```text
node --test --test-timeout=120000 packages/broker/dist/virtualization-guest-native.test.js packages/broker/dist/virtualization-guest-vm-native.test.js
npm test
```

The focused native Virtualization suite passes 12/12. It covers protected
image/configuration readback, symlink and digest mismatch rejection, native
artifact identity, retained-handle close fencing, disabled startup gates,
invalid VM configuration handling, broker-owned image rejection, bounded
lifecycle result parsing, virtio frame forwarding, listener adaptation, and
post-cancellation connection cleanup.

The complete repository regression passes 876/876 with 14 explicit skips
(890 total), 0 failures. The native artifact performs read-only image
preflight and configures no host network, directory-sharing, serial, or
socket devices in the readback path. No VM boot, guest filesystem access,
guest process execution, or production capability was performed.

## Limit

This is current-revision native adapter evidence only. It does not prove a
bootable approved image, guest-side attestation production, guest
filesystem/network/credential/process isolation, crash/restart recovery, or
`mac_task_run` enablement. The existing publication, signing, entitlement,
and independent release gates remain open.
