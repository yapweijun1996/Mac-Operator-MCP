# System-published guest image evidence

Date: 2026-09-15
Source commits: `e00554c`, `f74e485`
Host: physical Darwin arm64 development host

## Boundary

`VZDiskImageStorageDeviceAttachment` accepts a pathname rather than an
already-open descriptor. A descriptor hash and identity check alone therefore
leave a pathname target-swap window before `initWithURL:` opens the image.

## Implementation

Guest image startup configuration now carries an explicit `publication` mode.
The default `broker-owned` mode remains available for protocol and test
fixtures. The native Virtualization.framework adapter requires
`system-published`: the image and its canonical parent directory must be
root-owned, regular/non-symlink paths with no group/other write bits, and the
image must be readable. Every canonical ancestor is checked; checking only the
direct parent would still allow a writable grandparent to rename the tree. The
same root-owned publication check is enforced in the native C++ `ValidateImage`
boundary after canonicalization and before attachment. Later lifecycle
operations continue to re-read the bound device/inode/size/digest.

This blocks replacement by an unprivileged same-user process. Root-owned host
rotation remains an administrative action and is detected by subsequent
identity readback; no public Darwin atomic descriptor-to-image attachment API
was assumed.

## Verification

- Focused image/native suites pass 12/12.
- The non-overlapping package regression passes 508 total (502 pass,
  6 skipped, 0 fail).
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This narrows the native image target-swap boundary but does not prove a
bootable production VM image, guest attestation producer, credential or
filesystem isolation, remount behavior, or `mac_task_run` enablement.

## Rollback

Revert commits `f74e485` and `e00554c`. No persisted schema or MCP wire
contract changes are introduced; startup configurations using the default
publication mode remain protocol/test-only and are rejected by the enabled
native adapter.
