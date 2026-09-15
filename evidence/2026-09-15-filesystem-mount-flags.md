# Filesystem mount-flag identity binding

Date: 2026-09-15
Source revision: `eaca6c6`
Host: Darwin 25.2.0, arm64, Node v25.5.0

## Result

The native filesystem boundary now treats mount flags as part of the
filesystem identity. Descriptor operations require `fstatfs` to match the
authorized `f_fsid`, filesystem type, and `f_flags`; storage-volume IDs also
include the flags value. A remount that changes read-only, no-exec, or another
reported mount flag therefore fails the existing root/target identity checks
instead of being silently accepted as the same volume.

This is a stronger remount-change detector, not a kernel mount namespace or an
in-syscall remount proof. A remount that preserves every reported identity
field, or a swap that occurs after the final check, remains outside this
boundary and keeps the physical remount gate open.

## Host readback

The rebuilt native adapter returned the bounded volume identity for the
canonical temporary volume with the new format:

```text
id=dev:16777234:fsid:16777234:26:flags:76583040
name=apfs
mountPath=/System/Volumes/Data
```

## Verification

```text
node --test --test-concurrency=1 \
  packages/broker/dist/filesystem-inspector.test.js \
  packages/broker/dist/filesystem-executor.test.js
tests 38
pass 38
fail 0

npm run typecheck
exit 0

npm run lint
Style check passed for 671 tracked files.
```

The source-level native boundary test also asserts the `f_flags` comparison
and the flags-bearing identity format. No mount, remount, or other host
configuration mutation was performed.

## Rollback

Revert commit `eaca6c6`; no runtime or host state needs restoration.
