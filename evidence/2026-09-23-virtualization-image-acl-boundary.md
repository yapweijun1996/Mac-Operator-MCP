# Virtualization Guest Image ACL Boundary

## Finding

The system-published guest-image preflight already required a root-owned image,
non-writable POSIX mode bits, and root-owned protected directories. macOS
extended ACL entries are a separate permission layer, however, and can grant a
user write access even when those mode-bit checks pass. The Virtualization
framework later opens the image by pathname, so publication checks must reject
an ACL that weakens that path boundary.

## Change

The shared native `hasExtendedAclEntries` primitive accepts regular files as
well as directories, while continuing to reject symlinks and other file types.
Both the TypeScript loader and the native `createGuestVm`/image-publication
boundary fail closed if ACL readback fails or if the image or any canonical
ancestor has an extended ACL. This prevents an internal caller from relying
only on the TypeScript preflight. `broker-owned` fixtures and their existing
policy are unchanged.

The Darwin regression uses a temporary file and directory, adds an allow-write
ACL entry with fixed `/bin/chmod` argv (no shell), and confirms the native probe
detects both. The focused image/lifecycle suites pass 16/16. The temporary tree
is removed by the test. Full `npm test` passes 1,209 tests, skips 16, and fails
0.

## Limits

This is host-side path-integrity evidence, not proof of VM boot, guest-state
reset, production signing, service installation, or task isolation. No guest
image was acquired and no production host policy was changed. Public
`mac_task_run` and VT-SBX gates remain closed; overall completion remains 92%.

Apple documents ACLs as an additional filesystem permission mechanism in its
[File System Programming Guide](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
and documents `acl_get_file()` readback in its
[ACL man page](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/acl_get.3.html).
