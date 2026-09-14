# Audit-anchor cross-process lock evidence

Date: 2026-09-14
Status: focused implementation and boundary evidence; not an external immutable log

## Boundary

`AuditAnchorManager` now takes an owner-only, atomically-created sibling lock
before every sidecar read or publication. The lock is held across validation,
readback, atomic rename, and directory `fsync`, and release rechecks the lock
device/inode before unlinking it. A pre-existing lock is never force-removed;
startup or publication fails closed and requires reviewed operator recovery.

This closes the sidecar's same-target cross-process race without treating a
stale lock as proof that another process is gone. The Broker's separate
single-instance lock remains the normal service-level exclusion.

## Verification

- Focused audit-anchor and persistence tests: 44/44 passed.
- The lock test creates a protected sibling lock, confirms publication is
  rejected, removes it through the test owner, then confirms normal publish and
  verify still work.
- `git diff --check` passed for the implementation slice.

## Limits

This is local mutual exclusion and fail-closed recovery, not a kernel-backed
lease or an external immutable audit anchor. A crash can leave a lock that
requires an authenticated operator to inspect and remove; no automatic stale
lock reclamation is attempted because PID reuse and target substitution would
make that unsafe.
