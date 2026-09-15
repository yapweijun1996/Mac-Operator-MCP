# Filesystem Unlink Orphan-Recovery Evidence

- Source revision: pending local commit
- Date: 2026-09-15
- Scope: Native filesystem unlink quarantine naming and explicit orphan recovery

## Implementation

`unlinkFileWithinRoot` now names each private quarantine with a creation
timestamp, random nonce, and SHA-256 fingerprint of the original basename.
The fingerprint is not a permission input; it only gives recovery a bounded
candidate set without retaining the original path in the filename.

`recoverUnlinkFileWithinRoot` is an explicit, non-automatic recovery boundary.
It reopens the authorized root and canonical parent with `O_NOFOLLOW`, checks
the local volume and parent identity, scans only the matching quarantine-name
shape, and requires a regular single-link artifact whose device/inode exactly
match the caller's recorded precondition. Recent artifacts remain untouched;
multiple or mixed-age matches return `ambiguous`; stale artifacts are removed
with `unlinkat` plus parent `fsync`, followed by an absence readback.

The TypeScript Broker boundary independently validates content-path policy,
root/deny-zone containment, age bounds (1 second through 7 days), exact result
shape, and recovery identity. No automatic startup sweep was added because a
quarantine without a persisted mutation record must not be guessed into a
mutation.

## Verification

- `npm run build`: passed, including the Darwin native adapter.
- `npm run lint`: passed across 659 tracked files.
- `npm run typecheck`: passed.
- `git diff --check`: passed.
- Dedicated filesystem inspector suite: 36 passed, 0 failed.
- Physical Darwin probe created stale and recent native-style quarantines;
  stale identity-bound recovery removed only the stale artifact, recent
  recovery returned `not_stale`, and a different basename returned `absent`.

Production crash/remount evidence, Developer ID signing, and persisted Job
integration remain open release gates. The existing long-running Broker and
helper IPC suites were left untouched.
