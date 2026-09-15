# Filesystem Unlink Target-Swap Evidence

- Source revision: `a6971fc`
- Date: 2026-09-15
- Scope: descriptor-relative removal of Broker-authorized regular files

## Decision

Native unlink no longer removes an authorized pathname directly after a single
`fstatat` check. It first atomically moves the pathname to a private,
same-directory quarantine using `renameatx_np(..., RENAME_EXCL)`, rechecks the
device/inode/type/link-count identity, and deletes only the verified quarantine
inode. If the identity changed, `linkat` restores that exact artifact without
overwriting a concurrent pathname occupant; a failed restoration leaves the
quarantine for explicit operator recovery. This prevents a target swap from
turning an expected-file deletion into deletion of a different file.

## Verification

- `npm run build`: passed, including native artifacts and TypeScript.
- `npm run lint`: passed.
- `npm run typecheck`: passed.
- `git diff --check`: passed.
- `node --test --test-timeout=120000 packages/broker/dist/filesystem-inspector.test.js packages/broker/dist/filesystem-patch.test.js`: 40 passed, 0 failed.
- Physical temp-root unlink probe removed one regular file and confirmed the
  target was absent with the returned device/inode identity.
- Boundary source assertions require quarantine rename and non-overwriting
  restoration primitives in the native adapter.

The long-running Broker/Persistence and helper IPC test processes were left
untouched. Crash recovery of an orphaned unlink quarantine and production
packaging remain open release work.
