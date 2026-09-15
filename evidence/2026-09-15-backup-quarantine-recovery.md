# Backup Quarantine Recovery Evidence

- Source revision: `38c5381`
- Date: 2026-09-15
- Scope: Broker encrypted-backup cleanup quarantine recovery

## Decision

`pruneBrokerBackups` now scans a bounded set of strictly named Broker backup
quarantine artifacts. Recent artifacts are left untouched because an active
cleanup may still own them; stale artifacts are validated as owner-only regular
files and removed through the existing device/inode-fenced cleanup primitive.
Unexpected types, ownership, modes, or counts fail closed. The scan only
accepts quarantine names emitted for recognized backup or backup-temporary
files, so it does not perform a broad directory deletion.

## Verification

- `npm run build`: passed, including native artifacts and TypeScript.
- `npm run lint`: passed across 655 tracked files.
- `npm run typecheck`: passed.
- `git diff --check`: passed.
- Dedicated backup-quarantine regression: 1 passed, 0 failed.
- Physical temporary-directory probe confirmed a stale quarantine is removed
  and no quarantine artifact remains.

The long-running Broker/Persistence and helper IPC test processes were left
untouched. Orphan recovery for native filesystem-unlink, IPC socket, service
lock, and audit-anchor artifacts remains open, as do production crash/remount
and installed-service recovery gates.
