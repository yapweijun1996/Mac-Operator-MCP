# Backup Cleanup Target-Fence Evidence

- Source revision: `f25c900`
- Date: 2026-09-15
- Scope: Broker persistence backup and temporary-file cleanup

## Decision

Backup retention, stale-temporary cleanup, restore cleanup, encrypted-source
publication cleanup, and decrypt-failure cleanup now remove files through one
protected-file primitive. It rechecks the expected owner/mode/device/inode/
size/mtime identity, atomically moves the selected pathname to a private
same-directory quarantine, verifies the quarantined inode, then deletes it and
syncs the directory. Failures attempt non-overwriting hard-link restoration;
the quarantine remains when restoration cannot be proven safe.

## Verification

- `npm run build`: passed, including native artifacts and TypeScript.
- `npm run lint`: passed.
- `npm run typecheck`: passed.
- `git diff --check`: passed.
- Physical temp-root backup probe created three encrypted backups, pruned one,
  retained two, and left no quarantine artifacts.

The long-running Broker/Persistence and helper IPC test processes were left
untouched. A fresh full persistence regression and crash recovery of an orphan
cleanup quarantine remain open.
