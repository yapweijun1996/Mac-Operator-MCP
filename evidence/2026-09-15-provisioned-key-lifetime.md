# Provisioned Key Lifetime Evidence

- Source revision: `5f4bc61`
- Date: 2026-09-15
- Scope: Broker file-backed authentication-key provisioning

## Decision

The random key used during file provisioning is now cleared in a `finally`
block after its digest is returned or provisioning fails. Cleanup after a
write/sync failure uses the created file's device/inode/owner/mode/size/time
identity, moves that exact file to a private quarantine, rechecks it, and only
then removes it. A replacement pathname is not unlinked.

## Verification

- `npm run build`: passed, including native artifacts and TypeScript.
- `npm run lint`: passed across 651 tracked files.
- `npm run typecheck`: passed.
- `git diff --check`: passed.
- Focused credentials and keyring suite: 28 total, 27 passed, 1 explicit
  physical-Keychain skip, 0 failed.

The long-running Broker/Persistence and helper IPC test processes were left
untouched. Production Keychain distribution, crash-recovery readback, and
release enablement remain open.
