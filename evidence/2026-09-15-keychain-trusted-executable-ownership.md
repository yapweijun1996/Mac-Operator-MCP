# Keychain Trusted Executable Ownership Evidence

- Source revisions: `7f725bf`, `0c21edb`
- Date: 2026-09-15
- Scope: Broker and root-helper Keychain ACL executable binding

## Change

Keychain ACL checks now bind the trusted executable to the current process
owner in both layers. The TypeScript boundary rejects missing POSIX identity,
foreign ownership, writable modes, symlinks, and non-canonical paths before
native access. The macOS native adapter repeats the owner check with `geteuid()`
and retains the canonical-path double-read around
`SecTrustedApplicationCreateFromPath`. Its before/after identity fence also
includes UID and mode, so permission or ownership changes during that native
call are treated as a target change. This keeps a root helper from accepting a
user-owned executable path and keeps the unprivileged Broker from binding a
credential to an external owner.

## Verification

- `npm run build`: passed, including the macOS native adapter and code-sign
  verification step.
- Focused peer/credentials/helper suites with `MOPS_REAL_KEYCHAIN=1`: 30/30
  passed, 0 skipped, 0 failed.
- The physical non-overlapping package regression with all three explicit
  gates (`MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1 MOPS_REAL_SANDBOX=1`):
  618/618 passed, 0 skipped, 0 failed.
- `npm run typecheck`, `npm run lint`, and `git diff --check`: passed.
- The existing long-running Broker/Persistence test process was not restarted.

The physical run proves the temporary Keychain ACL lifecycle and the new
owner/mode/symlink boundary on this Mac. It does not establish Developer ID
provenance or production helper enablement.
