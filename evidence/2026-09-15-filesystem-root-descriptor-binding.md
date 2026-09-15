# Filesystem root-descriptor binding evidence

Date: 2026-09-15
Source commit: `6fb5372`
Host: physical Darwin arm64 development host

## Boundary

The native filesystem adapter already pinned the authorized root with a
descriptor, but several target operations still opened an absolute pathname.
That left a root-directory rename/replacement window even when final target
identity was rechecked.

## Implementation

Metadata, directory listing, content read, and hashing now canonicalize only
the target parent (preserving a final symlink for no-follow operations), derive
a traversal-free relative path, and open it with `openat(root_descriptor, ...)`.
Atomic writes and temporary cleanup likewise open the canonical parent through
the pinned root descriptor before using `openat`/`fstatat`/`renameat`/`unlinkat`.
Relative-path conversion rejects `.`/`..`, empty components, and lexical
escapes. Descriptor path and filesystem identity checks remain in place after
open and after I/O.

## Verification

- Filesystem inspector suite passes 32/32, including symlink target-swap and
  create-only race coverage.
- The non-overlapping package regression passes 509 total (503 pass,
  6 skipped, 0 fail).
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This closes the absolute-open root replacement window for the native adapter,
but physical remount identity, cross-volume policy, broader device coverage,
and production-scale resource exhaustion remain open. It is not proof of
kernel-held mount namespaces or unrestricted mutation safety.

## Rollback

Revert commit `6fb5372`. No MCP wire schema or persisted ledger format changes
are introduced.
