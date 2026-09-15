# Filesystem mutation directory rename race evidence

Date: 2026-09-15
Source commit: `e83bf1e`
Host: physical Darwin arm64 development host

## Boundary

Atomic writes must not follow an authorized child directory after it is
renamed, recreated, or replaced by a symlink to an outside directory. A write
that races with a legitimate rename may resolve through a renamed descriptor,
but it must never modify the outside target.

## Harness

The test creates an authorized `allowed/nested` directory and an outside
directory containing a sentinel `outside/value.txt`. A worker repeatedly
renames `nested` to `nested.moved`, creates an outside symlink at `nested`,
removes the symlink, and restores the renamed directory. The Broker plans one
write before the loop and performs 500 bounded atomic writes while the worker
runs. Successful readbacks must contain `safe` and resolve under the canonical
authorized root; all other outcomes must use the stable policy/precondition
errors. The outside sentinel is checked unchanged after the worker stops.

## Verification

- Filesystem inspector suite passes 34/34, including read and atomic-write
  directory rename/replacement races.
- The non-overlapping package regression passes 511 total (505 pass,
  6 skipped, 0 fail).
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This adds runtime mutation evidence for descriptor-relative parent opens. It
does not prove physical remount handling, cross-volume identity under mount
replacement, broader resource-exhaustion behavior, or production task-runner
enablement.

## Rollback

Revert commit `e83bf1e`. No MCP wire schema or persisted ledger format changes
are introduced.
