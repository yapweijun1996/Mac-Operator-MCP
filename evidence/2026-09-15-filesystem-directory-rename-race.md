# Filesystem directory rename race evidence

Date: 2026-09-15
Source commit: `7fe59fd`
Host: physical Darwin arm64 development host

## Boundary

The native filesystem boundary must remain safe while a directory below an
authorized root is renamed, recreated, or temporarily replaced by a symlink
to an outside directory. A successful read may observe the original directory
under its renamed canonical path, but it must never return outside content.

## Harness

The test creates an authorized `allowed/nested/value.txt` containing `inside`
and an outside directory containing `outside`. A worker repeatedly renames
`nested` to `nested.moved`, creates an outside symlink at `nested`, removes the
symlink, and restores the renamed directory. The Broker plans one content read
before the loop and performs 2,000 bounded reads while the worker runs.
Successful reads must contain `inside` and resolve under the canonical
authorized root. Native failures are accepted only through the stable
fail-closed escape error.

## Verification

- Filesystem inspector suite passes 33/33, including the directory
  rename/replacement race.
- The non-overlapping package regression passes 510 total (504 pass,
  6 skipped, 0 fail).
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This provides runtime directory create/rename evidence for the descriptor-
relative adapter. It does not prove physical remount handling, cross-volume
identity under mount replacement, broader rename/resource-exhaustion coverage,
or production task-runner enablement.

## Rollback

Revert commit `7fe59fd`. No MCP wire schema or persisted ledger format changes
are introduced.
