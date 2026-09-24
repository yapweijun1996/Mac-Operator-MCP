# LaunchAgent deployment journal

## Decision

The owner-invoked LaunchAgent controller now persists a small deployment
journal beneath the planned owner-only install root. The journal is not an
audit log and contains no keys, command output, or service payloads. It binds
the exact primary/inverse manifest digest, operation, dependency order,
completed-component prefix, transaction identity, and recovery state.

The controller writes `in-progress` before host mutation, `applied` only after
the coordinator returns, `recovered` after a completed inverse recovery, and
`recovery-required` when inverse recovery fails. A hard process crash can
therefore leave a durable `in-progress` marker for the next readback instead
of silently losing the controller state. Readback rejects an absent, stale,
malformed, or recovery-required journal before claiming success.

## Protection

- Parent directory must already be an owner-only regular directory.
- Journal files are owner-only regular files with a bounded size.
- Reads use `O_NOFOLLOW` and compare descriptor identity before and after the
  read.
- Writes use an `O_EXCL` same-directory temporary, `fsync`, mode `0600`,
  atomic rename, directory `fsync`, and publication readback.
- The record uses strict JSON parsing, exact fields, bounded identifiers, a
  fixed component order, and a SHA-256 manifest digest.

## Evidence

- Deployment journal unit coverage: 4/4 passed, including a symlinked-ancestor
  negative that rejects a substituted install-root chain.
- LaunchAgent handoff coverage: 5/5 passed.
- Full repository regression: 1,179 total, 1,164 passed, 15 skipped, 0 failed.
- `npm run typecheck` passed.
- `node --check scripts/apply-macos-launchagents.mjs` passed.
- No host LaunchAgent, privilege, or permission state was changed.

## Limits and rollback

This is durable controller-state evidence, not proof of a persistent
production installation or physical crash recovery on the target Mac. The
install root must already exist with owner-only permissions. Removing the
journal module, controller calls, focused tests, documentation, and this
evidence file restores the prior in-memory coordinator behavior; it does not
remove any existing LaunchAgent because this change performs no host mutation.
