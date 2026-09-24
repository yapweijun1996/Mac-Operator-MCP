# Observed process-group census expansion

## Decision

The Broker process supervisor now retains a bounded set of process groups that
were observed through an owned process-group leader. Each strict lifecycle
sample reads both the root descendant tree and those retained groups. This
covers the concrete escape window where an observed child creates a new
session, forks a grandchild, exits, and leaves the grandchild running after
the root exits. Malformed or truncated native observations, and more than 256
tracked groups, fail closed.

The supervisor does not adopt an arbitrary pre-existing group merely because
a task joined it. Only a group whose leader was itself observed is added to the
census, and descendant signals remain identity-bound.

## Evidence

- Source revision: `540541cb44a290ea512070796004e9129ff0ab36` with an
  uncommitted worktree; the worktree was already dirty before this change.
- Host profile: macOS `26.2`, Darwin `arm64`, UID `501`.
- `packages/broker/src/process-supervisor.ts` samples the root descendant
  tree plus the bounded observed-group set and rejects census overflow.
- `packages/broker/src/process-supervisor.test.ts` adds a real Darwin strict
  exit test for a detached process group whose leader exits before the root.
- ProcessSupervisor Darwin regression: 46 passed, 0 failed.
- Full repository regression: 1,166 total, 1,151 passed, 15 skipped, 0
  failed.

## Limits

This is bounded local process-observer evidence, not proof of arbitrary
post-snapshot process creation, kernel isolation, physical cleanup, production
task-runner isolation, or installed operator recovery. Those remain open under
VT-SBX-01/02, VT-REL-01, VT-REV-01, and VT-OPS-01.
