# Task Persistence-Isolation Proof Evidence

Date: 2026-09-15
Source commit: `7a101d9`
Host: physical Darwin arm64 development host

## Implemented boundary

`TaskIsolationProof` now requires an explicit `persistence: "isolated"`
claim in addition to filesystem, network, credential, and process-tree
guarantees. The strict validator rejects a missing or non-isolated persistence
claim, and normalized proofs preserve the field before any task runner can be
considered available.

## Verification

- Task-runner and guest isolation focused tests pass; the negative proof case
  rejects a non-isolated persistence claim.
- Full physical-Darwin regression with install, sandbox, and Keychain gates:
  582/582 pass, 0 skipped, 0 failed.
- `npm run build`, `npm run typecheck`, `npm run lint`,
  `npm run verify:contracts`, and `git diff --check` pass.

## Remaining boundary

This strengthens the proof contract but does not create real persistence,
credential, or VM isolation evidence. `mac_task_run` remains disabled until
the host evidence gate, supported sandbox/VM mechanism, and production
readback are accepted.

## Rollback

Revert `7a101d9`. The previous proof shape remains source-compatible, but it
does not require a distinct host-persistence isolation claim.
