# Persistent host-task quarantine for unresolved execution outcomes

Date: 2026-09-24

## Change

The Broker now treats an unknown host `mac_task_run` Job as a durable admission
quarantine, not merely an in-memory Runner failure. The host Runner is disabled
and closed when the quarantine is observed, and a runtime `UNKNOWN_OUTCOME`
immediately poisons/closes that Runner. Startup process recovery now considers
all unresolved unknown host task Jobs with process identity, independent of the
reason the Job became unknown.

Only an exact `sandbox-exec-no-fork-v1` process proof with an empty descendant
list and a durable recovery completion audit (`PROCESS_ABSENT` or
`PROCESS_DRAINED`) clears the host admission gate. Missing/malformed identity,
incomplete recovery, and BrokerStore read failure remain fail-closed.
Virtualization guest Jobs are excluded from this host gate and continue through
their separate authenticated guest recovery path. No schema migration was
needed.

## Verification

- Focused persistence and Broker quarantine tests: 5 passed, 0 failed.
- `npm test`: 1,217 passed, 16 skipped, 0 failed (1,233 tests).
- `npm run lint`: passed.
- `npm run verify:docs`: passed.
- `npm run verify:matrix`: passed.
- `npm run verify:process-boundaries`: passed with no unreviewed entries.
- `git diff --check`: passed.

## Limits

This is a restart-safe admission guard; it does not contain a process that has
already escaped. The physical App Sandbox double-fork/`setsid` probe previously
confirmed that an escaped child can survive an `UNKNOWN_OUTCOME`. That boundary
remains unresolved, public `mac_task_run` stays gated, and overall completion
remains 92%. Production signing, Accessibility authorization, installed
service readback, and the production acceptance record remain outstanding.
