# Process Startup Admission Evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: Broker-owned child-process admission and shutdown; no capability enablement

## Boundary

`ProcessSupervisor` now accounts for a child from the moment its bounded
request has passed validation and admission begins. A startup remains in the
pending set while the detached child is spawned, its Darwin PID/start-time is
observed, and any `onStarted` ownership persistence callback completes. Pending
starts count against the shared `maxConcurrent` limit. If the Broker closes in
that window, the close promise waits for the startup's verified abort and
cleanup instead of returning while an untracked child can still be starting.
The native Darwin identity readback also includes the actual process-group ID;
startup requires it to match the detached child PID, and every later root
identity check fails closed if the group changes.
For the validated `sandbox-exec` single-process profile, ownership snapshots
carry the Broker-owned `sandbox-exec-no-fork-v1` proof. Recovery may report a
dead root as `PROCESS_ABSENT` only when that proof is present, the snapshot has
no descendants, and the original process group is gone. Generic or observed-
descendant snapshots remain `UNKNOWN` after root exit because they cannot prove
that a post-snapshot `setsid` escape did not occur.

## Verification

```text
npm run typecheck
npm run build
node --test packages/broker/dist/process-supervisor.test.js
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
```

Observed result: focused ProcessSupervisor suite passed 23/23 with zero
failures. The new Darwin regression calls `close()` from the ownership-start
callback, requires the run to fail closed as `CANCELLED`, waits for the same
close promise, and confirms that no active process capacity remains.
The complete real-host regression passed 488/488 with the temporary
LaunchAgent smoke enabled and no skipped tests.

## Limits

This closes an in-process admission/ shutdown race; it does not prove kernel
resource quotas, post-snapshot descendant attribution, crashed-Broker process
ownership, credential isolation, or production task-runner enablement.
