# Process-Tree PID-Reuse Evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: Broker-owned process identity tracking; no task capability enablement

## Commands

```text
npm run typecheck
npm run build
node --test packages/broker/dist/process-supervisor.test.js packages/broker/dist/sandbox-profile.test.js packages/broker/dist/task-runner.test.js
```

## Observed result

- The focused process/sandbox/task-runner boundary suite passes its unit and
  host-gated cases; the new PID-reuse regression passes.
- The full `MOPS_REAL_SANDBOX=1 npm test` run reports 467 tests: 466 passed,
  0 failed, and 1 explicit opt-in install test skipped.
- A later descendant snapshot with the same PID and a different start-time is
  treated as an ownership failure. The tracker stops accepting the snapshot,
  refuses further descendant signalling, and preserves an unresolved outcome.

## Boundary

Descendant ownership is keyed by `(pid, startTimeMicros)`, not PID alone. A PID
replacement is therefore a target-swap event: the ProcessSupervisor marks its
native observation failed and the Broker can only retain `UNKNOWN_OUTCOME` until
an independent recovery path proves termination.

## Limitations

The regression uses a deterministic identity-replacement fixture rather than
waiting for operating-system PID reuse. Descendants created after the final
observation, post-snapshot `setsid` escapes, and kernel-level process-tree
containment remain open.
