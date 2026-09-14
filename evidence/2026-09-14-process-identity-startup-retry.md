# Process-Identity Startup-Retry Evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: bounded native PID/start-time capture at child startup; no production capability enablement

## Commands

```text
npm run typecheck
npm run build
MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/process-supervisor.test.js packages/broker/dist/sandbox-profile.test.js
MOPS_REAL_SANDBOX=1 npm test
MOPS_REAL_SANDBOX=1 npm test
```

## Observed result

- Focused process-supervisor/sandbox suite: 29/29 passed.
- Two consecutive full real-sandbox runs: each 452/453 passed, 0 failed,
  1 explicit host-boundary/opt-in skip.
- The startup path tolerated a transient native process-table visibility delay
  without weakening the required PID/start-time identity or ownership callback.

## Boundary

When a child is spawned, `ProcessSupervisor` retries native root identity capture
for at most 100ms at 1ms polling intervals. If the child exits before identity
becomes observable, the run remains fail-closed and bounded startup cleanup is
attempted; no synthetic identity is created. Once captured, the exact
PID/start-time identity is still required for ownership persistence and later
process-group signalling.

## Limitations

This closes a short startup-observation race on the tested host. It does not
provide kernel-held mount namespaces, in-syscall remount resistance,
credential-store isolation, post-snapshot descendant ownership, or production
sandbox selection. `mac_task_run` remains disabled by default.
