# Task Crash Unknown-Outcome Evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: Broker task result mapping after an observed child crash; no production capability enablement

## Commands

```text
npm run typecheck
npm run build
MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/process-supervisor.test.js packages/broker/dist/sandbox-profile.test.js packages/broker/dist/task-runner.test.js
MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/broker.test.js packages/broker/dist/process-supervisor.test.js packages/broker/dist/sandbox-profile.test.js packages/broker/dist/task-runner.test.js
MOPS_REAL_SANDBOX=1 npm test
```

## Observed result

- Focused Broker/process-supervisor/sandbox/task-runner suite: 106/106 passed.
- Full real-sandbox suite: 453/454 passed, 0 failed, 1 explicit host-boundary/opt-in skip.
- A `SandboxExecTaskRunner` result with `EXECUTION_FAILED` plus `SIGKILL`
  is mapped to `state: unknown`, `resultClass: UNKNOWN_OUTCOME`, and unknown
  verification with a side-effect warning. Explicit timeout, cancellation, and
  output-limit classes retain their dedicated bounded outcomes.
- The real Broker integration returns `UNKNOWN_OUTCOME` after a profile-owned
  child self-terminates and leaves both the Request and Job unresolved.

## Boundary

The process boundary reports an observed signal as an execution failure, while
the task boundary treats that signal as an unresolved task outcome. This keeps
the Broker Job in `UNKNOWN` when a writes-local task may have changed an
authorized root before crashing; process-group drain alone is not actor or
postcondition attribution.

## Limitations

This is controlled crash-attribution evidence, not exhaustive arbitrary
instruction crash coverage. It does not prove filesystem durability,
remount resistance, credential-store isolation, or production sandbox
selection. `mac_task_run` remains disabled by default.
