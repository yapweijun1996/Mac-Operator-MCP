# Process-Supervisor Crash Attribution Evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: unexpected child signal termination; no production capability enablement

## Commands

```text
npm run typecheck
npm run build
MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/process-supervisor.test.js
MOPS_REAL_SANDBOX=1 npm test
```

## Observed result

- Focused process-supervisor suite: 16/16 passed.
- Full real-sandbox suite: 451/452 passed, 0 failed, 1 explicit host-boundary/opt-in skip.
- A real `/usr/bin/python3` child that terminated itself with `SIGKILL`
  returned `state: failed`, `resultClass: EXECUTION_FAILED`, `exitCode: null`,
  `signal: SIGKILL`, and `terminationObserved: true`.

## Boundary

`ProcessSupervisor` now treats any non-null termination signal as an abnormal
exit. The result cannot be mapped to `SUCCEEDED` merely because the OS supplied
no numeric exit code; the Broker therefore cannot publish a successful task
readback after an observed crash signal.

## Limitations

This proves signal/exit attribution for a bounded child process. It does not
prove which actor caused a mutation before the crash, filesystem durability,
remount resistance, credential-store isolation, or production sandbox
selection. Mutation Jobs must still retain `UNKNOWN` when their completion or
actor attribution is unresolved, and `mac_task_run` remains disabled by
default.
