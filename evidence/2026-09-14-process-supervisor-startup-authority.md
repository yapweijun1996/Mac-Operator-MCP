# Process-Supervisor Startup-Authority Evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: authority loss during child startup; no production capability enablement

## Commands

```text
npm run typecheck
npm run build
MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/process-supervisor.test.js
MOPS_REAL_SANDBOX=1 npm test
```

## Observed result

- Focused process-supervisor suite: 17/17 passed.
- Full real-sandbox suite: 454/455 passed, 0 failed, 1 explicit host-boundary/opt-in skip.
- A real `/bin/sleep` child closed its Supervisor authority from the startup
  ownership callback. The Supervisor killed the unowned process, waited for its
  PID to disappear, returned `CANCELLED`, and left active capacity at zero.

## Boundary

After startup identity/ownership callbacks and before registering an active
run, `ProcessSupervisor` checks both its close state and the request's
cancellation predicate. Authority loss takes the same bounded process-group
drain path as other startup failures; an unproven drain returns retryable
`UNKNOWN_OUTCOME` rather than allowing the child to proceed. If the native
process-tree observer is unavailable or fails, the supervisor does not infer
that group disappearance means descendants were drained.

## Limitations

This proves a startup kill-switch race on the tested host. It does not prove
kernel-held mount namespaces, in-syscall remount resistance, credential-store
isolation, or production sandbox selection. `mac_task_run` remains disabled by
default.
