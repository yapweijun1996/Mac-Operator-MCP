# Process-Supervisor Startup-Abort Evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: startup ownership-persistence failure; no production capability enablement

## Commands

```text
npm run typecheck
npm run build
MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/process-supervisor.test.js packages/broker/dist/sandbox-profile.test.js
MOPS_REAL_SANDBOX=1 npm test
```

## Observed result

- Focused process-supervisor/sandbox suite: 27/27 passed.
- Full real-sandbox suite: 450/451 passed, 0 failed, 1 explicit host-boundary/opt-in skip.
- A real `/bin/sleep` process whose startup ownership callback failed was
  force-terminated; the test waited for the captured PID to disappear and
  confirmed the Supervisor active count returned to zero.

## Boundary

`ProcessSupervisor.run()` invokes the startup ownership callback before adding a
child to `activeRuns`. Any callback failure now kills the detached process
group, samples the native root/descendant identities until they are gone, and
only then returns the original stable error. If the bounded drain cannot be
proved, the Supervisor returns retryable `UNKNOWN_OUTCOME` instead of claiming
that cleanup completed. This closes the cleanup path used by
`SandboxExecTaskRunner` when process-start volume identity verification fails.

## Limitations

This proves bounded startup-abort cleanup on the tested host and does not prove
kernel-held mount namespaces, in-syscall remount resistance, credential-store
isolation, or production sandbox selection. `sandbox-exec` remains deprecated
and `mac_task_run` remains disabled by default.
