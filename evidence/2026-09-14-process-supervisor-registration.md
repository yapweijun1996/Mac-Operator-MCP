# Process supervisor registration evidence

Date: 2026-09-14
Host: Darwin arm64 development Mac
Scope: active-run lifecycle and synchronous ownership failure

## Evidence

- `npm run build` passed.
- `node --test packages/broker/dist/process-supervisor.test.js` passed 14/14.
- The regression test uses a real `/bin/sleep` process and throws from the
  first ownership callback; the result is `UNKNOWN_OUTCOME`, capacity returns
  to zero, and `close()` completes and remains idempotent.

## Boundary covered

`ProcessSupervisor.run()` registers the `ActiveProcessRun` before invoking the
observation loop. If initial ownership persistence fails synchronously, the
termination path can call `release()` and remove the same run from
`activeRuns`. This preserves the invariant that `activeCount() === 0` implies
no close-time drain promise is waiting on an already-finished process.

The result remains conservative `UNKNOWN_OUTCOME`; the fix changes only
lifecycle bookkeeping and does not infer task success from the failed proof.

## Not established

This evidence does not establish production task-runner enablement, stronger
than `sandbox-exec` isolation, post-snapshot descendant capture, or crash
actor attribution.
