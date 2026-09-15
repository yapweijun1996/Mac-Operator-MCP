# Process supervisor early child-event capture evidence

Date: 2026-09-15
Source commit: `efb9d5c`
Host: physical Darwin arm64 development host
Scope: child startup event/output capture and bounded process execution

## Finding

`ProcessSupervisor` spawned a child and then awaited path and ownership checks
before registering `exit`, `close`, and stdout/stderr handlers. A short-lived
child could finish during that gap, losing its output and close event. The
active capacity counter could reach zero while the observer waited until its
timeout, producing an incorrect empty result.

## Implementation

The supervisor now installs a bounded `ChildProcessCapture` immediately after
spawn. It records stdout/stderr up to the request cap, overflow state, spawn
errors, exit identity, and close state. The later observer consumes the
captured snapshot and attaches callbacks for subsequent events, preserving
the existing path-identity, process-tree, cancellation, timeout, and output
limits without exposing unbounded child output.

## Verification

- Process-supervisor tests pass 30/30, including an eight-iteration fast
  `/usr/bin/printf` startup-race regression and the cancellation/capacity test
  that previously failed intermittently.
- The physical-Darwin regression over all non-overlapping test files passes
  485/485 with 0 skipped tests. The repository already had a separate
  long-running `broker.test.js`/`persistence.test.js` process, so those two
  files were excluded from this run rather than duplicated.
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

## Boundary

This closes the observer registration race and keeps output/capacity results
bounded. It does not prove kernel-held descriptor/fexec atomicity, remount
resistance, or production task-runner isolation; those remain separate gates.

## Rollback

Revert commit `efb9d5c`. No persisted schema, wire contract, or MCP capability
advertisement changes are involved.
