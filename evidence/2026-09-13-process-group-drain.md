# Process group drain evidence

Date: 2026-09-13
Host: macOS arm64 development host
Scope: disabled local ProcessSupervisor and synthetic child-process fixtures; no production task runner or user data

## Boundary exercised

The disabled ProcessSupervisor launches a Broker-resolved executable in a
detached POSIX process group. The direct child exit is not treated as complete
termination evidence while the process group still exists. Normal completion,
timeout, cancellation, output overflow, and direct-child orphan detection use
bounded `kill(-pgid, 0)` polling after TERM/KILL escalation. A group that does
not disappear before the bounded deadline returns `UNKNOWN_OUTCOME`; the
capacity slot stays occupied and an unref'd reaper releases it only after group
disappearance.

## Tests

- Normal bounded execution reports observed termination only after the group is
  gone.
- Timeout and output overflow terminate the detached group and pass drain
  readback before returning.
- Cancellation kills a shell-spawned descendant and releases capacity after
  the group disappears.
- The full suite passes with 247 tests; `npm run typecheck` passes.

## Limits and next gate

This is controlled host evidence for a process-group readback boundary. It does
not prove that descendants cannot call `setsid`, that a macOS sandbox enforces
filesystem/network rules, that credentials are isolated, or that a production
task runner is safe to enable. Those remain blocked by MOP-086/MOP-045 and
VT-SBX-01/VT-SBX-02.
