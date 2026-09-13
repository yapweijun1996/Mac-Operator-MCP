# Process group drain evidence

Date: 2026-09-13
Host: Mac mini M4, macOS 26.2, arm64 development host
Source commits: `db37a64` (`feat: track detached task descendants`) and
`4621635` (`test: stabilize detached descendant fixture`)
Scope: disabled local ProcessSupervisor and synthetic child-process fixtures; no production task runner or user data

## Boundary exercised

The disabled ProcessSupervisor launches a Broker-resolved executable in a
detached POSIX process group. The direct child exit is not treated as complete
termination evidence while the process group or a tracked descendant still
exists. On macOS, a native process-identity adapter snapshots descendants by
PID, parent PID, and start time, verifies the identity before signalling, and
keeps the snapshot bounded to 256 processes. TERM/KILL escalation covers both
the process group and the verified descendant identities. A missing native
observer fails closed before execution; a malformed, truncated, or failed
observation returns `UNKNOWN_OUTCOME` and holds the capacity slot until a
reaper can prove that the group and tracked descendants are gone.

## Tests

- Normal bounded execution reports observed termination only after the group is
  gone.
- Timeout and output overflow terminate the detached group and pass drain
  readback before returning.
- Cancellation kills a shell-spawned descendant and releases capacity after
  the group disappears.
- A hostile Python fixture forks a child, calls `setsid`, and sleeps; the
  supervisor tracks and terminates the detached descendant on timeout, returns
  `TIMEOUT` with `terminationObserved: true`, and completes within the bounded
  test deadline.
- The focused ProcessSupervisor suite passes 8/8; the full suite records 296
  tests with 294 passing and two opt-in sandbox tests skipped; `npm run
  typecheck` passes.

## Limits and next gate

This is controlled host evidence for process-group and observed-descendant
termination. It does not prove that a descendant can never fork between
snapshots, can never call `setsid` after the final snapshot, or that a macOS
sandbox enforces filesystem/network rules or credential isolation. Crash/restart
cleanup, real task Job ownership, and production task-runner enablement remain
blocked by MOP-086/MOP-045 and VT-SBX-01/VT-SBX-02.
