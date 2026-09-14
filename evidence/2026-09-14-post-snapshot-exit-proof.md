# Strict task exit proof evidence

Date: 2026-09-14
Scope: `ProcessSupervisor` and `SandboxExecTaskRunner` task boundary
Host: physical Darwin arm64 development host

## Decision

Governed sandbox tasks now set `requireCleanExitProof`. Before a successful
result is published, the Supervisor performs one additional native process-tree
snapshot after the child close event. Missing native observation, truncation,
PID identity replacement, or any unresolved descendant maps to
`UNKNOWN_OUTCOME`. Ordinary fixed adapters do not set this field and retain
their bounded child-exit behavior.

## Verification

- Strict `/usr/bin/printf` task exit with the native observer returned
  `SUCCEEDED` only after the final descendant readback.
- Sandbox runner forwarding test confirms the strict flag is Broker-owned and
  not supplied by task arguments.
- Focused process-supervisor/sandbox suite: 29 passed, 3 explicit Darwin-boundary
  skips.
- Full regression with `MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1`: 476 tests,
  475 passed, 0 failed, 1 explicit skip.
- Typecheck, style, contract verification, dependency audit, and diff checks
  pass.

## Limits

The final snapshot is an observation boundary, not a kernel-held process or
mount namespace. It does not prove that a process created and detached after
the last observable snapshot could not escape, nor does it prove in-syscall
remount resistance or credential-store isolation. The single-process sandbox
profile's fork denial and production enablement remain separately evidence-
gated under MOP-086.
