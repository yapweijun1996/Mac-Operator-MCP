# ProcessSupervisor descriptor canary evidence

Status: PARTIAL host-side launch-boundary evidence for MOP-086 / VT-SBX-01

## Scope

This probe uses a synthetic temporary file, never a real credential. The parent opens the canary before invoking the Broker `ProcessSupervisor`. The child is started with the supervisor's explicit `stdio` configuration and reports whether the canary's device/inode identity is visible at its expected descriptor path.

## Evidence

- Host: Darwin arm64, macOS 26.2 build `25C56`, Node `v25.5.0`.
- Fixture: temporary `0600` file containing only `synthetic-canary`.
- Child: fixed `/usr/bin/python3`, no inherited environment, bounded output and timeout.
- Expected result: `not-leaked`.
- Observed result: `not-leaked`; test passed.
- Test: `process supervisor does not leak a parent file-descriptor canary`.
- Source: `packages/broker/src/process-supervisor.test.ts`.
- Source SHA-256: `b3a748e10a5616541f56e0b7b7b6658d86b1304e0ddd7d08cf8e135d581f08d2`.
- Command: `npm test -- --test-name-pattern='does not leak a parent file-descriptor canary'`.
- Verification: build completed; 233 tests passed, 0 failed in the repository test run.

## Interpretation and limits

This proves the current Broker-side Node launch path does not pass the synthetic non-stdio descriptor to the child on the tested POSIX host. It does not prove that `sandbox-exec` or a future executor enforces descriptor policy, nor does it prove credential isolation, filesystem/network isolation, persistence prevention, or process-tree ownership. `mac_task_run` remains disabled and MOP-086 remains open.
