# Broker task-process restart recovery evidence

- Source commit: `e12da49ffb25265cf857fbcfef75266ed95144a0`
- Working tree: clean before this evidence document was added
- Host: Mac mini M4, `Darwin yaps-Mac-mini.local 25.2.0`, arm64
- Runtime: Node `v25.5.0`; macOS platform reported by Node as `darwin`
- Captured: 2026-09-13 (Asia/Kuala_Lumpur)
- Contract/policy: tool contracts `0.1`; Broker policy fixtures `policy-0.1`
- Scope: controlled task-process identity persistence and restart recovery;
  no service installation, privilege escalation, credential access, or
  external network

## Implemented boundary

`ProcessSupervisor` captures the Darwin root PID, detached process-group ID,
and native start-time identity synchronously after spawn. The Broker persists
that bounded identity in the running task Job under a lease and revision fence.
The identity is not exposed through MCP job status or output.

On a new `BrokerStore`, an interrupted running task becomes `UNKNOWN` and
retains only the process identity metadata. The explicit host-startup hook
`reconcileRestartedTaskProcesses()` selects only those restart-reconciled task
Jobs, records redacted recovery intent, and calls the new Broker-owned recovery
primitive. Recovery signals only when the exact PID/start-time identity is
still alive, drains the verified process group/descendants, and records a
completion result. Identity mismatch, observer failure, and unresolved group
state remain non-success outcomes; the Job is never changed to `completed`.

## Verification

- `restarted Broker recovers an exact task process identity without resolving
  the Job` passes: a real `/bin/sleep` process is started by one supervisor,
  the Job is reconciled to `UNKNOWN` by a second `BrokerStore`, and a new
  Broker terminates the exact persisted identity. Audit result is
  `PROCESS_DRAINED`; Job state remains `unknown`.
- `process supervisor captures and recovers an exact persisted root identity`
  passes on Darwin.
- `process supervisor refuses a swapped persisted root identity` passes and
  leaves the original process for the owning supervisor to close.
- `task process ownership metadata survives restart as UNKNOWN` passes,
  including schema migration and process-metadata readback.
- Default `npm test` — 385 tests, 382 passed, 3 opt-in sandbox tests skipped.
- `MOPS_REAL_SANDBOX=1 npm test` — 385 tests, 385 passed, 0 skipped.
- `npm run typecheck -- --pretty false`, `npm run verify:contracts`,
  `npm audit --omit=dev --audit-level=high`, and `git diff --check` pass.

## Interpretation and limits

This is real Darwin cross-BrokerStore recovery for a still-running root
process. It does not prove that a Broker can safely recover descendants after
the persisted root has already exited, defeat every post-snapshot `setsid`
race, or establish sandbox filesystem/network/credential isolation. The
task runner and `owned_group` profile remain disabled.

Source hashes at capture:

```text
205c3c0909f88977e119aa2833573999e060e5a8c5907a59b81293a7a7bae183  packages/broker/src/process-supervisor.ts
d1a98a8b4cce921b0d9eb0b209b673596a1f2eeaf03e8b41c195567b98e629e6  packages/broker/src/process-supervisor.test.ts
0be84be1b8257248f0cb0351cde1616045323e6931aab7fee63d0c7fd33a470c  packages/broker/src/persistence.ts
22b5c6f885ecc692af26f955c70cc1beab39095481e0c6e81ca5df49296d0d53  packages/broker/src/persistence.test.ts
6968aa4f670580f09880b26cfa7b98a39647a0262b80c52978a0dd4d9f76614f  packages/broker/src/broker.ts
fe1be778e928c4082be1b05ad67b7b0ba020eb1acd14cf0b2a90d4b8be8d7b3f  packages/broker/src/broker.test.ts
30431982d9e4759c419061cb4c54c1b5232964e01e7a6e2c919ec12fc6bed4ff  packages/broker/src/task-runner.ts
8f052862698bc6f0e2c028c1d125706a269fa7e83126282945cf461dfb6c3296  packages/broker/src/sandbox-profile.test.ts
```
