# Broker shared OS-process ownership evidence

- Source commit: `1a8b0cc5c774490f1b10482da7a3195a5776f5a1`
- Working tree: clean before this evidence document was added
- Host: Mac mini M4, `Darwin yaps-Mac-mini.local 25.2.0`, arm64
- Runtime: Node `v25.5.0`; macOS platform reported by Node as `darwin`
- Captured: 2026-09-13 (Asia/Kuala_Lumpur)
- Contract/policy: tool contracts `0.1`; Broker policy fixtures `policy-0.1`
- Scope: live Broker-owned OS-process shutdown; no service installation,
  privilege escalation, credential access, or external network

## Implemented boundary

Broker now creates one shared `ProcessSupervisor` for default launchd, log,
Git, Docker, app, and UI adapters. The supervisor has a bounded aggregate
concurrency limit and an explicit union of non-secret environment keys required
by those adapters. Caller-supplied adapter arguments still pass through their
existing fixed validators; sharing the supervisor does not grant a new tool or
scope.

`Broker.close()` drains that shared supervisor in addition to filesystem and
process worker executors and the task runner. Injected inspectors remain
caller-owned; the explicit `processSupervisor` option identifies the Broker
owned authority used by default adapters.

## Verification

- `Broker close drains its shared OS process supervisor` passes: an active
  `/bin/sleep` is terminated through `Broker.close()`, returns `CANCELLED` with
  `terminationObserved: true`, and shared capacity returns to zero.
- `process supervisor close drains owned processes and rejects new work` and
  `SandboxExecTaskRunner exposes its supervisor close boundary` pass.
- `MOPS_REAL_SANDBOX=1 npm test` — 381 tests, 381 passed, 0 skipped.
- Default `npm test` — 381 tests, 378 passed, 3 opt-in sandbox tests skipped.
- `npm run typecheck -- --pretty false` and `git diff --check` pass.

## Interpretation and limits

This proves live graceful shutdown ownership for default Broker adapter
processes and the opt-in task-runner supervisor. It does not prove that a
crashed Broker can identify and terminate descendants after restart, that
post-snapshot `setsid` escapes are impossible, or that sandbox credential and
network isolation are complete. `mac_task_run` and `owned_group` remain
disabled.

Source hashes at capture:

```text
2b909da41540ead45d6ba7803444c4fd53c97b66ca2d7efefeef7709e375b244  packages/broker/src/broker.ts
614a6c873dd5084bc03d6a22011f813ad566a1aedb268a1ee9dd1ba83baafe45  packages/broker/src/broker.test.ts
```
