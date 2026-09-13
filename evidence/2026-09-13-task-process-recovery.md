# Broker task-process restart recovery evidence

- Source commit: `a20fed791b73d8b8fb02c08384a115bde21e18f9`
- Working tree: clean before this evidence document update
- Host: Mac mini M4, `Darwin yaps-Mac-mini.local 25.2.0`, arm64
- Runtime: Node `v25.5.0`; macOS platform reported by Node as `darwin`
- Captured: 2026-09-13 (Asia/Kuala_Lumpur)
- Contract/policy: tool contracts `0.1`; Broker policy fixtures `policy-0.1`
- Scope: controlled task-process identity persistence and restart recovery;
  no service installation, privilege escalation, credential access, or
  external network

## Implemented boundary

`ProcessSupervisor` captures the Darwin root PID, detached process-group ID,
and native start-time identity synchronously after spawn, together with a
bounded snapshot of observed descendant PID/start-time pairs. The Broker
persists that non-secret snapshot in the running task Job under a lease and
revision fence; later snapshots are monotonic and cannot replace the root
identity. The metadata is not exposed through MCP job status or output.

On a new `BrokerStore`, an interrupted running task becomes `UNKNOWN` and
retains only the process identity metadata. The explicit host-startup hook
`reconcileRestartedTaskProcesses()` selects only those restart-reconciled task
Jobs, records redacted recovery intent, and calls the Broker-owned recovery
primitive. Recovery signals only when exact PID/start-time identities are
still alive, including persisted descendants after the root has exited, drains
the verified process group/descendants, and records a completion result.
Identity mismatch, observer failure, and unresolved group state remain
non-success outcomes; the Job is never changed to `completed`.

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
- `process supervisor recovers a persisted detached descendant after root exit`
  passes on Darwin: a forked child calls `setsid()`, the persisted root is
  killed, and recovery terminates the exact child identity without relying on
  process-group membership.
- `process supervisor keeps an empty snapshot unresolved after root exit`
  passes on Darwin: a killed root with no persisted descendants returns
  `unknown`, not `absent`, because a child could have been created after the
  last observation and escaped the process group.
- `task process ownership metadata survives restart as UNKNOWN` passes,
  including schema migration and process-metadata readback.
- Default `npm test` — 387 tests, 384 passed, 3 opt-in sandbox tests skipped.
- `MOPS_REAL_SANDBOX=1 npm test` — 387 tests, 387 passed, 0 skipped.
- `npm run typecheck -- --pretty false`, `npm run verify:contracts`,
  `npm audit --omit=dev --audit-level=high`, and `git diff --check` pass.

## Interpretation and limits

This is real Darwin cross-BrokerStore recovery for a live root and for a
persisted detached descendant after root exit. If no descendant identity was
persisted, recovery now stays unresolved rather than claiming absence. It does
not prove cleanup of descendants created after the last snapshot, defeat every
post-snapshot `setsid` race, or establish sandbox filesystem/network/credential
isolation. The task runner and `owned_group` profile remain disabled.

Source hashes at capture:

```text
da604a96f8f0c77b87c06e7da2dfec33ea3c7b85ecf0b2d21394b666dc12a2e7  packages/broker/src/process-supervisor.ts
116a8644cdd71d65366f04f69a1de809d4c6eecbd5605aca2232aa5f85a18664  packages/broker/src/process-supervisor.test.ts
15c9c5bfc3acac35d237a23831f4bb8713f4f00e68c7ee9929d921119ef7f55f  packages/broker/src/persistence.ts
6c73166cd32c03d220247e83b3b52b07c55934f37469ef1a170f7bffdd8382fd  packages/broker/src/persistence.test.ts
a0dc97ad681563f2567d9260508e769302f2f345e1829298160c01c2851416cf  packages/broker/src/broker.ts
f67ee7d46412c01a36866a05fafc41f3b08f847f4308943c3c475a7bc7f61d85  packages/broker/src/broker.test.ts
b264c40cb03fe3f24e10242678cbe53a23ef4729329a1da2442859b87522d600  packages/broker/src/task-runner.ts
e105b052cf979ee8beec1e1ff281f2a8306667171262eb2d24af3a91bbb3e49a  packages/broker/src/sandbox-profile.test.ts
```
