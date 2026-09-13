# Real filesystem worker crash and unknown-outcome readback

- Source commit: `61b08655cbc0389cf2185bde752bf5f11d5fdfd7`
- Working tree: clean before this evidence document was added
- Host: Mac mini M4, `Darwin yaps-Mac-mini.local 25.2.0`, arm64
- Runtime: Node `v25.5.0`; macOS platform reported by Node as `darwin`
- Captured: 2026-09-13 (Asia/Kuala_Lumpur)
- Scope: test-only worker crash and temporary filesystem fixture; no service installation, privilege escalation, credential access, or external network

## Boundary implemented

`filesystem-crash-worker.ts` is compiled only as a controlled test worker URL.
It performs a real `FilesystemInspector.writePlanned` atomic write, then raises
an uncaught worker exception before posting a result. The production
`WorkerFilesystemExecutor` default remains the fixed `filesystem-worker.js`
URL; MCP arguments cannot select the crash worker.

## Observed results

- Focused Broker/worker command: 69 tests, 69 passed, 0 failed
- `npm test`: 375 tests, 372 passed, 0 failed, 3 opt-in real-sandbox tests skipped
- `MOPS_REAL_SANDBOX=1 npm test`: 375 tests, 375 passed, 0 failed, 0 skipped
- Crash-write result: `EXECUTION_FAILED`; Job state: `unknown`
- Target readback: exact fixture content remained present after the worker exit
- `mac_job_status` recovery: `postcondition: matches`, `resolution: remains_unknown`
- Capacity readback: the bounded executor stayed occupied until the worker exit
  event, then accepted and completed a subsequent request
- `npm run typecheck -- --pretty false`: passed
- `npm run verify:contracts`: passed (44 unique contracts)
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities
- `git diff --check`: passed

## Interpretation and limits

The Broker does not convert a worker crash after a committed mutation into
success. It records an unresolved Job and exposes only a bounded postcondition
probe, while the executor avoids reusing a capacity slot before the crashed
worker has exited. This is evidence for worker-thread crash ambiguity and
capacity fencing.

It is not evidence that a separate OS worker process is owned, that an old
worker cannot outlive a Broker process restart, or that a restarted Broker can
prove the prior worker's termination before cleanup. Those remain release-gate
items, along with physical disk/remount behavior and production task-runner
enablement.

Source hashes at capture:

```text
7cc3018c9f738defcc334863bf8478e9b6383129326b1774cacc7496458012d7  packages/broker/src/filesystem-crash-worker.ts
a5d62cd6073094c789875e8fba405ac1b73ae6333f0bde35cdd3b102b4ba4040  packages/broker/src/broker.test.ts
2bf7067d5de3e1f931aa7fb0c747769c5e4b9a710e55c0f9179acfd8d9a0d050  packages/broker/src/worker-executor.test.ts
```
