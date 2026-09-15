# Process Worker Executor Result Boundary Evidence

Date: 2026-09-15
Source revision: `8a9a89c`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T05:32:47Z
Artifact hashes: `packages/broker/src/process-inspector.ts` SHA-256
`03174323cec17846e37280ea06ddc7671ca7a4f9a6c6ef63faad338fda73a9bd`;
`packages/broker/src/process-executor.ts` SHA-256
`b2cc0586deaccdb5cca90ae8f098a7a16975132bbdcc415b477e7327aca0665c`;
`packages/broker/src/process-executor.test.ts` SHA-256
`611b10f9caa532abcad67e554793e56956892bc3c5d1ec2c3c033751376c6f63`.

## Decision

Process results cross a worker-thread boundary after native process
inspection. The worker executor must apply the same strict parser as the
native adapter rather than trusting a structurally similar union.

## Implemented controls

- `WorkerProcessExecutor` delegates inventory/detail validation to
  `parseProcessInventory` and `parseProcessDetail`.
- Native parsers require exact field sets, plain data records, bounded scalar
  values, and dense arrays; detail child PIDs remain strictly ordered.
- Parsed values are copied into fresh records before Broker consumers receive
  them, preventing worker-owned objects from carrying hidden authority.
- Malformed worker results map to stable `EXECUTION_FAILED` errors.

## Verification

Focused command:

```text
npm run build && node --test packages/broker/dist/process-executor.test.js packages/broker/dist/process-inspector.test.js
```

Result: 6 tests passed, 0 failed, 0 skipped. Hostile fixtures reject sparse
inventories, unknown fields, and nested accessor identities at both parser and
executor boundaries.

Non-overlapping package regression (excluding the two pre-existing long-lived
broker/persistence test processes): 528 tests total, 522 passed, 6 skipped,
0 failed.

## Boundary status

This proves local process result-shape integrity only. It does not prove
native code provenance, process ownership after crash, kernel resource
limits, credential isolation, or production task enablement. Those gates
remain fail-closed and incomplete.
