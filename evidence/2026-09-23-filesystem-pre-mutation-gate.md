# Filesystem pre-mutation authority gate

## Decision

Worker-backed atomic writes and textual patches now pause immediately before
the native filesystem mutation and request a fresh Broker authority decision.
The parent resolves the bounded shared-memory gate only after re-running the
active authority check; a denial terminates the worker before the native write.
Multi-file patches use the gate for every changed file, including rollback
writes and rollback unlinks. The gate is Broker-owned and cannot be enabled or replaced by tool
arguments.

## Evidence

- `packages/broker/src/filesystem-inspector.ts` invokes the optional gate after
  preconditions and volume checks but immediately before
  `writeFileAtomicWithinRoot`.
- `packages/broker/src/filesystem-pre-mutation-gate.ts` uses a bounded
  `SharedArrayBuffer` handshake and maps missing authority to cancellation or
  timeout.
- `packages/broker/src/worker-executor.ts` accepts only the known
  `pre_mutation` control message and releases the worker gate after the parent
  callback succeeds.
- `packages/broker/src/filesystem-executor.test.ts` proves that a denied gate
  leaves the target absent and releases worker capacity.
- Full repository regression: 1,165 total, 1,150 passed, 15 skipped, 0
  failed.

## Limits

The gate closes the Broker-to-worker pre-mutation race in the local worker
protocol. It does not prove physical remount durability, kernel-level atomic
filesystem behavior, or production host acceptance; those remain open under
VT-FS-01, VT-FS-02, VT-REL-01, and VT-REV-01.
