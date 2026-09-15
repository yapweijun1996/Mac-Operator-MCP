# Process Worker Result Boundary Evidence

Date: 2026-09-15
Source revision: `a01b62e`
Host: physical macOS host used by the repository test harness

## Decision

Process metadata crosses both a native adapter boundary and a worker-thread
boundary. The Broker must not accept inherited/accessor fields, unexpected
metadata, or unstable child identities as a verified read-only result.

## Implemented controls

- Native inventory and detail records require the shared plain-data shape and
  exact declared field sets.
- Process owner values are non-empty bounded `uid:<number>` identities.
- Child PID arrays are dense, bounded, valid identities with strict ordering,
  preventing duplicate or ambiguous child readback.
- Worker success/failure envelopes reject unknown fields before the generic
  executor resolves a result.
- Parsed native results are copied into fresh typed records before return.

## Verification

Focused command:

```text
node --test packages/broker/dist/process-inspector.test.js packages/broker/dist/worker-executor.test.js
```

Result: 14 tests passed, 0 failed, 0 skipped. Hostile parser fixtures reject
prototype/accessor/symbolic results, duplicate child identities, and worker
success envelopes containing an extra authority field.

Non-overlapping package regression (excluding the two pre-existing long-lived
broker/persistence test processes): 520 tests total, 514 passed, 6 skipped,
0 failed.

## Boundary status

This proves local native/worker result-shape integrity only. It does not prove
native code provenance, kernel sandboxing, credential or persistence
isolation, VM/guest attestation, production resource behavior, or capability
enablement. Those gates remain fail-closed and disabled.
