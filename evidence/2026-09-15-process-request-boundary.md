# Process Request Boundary Evidence

Date: 2026-09-15
Source revision: `78dd404`
Host: physical macOS host used by the repository test harness

## Decision

ProcessSupervisor is a Broker-owned process admission boundary. A request
must be a plain data record with the exact declared fields before any child
process is spawned. Tool arguments cannot add authority through prototypes,
accessors, symbols, sparse arrays, unknown fields, or callback substitution.

## Implemented controls

- Executable and cwd are canonical absolute paths.
- Arguments are dense bounded string arrays with no hidden or symbolic
  properties.
- Environment data must be a plain record, after the existing allowlist and
  secret checks.
- Timeout and output-cap values are safe integers within the supervisor
  budgets.
- Exit-proof and control callback fields have strict runtime types.
- Invalid requests return stable `PRECONDITION_FAILED` errors before process
  admission; the hostile-shape test confirms `activeCount() === 0`.

## Verification

Focused command:

```text
node --test packages/broker/dist/process-supervisor.test.js packages/broker/dist/task-profile.test.js packages/broker/dist/task-runner.test.js
```

Result: 49 tests passed, 0 failed, 0 skipped.

Non-overlapping package regression (excluding the two pre-existing long-lived
broker/persistence test processes): 514 tests total, 508 passed, 6 skipped,
0 failed.

## Boundary status

This evidence proves local request representation integrity only. It does not
prove sandbox enforcement, credential or persistence isolation, VM/guest
attestation, resource exhaustion behavior on a production workload, or
`mac_task_run` enablement. Those gates remain fail-closed and disabled.
