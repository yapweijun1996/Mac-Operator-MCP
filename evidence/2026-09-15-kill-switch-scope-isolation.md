# Mutation kill-switch scope isolation evidence

Date: 2026-09-15
Source revision: `6bf29d4`

Queued-job authority reconciliation now treats the `mutations` kill switch as
an independent write boundary. It cancels only the explicit mutation Job
allowlist (file writes/patches, Git writes, GUI actions, task execution,
privileged operations, and job cancellation) while leaving read-only queued
Jobs untouched. The `global` switch remains the all-capability stop. Process,
GUI, destructive, and privileged switches retain their narrower mappings.

Verification:

```text
npm run build
temporary BrokerStore smoke: mutation switch preserved mac_health queued Job
and cancelled mac_write_file_atomic queued Job
```

The persistence regression includes the same assertion. The full non-overlap
regression remains 546 total (540 passed, 6 skipped, 0 failed); the long-lived
BrokerStore test process was intentionally not duplicated.
