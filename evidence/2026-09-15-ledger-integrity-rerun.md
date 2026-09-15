# Persistence Integrity Rerun Evidence

Date: 2026-09-15

Source revision: `8077a6d`

Command:

```text
node --test \
  packages/broker/dist/replay-row-invariants.test.js \
  packages/broker/dist/approval-row-invariants.test.js \
  packages/broker/dist/authority-row-invariants.test.js \
  packages/broker/dist/configuration-row-invariants.test.js \
  packages/broker/dist/request-state-invariants.test.js \
  packages/broker/dist/job-row-invariants.test.js \
  packages/broker/dist/request-link-invariants.test.js \
  packages/broker/dist/schema-layout-invariants.test.js
```

Result: 33 tests passed, 0 failed, 0 skipped.

## Coverage

The rerun covers all seven durable replay ledgers, Approval lifecycle and
revocation invariants, active/history configuration binding for every key
family, Request state and timestamp invariants, Job lease/output/authority
invariants, Request-to-Job ownership/linkage checks, and unknown-column
rejection across every Broker persistence table.

Every malformed or substituted persisted authority record failed closed as
`AUDIT_UNAVAILABLE`; no external authority, privileged action, or destructive
operation was invoked. The pre-existing `broker.test.js` and
`persistence.test.js` process remains undisturbed and is not represented by
this focused result.

This is current local integrity evidence only. Physical crash/remount
durability, production Keychain distribution, installed recovery, external
rollback detection, and independent P0/P1 review remain open.
