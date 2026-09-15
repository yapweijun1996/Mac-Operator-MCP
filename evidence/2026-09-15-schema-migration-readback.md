# Broker Schema Migration Readback Evidence

Date: 2026-09-15
Source revision: `7ce59c1`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T06:16:14Z
Artifact hashes: `packages/broker/src/persistence.ts` SHA-256
`4397c1691d68222297080b4ac595425079acf3742308bdc8e999eb53556e608b`;
`packages/broker/src/persistence.test.ts` SHA-256
`0d8ef1336fb2a951d88faee55e4ba51de4929c6acea0dd9d87788c1d9b395032`.

## Decision

Broker persistence must not treat a successful `PRAGMA user_version` write as
proof that all migrations completed. Startup must read back the marker and the
complete ordered migration registry inside the same transaction before any
ledger or authority recovery proceeds.

## Implemented controls

- Migration startup reads back `user_version` and requires the exact runtime
  schema version.
- It reads back every registry row and requires exact count, version order, and
  migration names.
- Any mismatch throws before transaction completion, so the migration is
  rolled back and Broker startup fails closed.

## Verification

Focused commands:

```text
npm run build && node --test --test-name-pattern='schema version|inconsistent schema migration' packages/broker/dist/persistence.test.js
node --test --test-name-pattern='complete migration registry before startup' packages/broker/dist/persistence.test.js
```

Result: 3 focused migration tests passed, 0 failed, 0 skipped. The complete
non-overlapping package regression passes 538 total tests (532 passed,
6 skipped, 0 failed).

## Boundary status

This proves local migration marker/registry readback only. It does not prove
physical disk-exhaustion recovery, production backup operations, Keychain
deployment, installed service recovery, or final release acceptance. Those
gates remain fail-closed and incomplete.
