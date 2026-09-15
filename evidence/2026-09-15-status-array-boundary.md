# Broker and Privileged Helper Status Array Boundary Evidence

Date: 2026-09-15
Source revision: `987cadc`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T06:10:11Z
Artifact hashes: `packages/broker/src/privileged-helper.ts` SHA-256
`6cd2b5ca9c69da962694f2421b0988ad157ecc30347ba04b0370a87dfa48570b`;
`packages/broker/src/privileged-helper.test.ts` SHA-256
`f28f055eded5a82321c81989052fa12f5689952e897b2fbb06004e19b1d9f2df`;
`packages/broker/src/broker-status-ipc.ts` SHA-256
`0ce2f335604308b4d1399fefa9e0f6ef6561549680f9ae3e051e290aca250558`;
`packages/broker/src/broker-status-ipc.test.ts` SHA-256
`ed80d1558b1947a2a2e6138223cc62a8b3408346b5ca3979b7f21e9952d2601c`.

## Decision

Status readbacks are trusted only after their nested capability lists are
bounded dense arrays. Extra enumerable/accessor properties, symbols, and sparse
array layouts are not data-only results and must fail closed.

## Implemented controls

- Privileged-helper status readback requires an empty dense capability list.
- Broker status readback requires a dense capability list bounded to 128 entries.
- Existing per-entry capability-name validation and exact top-level readback
  fields remain in force.

## Verification

Focused command:

```text
npm run build && node --test --test-name-pattern='privileged helper status readback rejects|Broker status IPC authenticates readback' packages/broker/dist/privileged-helper.test.js packages/broker/dist/broker-status-ipc.test.js
```

Result: 2 tests passed, 0 failed, 0 skipped. Hostile extra-array-property
fixtures are rejected. The non-overlapping package regression passes 538 total
tests (532 passed, 6 skipped, 0 failed).

## Boundary status

This proves nested status-array representation integrity only. It does not prove
production deployment, Keychain lifecycle, remote transport, privileged
operations, or final capability enablement. Those gates remain fail-closed and
incomplete.
