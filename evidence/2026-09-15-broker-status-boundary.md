# Broker Status Request Boundary Evidence

Date: 2026-09-15
Source revision: `240ee88`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T06:07:19Z
Artifact hashes: `packages/broker/src/broker-status-ipc.ts` SHA-256
`4c84a1b807c5da4c9bf946659262a1a7ac92ee2fccafd2295ddd15a75ee7d385`;
`packages/broker/src/broker-status-ipc.test.ts` SHA-256
`f508cd0c3a22c4b17b612740bc479aaf186cb697247dcb8e9ba2878ee42dae70`.

## Decision

Broker status requests are local control-plane inputs. The unsigned validator
must reject accessors and inherited authority fields before key enumeration or
field reads, matching the authenticated parser and response boundary.

## Implemented controls

- `validateUnsignedBrokerStatusRequest` checks the shared plain-data boundary
  before `Object.keys` and requires the exact seven-field request.
- Existing signed parsing, candidate recovery, replay admission, and status
  readback validation continue to use data-only records and stable errors.

## Verification

Focused command:

```text
npm run build && node --test --test-name-pattern='Broker status parser rejects accessor request fields' packages/broker/dist/broker-status-ipc.test.js
```

Result: 1 test passed, 0 failed, 0 skipped. Direct validator checks reject
accessor and inherited request fields. The non-overlapping package regression
passes 538 total tests (532 passed, 6 skipped, 0 failed).

## Boundary status

This proves Broker status request representation integrity only. It does not
prove production deployment, Keychain lifecycle, remote transport, privileged
operations, or final capability enablement. Those gates remain fail-closed and
incomplete.
