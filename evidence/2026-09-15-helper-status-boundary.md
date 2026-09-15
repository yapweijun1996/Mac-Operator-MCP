# Privileged Helper Status Request Boundary Evidence

Date: 2026-09-15
Source revision: `e9d67e6`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T06:05:24Z
Artifact hashes: `packages/broker/src/privileged-helper.ts` SHA-256
`2d763b17c87b9565d4eee4ba188de54a584d96869c36c8f676aad309780546b1`;
`packages/broker/src/privileged-helper.test.ts` SHA-256
`c819e72e6a0b2cf0ebece4c546f6e35b091369a5705b167bb662fbff0c04e9e6`.

## Decision

Status requests are authenticated control-plane inputs. Classification,
candidate recovery, and field validation must not read accessors, inherited
properties, symbols, or other non-data objects before the Broker's authority
and replay gates.

## Implemented controls

- `isStatusRequestEnvelope` accepts only shared plain-data records before
  reading `kind`.
- Unsigned status validation checks the plain-data boundary before `Object.keys`
  or field access and requires the exact seven-field envelope.
- Failure candidate recovery uses the same plain-data boundary, so malformed
  objects cannot influence stable failure identity through prototype or getter
  behavior.
- Status readback validation checks the same boundary before enumerating keys or
  consuming helper-owned state.

## Verification

Focused command:

```text
npm run build && node --test --test-name-pattern='privileged helper status request boundary' packages/broker/dist/privileged-helper.test.js
```

Result: 2 focused tests passed, 0 failed, 0 skipped. Accessor and inherited
status request/readback fields are rejected with stable fail-closed behavior.
The non-overlapping package regression passes 538 total tests (532 passed,
6 skipped, 0 failed).

## Boundary status

This proves status-request representation integrity only. It does not prove
Developer ID provenance, root-domain installation, production Keychain
distribution, real privileged adapters, crash recovery, or helper enablement.
Those gates remain fail-closed and incomplete.
