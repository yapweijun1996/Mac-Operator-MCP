# Privileged Helper Status Request Boundary Evidence

Date: 2026-09-15
Source revision: `026a83f`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T06:03:48Z
Artifact hashes: `packages/broker/src/privileged-helper.ts` SHA-256
`22423762aefed4035f7494611f82bf2fffcf5406b5160e00c2c4b02d81ecd9a4`;
`packages/broker/src/privileged-helper.test.ts` SHA-256
`e619b48a1effd8241d623bd7af06d3d3dffd1f10124326cd972f1286d656453c`.

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

## Verification

Focused command:

```text
npm run build && node --test --test-name-pattern='privileged helper status request boundary' packages/broker/dist/privileged-helper.test.js
```

Result: 1 test passed, 0 failed, 0 skipped. Accessor and inherited status
fields are rejected with stable `PRECONDITION_FAILED` behavior. The
non-overlapping package regression passes 537 total tests (531 passed,
6 skipped, 0 failed).

## Boundary status

This proves status-request representation integrity only. It does not prove
Developer ID provenance, root-domain installation, production Keychain
distribution, real privileged adapters, crash recovery, or helper enablement.
Those gates remain fail-closed and incomplete.
