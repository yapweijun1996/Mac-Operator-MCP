# Runtime Policy Authority Array Boundary Evidence

Date: 2026-09-15
Source revision: `d1f96f2`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T06:18:42Z
Artifact hashes: `packages/broker/src/policy.ts` SHA-256
`e759d67fa1c194445a5e27a90442a7be65fa223aba600ba9a187368f3ba63355`;
`packages/broker/src/policy.test.ts` SHA-256
`193cf05204ff3c391d2a7c80d285a073eb6e5aef1146e9d26f3bcbde1da84f0a`.

## Decision

Policy collections are authority, not ordinary application data. Principal
scopes, target rules, filesystem roots, deny paths, tool scopes, and capability
families must be dense bounded arrays with data-only element slots before
authorization or capability advertisement.

## Implemented controls

- Runtime policy validation rejects sparse, symbolic, accessor, and
  extra-property arrays before iterating or calling `includes`/`some`.
- Collection limits are bounded by the policy vocabulary or explicit runtime
  caps (4096 target/deny entries, 128 filesystem roots).
- Existing exact object-field, duplicate-identity, deny-overrides-allow,
  unimplemented-enable, and scope-grant checks remain unchanged.

## Verification

Focused command:

```text
npm run build && node --test --test-name-pattern='runtime Broker policy rejects (inherited|accessor)' packages/broker/dist/policy.test.js
```

Result: 2 tests passed, 0 failed, 0 skipped. Hostile accessor and sparse
authority arrays fail closed. The non-overlapping package regression passes 539
total tests (533 passed, 6 skipped, 0 failed).

## Boundary status

This proves in-memory runtime policy collection integrity only. It does not
accept ADR-0004, prove production signer/Keychain distribution, or close
installed policy reload, migration, remote deployment, or final enablement.
Those gates remain fail-closed and incomplete.
