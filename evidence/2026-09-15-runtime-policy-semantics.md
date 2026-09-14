# Runtime Broker policy semantic validation evidence

Date: 2026-09-15
Source revision: `83a733e` (`fix: validate Broker policy authority semantics`)

## Boundary

The signed policy loader already validates policy documents, but a Broker can
also be constructed from an in-memory `BrokerPolicy`. Without a second
semantic gate, a malformed object could introduce a target rule outside a
principal grant, redirect a path rule to an unknown root, or smuggle wildcard
and non-canonical references into authorization. The Broker now validates the
full authority shape before use.

The gate checks exact top-level and nested fields, policy IDs, trusted-key
windows, principal-grant identity/scope membership, duplicate target/root
identities, normalized filesystem roots and deny-relative paths, kill-switch
keys, and target-kind/reference constraints. It preserves the existing model
where planned tools absent from the runtime map remain planned but
unimplemented. Malformed input maps to stable `POLICY_DENIED` errors.

## Verification

Commands run from the repository root:

```text
npm run build
node --test packages/broker/dist/policy.test.js
npm run lint
npm run verify:contracts
npm run verify:canonical:native
git diff --check
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
```

Results:

- Policy semantic validation tests: 3 passed, 0 failed.
- Style, build, contract, native canonical-vector, and diff checks: passed.
- Physical Darwin opt-in suite: 601 passed, 0 failed, 0 skipped.

## Limits

This evidence proves the in-memory policy semantic gate. It does not close
signed policy package provenance, Developer ID/notarization, production key
distribution, installed-service ownership, real privileged helper execution,
or the final P0/P1 release gate.
