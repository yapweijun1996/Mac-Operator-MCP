# Runtime Broker policy validation evidence

Date: 2026-09-15
Source revision: `ee994a8` (`fix: validate runtime Broker policy`)

## Boundary

The Broker is the final authority for capability discovery and execution. A
caller may supply a `BrokerPolicy` object in memory, and a `PolicyManager`
retains maps that can otherwise be mutated after construction. This boundary
therefore validates the policy both when it enters the Broker and immediately
before authorization. Policy-manager activation, restore, and rollback use
the same gate before persistence or assignment.

The validator rejects malformed policy metadata and ToolPolicy entries,
including unknown tool identities, contract-version drift, empty or unknown
scopes/capability families, duplicate authority markers, unsupported target or
approval types, unsafe output/timeout budgets, and `enabled: true` combined
with `implemented: false`. Missing planned tools remain represented as
planned-but-unimplemented so the existing planned/implemented/enabled model is
preserved.

## Verification

Commands run from the repository root:

```text
npm run build
node --test packages/broker/dist/policy.test.js packages/broker/dist/policy-loader.test.js --test-name-pattern='runtime Broker policy|policy manager rejects|verified signed policy'
npm run lint
npm run verify:contracts
npm run verify:canonical:native
git diff --check
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
```

Results:

- Policy and PolicyManager focused selection: 17 passed, 0 failed.
- Style, contract, native canonical-vector, and diff checks: passed.
- Physical Darwin opt-in suite: 600 passed, 0 failed, 0 skipped.

## Limits

This evidence proves the runtime policy-shape gate and its regression behavior.
It does not close signed policy package provenance, Developer ID/notarization,
production key distribution, installed-service ownership, real privileged
helper execution, or the final P0/P1 release gate.
