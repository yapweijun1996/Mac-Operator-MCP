# Broker policy authority snapshot evidence

Date: 2026-09-15
Source revision: `0be82c4` (`fix: snapshot Broker policy authority`)

## Boundary

`BrokerPolicy` contains mutable JavaScript collections. If a caller retains a
policy object or a `PolicyManager.current()` result, later changes to target
rules, principal grants, kill switches, filesystem roots, or ToolPolicy arrays
must not change the authority used by the Broker. The Broker therefore copies
plain policies during construction. `PolicyManager` copies policies on input
and returns a fresh deep snapshot on every `current()` call, while preserving
its internal active revision for authenticated policy transitions.

The snapshot includes maps, sets, nested scope/family arrays, target objects,
filesystem deny lists, principal grants, trusted-key windows, and kill-switch
records. The earlier runtime validator still checks the copied policy before
it is used.

## Verification

Commands run from the repository root:

```text
npm run build
node --test packages/broker/dist/policy.test.js packages/broker/dist/broker.test.js --test-name-pattern='authorized health request|runtime Broker policy|policy authority snapshots|production-default policy'
npm run lint
npm run verify:contracts
npm run verify:canonical:native
git diff --check
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
```

Results:

- Focused Broker/policy selection: 82 tests, 76 passed, 6 explicit platform skips, 0 failed.
- Style, contract, native canonical-vector, and diff checks: passed.
- Physical Darwin opt-in suite: 601 passed, 0 failed, 0 skipped.

The focused platform skips are existing non-Darwin task-recovery cases in the
selected Broker test file; the complete physical-Darwin run exercised all
tests without skips.

## Limits

This evidence proves reference isolation for in-memory policy authority. It
does not close signed policy package provenance, Developer ID/notarization,
production key distribution, installed-service ownership, real privileged
helper execution, or the final P0/P1 release gate.
