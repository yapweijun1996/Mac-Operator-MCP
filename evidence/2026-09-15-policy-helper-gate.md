# Broker policy helper-gate evidence

Date: 2026-09-15
Source revision: `21559e7` (`fix: validate policy at every authority helper`)

## Boundary

Broker authorization is composed from several helpers. A caller that reaches
`authorizePrincipalProjection`, `authorizeTarget`,
`isCapabilityFamilyDisabled`, or `runtimeToolStates` must not be able to pass
a partial object that bypasses the full policy boundary. Each helper now
validates the complete policy before checking its own rule, while
`authorizeTool` retains the same gate before tool execution.

The deterministic security-fuzz policy corpus was updated to build complete
Broker policies with a real principal grant and filesystem root. It runs 256
sequences covering projected-scope expansion and deny-overrides-allow behavior,
including both allowed and explicitly denied target cases.

## Verification

Commands run from the repository root:

```text
npm run build
node --test packages/broker/dist/policy.test.js packages/broker/dist/security-fuzz.test.js --test-name-pattern='policy|target|projection|capability|mutation'
npm run lint
npm run verify:contracts
npm run verify:canonical:native
git diff --check
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
```

Results:

- Policy and selected security-fuzz tests: 10 passed, 0 failed.
- Style, build, contract, native canonical-vector, and diff checks: passed.
- Physical Darwin opt-in suite: 601 passed, 0 failed, 0 skipped.

## Limits

This evidence proves helper-entry policy validation and the deterministic
mutation corpus. It does not close signed policy package provenance,
Developer ID/notarization, production key distribution, installed-service
ownership, real privileged helper execution, or the final P0/P1 release gate.
