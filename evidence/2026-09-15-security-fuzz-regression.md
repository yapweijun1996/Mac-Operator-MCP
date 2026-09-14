# Deterministic Security Fuzz Regression Evidence

Date: 2026-09-15
Source commit: `92bf395`
Host: physical Darwin arm64 development host
Scope: bounded hardening regression only; no capability enablement

## Command

```text
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
```

## Observed result

- Full suite: 515/515 passed, 0 failed, 0 cancelled, 0 skipped.
- Focused security-fuzz suite: 6/6 passed.
- `npm run typecheck` and `npm run build` passed before the full run.

## Coverage added

`packages/broker/src/security-fuzz.test.ts` uses deterministic bounded
mutations rather than unseeded randomness. It exercises:

- Broker request identity, policy-version, scope, target-authority, and
  prompt-shaped field mutations without a valid authentication proof.
- Virtualization guest request identity, digest, profile, budget, process
  policy, extra-field, and credential-shaped mutations before exchange.
- 512 single-use guest request IDs/nonces and replay attempts.
- Secret, credential-assignment, and prompt-injection-shaped output through
  bounded UTF-8 redaction and content-secret denial.
- Oversized canonical JSON/redaction inputs and non-finite/unsupported values.
- Traversal, NUL, overlong, relative, and protected-zone path mutations against
  the Broker-owned filesystem root planner.

All cases assert stable fail-closed classes or bounded output; no test grants
authority, launches a privileged helper, boots a VM, or writes outside its
temporary/test boundary.

## Limits

This evidence is deterministic mutation coverage, not a proof of exhaustive
fuzzing, kernel-held isolation, cross-runtime parser equivalence, physical
remount resistance, or production capability enablement. MOP-070 remains
`IN_PROGRESS` until broader long-running fuzz campaigns and independent review
are complete.
