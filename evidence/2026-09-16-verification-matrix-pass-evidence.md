# Verification Matrix Passing-Evidence Enforcement

- Date: 2026-09-16
- Source revision: `168da62`
- Contract/policy versions: 0.1
- Evidence class: local CI/documentation boundary

## Decision

Require every matrix row marked `PASS` to reference at least one repository
evidence file. A passing state without a readback artifact is rejected by the
same machine check that validates row shape, IDs, gates, and references.

## Implemented controls

`scripts/check-verification-matrix.mjs` now fails closed when a `PASS` row has
no `evidence/` or `docs/adr/` reference. The two existing PASS rows reference
the ledger-contract and capability-version evidence files. The checker still
validates that every referenced path is a regular file inside the repository.

## Verification

```text
npm run verify:matrix
npm run verify:docs
npm run lint
npm run typecheck
git diff --check
```

Result: the matrix check passed for 28 targets, 24 threats, 30 tasks, and 3
evidence references; documentation, style, typecheck, and diff checks passed.

Artifact SHA-256:

```text
scripts/check-verification-matrix.mjs
a098fe5d797b9b8b77249b1deb9ce27514204b1f2082cc721e1d9c4ac35e9a61
VERIFICATION.md
fe97fb736edbf3057dc625db2c5eeda5687a35f85114426e6d931b98ab83a86a
```

## Boundary status

This enforces evidence presence for `PASS` rows; it does not make any
`OPEN`/`BLOCKED` row pass, replace focused or physical tests, supply remote CI,
or substitute for independent security review.
