# Verification Matrix Enforcement Evidence

Date: 2026-09-16
Source revision: `64ee61c`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean before documentation update
Tool contract version: 0.1
Policy version: 0.1
Artifact hashes:

- `scripts/check-verification-matrix.mjs` SHA-256
  `17cab2ed73d0274d54bd6a2cf34df2c3af048dd6e9596ba1333ed82ccf02f92a`;
- `VERIFICATION.md` SHA-256
  `fd4a38e4db0c8311d945145508e31c3ce7fa9ab5881c9027f0533afd6a134ed2`;
- `THREAT_MODEL.md` SHA-256
  `c070bf07b3b23e82c39988365dc1e82df70a3ddfe953f430b688c7cf42ac31a7`;
- `TASK.md` SHA-256
  `7b8d5cf229f3fb9908a07aafad3fdee1b42e1c083949bf60110cc80472c0bf85`.

## Decision

The verification matrix is a release input, not a passive report. CI must
reject malformed rows, duplicate targets, unknown threat/task references,
unknown release gates or statuses, missing required fields, and unavailable
repository-local evidence paths.

## Implemented controls

- `scripts/check-verification-matrix.mjs` parses the bounded Markdown matrix
  and validates its seven-column shape and unique `VT-*` identities.
- Threat references are checked against `THREAT_MODEL.md`; task references are
  checked against `TASK.md`; evidence references are constrained to regular
  files under `evidence/` or `docs/adr/`.
- Every threat-model verification target must have a corresponding matrix row.
- `npm run verify:matrix` is part of the macOS GitHub Actions verification job.

## Verification

```text
npm run verify:matrix
npm run verify:docs
npm run lint
npm run typecheck
git diff --check
```

Results: the matrix check passed for 28 targets, 24 threats, 30 tasks, and no
invalid references; documentation, style, typecheck, and diff checks passed.

## Boundary status

This closes machine enforcement of matrix structure and repository references.
It does not make an `OPEN` or `BLOCKED` row pass, does not replace focused or
real-Mac tests, and does not provide the pending remote CI run or independent
security review.
