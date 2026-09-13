# Filesystem case and Unicode canonicalization evidence

Status: PASS for the bounded lexical case-alias and normalized-search identity
slice; VT-FS-01 remains OPEN for remount identity, broader special-file
coverage, and release evidence.

- Date: 2026-09-13 (Asia/Kuala_Lumpur)
- Host profile: macOS 26.2, arm64
- Node: v25.5.0
- Source commit: `a742fbca607835179caa246ac1e36965545a88a5`
- Working tree before this evidence document: clean after the source commit
- Contract version: `0.1`
- Host mutation: none; only a temporary test directory was created and removed

## Boundary exercised

The filesystem adversarial fixture verifies two independent identity rules:

- A path using an upper-cased temporary root and a case-altered child is
  rejected by `planPath` with the stable outside-authorized-root policy error.
  The Broker therefore does not assume a case-insensitive filesystem when
  proving lexical containment.
- A decomposed Unicode query (`Cafe` plus combining acute) finds a composed
  `Café.txt` entry through the existing NFKC and locale-lowercase search key.
  The returned match is checked against the native `realpath` identity, which
  is `/private`-canonicalized on this host where applicable.

No protected path, credential content, service, policy, or capability state was
accessed or changed.

## Verification

- Focused filesystem suite: `node --test packages/broker/dist/filesystem-inspector.test.js` — 26/26 passed.
- Default full suite: `npm test` — 363 tests, 361 passed, 2 opt-in real-sandbox tests skipped.
- Opt-in host suite: `MOPS_REAL_SANDBOX=1 npm test` — 363/363 passed, 0 skipped.
- Type/build: `npm run build` and `npm run typecheck -- --pretty false` — passed.
- Contract validation: `npm run verify:contracts` — 44 unique contracts validated.
- Dependency audit: `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- Boundary check: `git diff --check` — passed.

## Source hash

```text
b3fc94cd8fbb9cfc4616aca65e2a07e63750f24a75442ab75007cf7bdb813ff9  packages/broker/src/filesystem-inspector.test.ts
```

## Remaining limits

This fixture intentionally does not claim that all macOS volumes share one
case or Unicode normalization policy. Removable-volume remount identity,
same-volume replacement under a mount race, directory create/rename races,
special-file policy, and resource-exhaustion evidence remain open. Returned
native canonical paths remain authoritative for subsequent Broker checks.
