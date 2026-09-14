# Cross-Runtime JSON Number Canonicalization Evidence

Date: 2026-09-15
Source commit: `c31f82a`
Host: physical Darwin arm64 development host

## Implemented boundary

The strict JSON scanner now normalizes each syntactically valid number without
floating-point conversion, then compares that spelling with Node's
ECMAScript `JSON.stringify` result. A mismatch fails closed. This prevents a
native lexical canonicalizer from preserving a value that Node rounded,
underflowed, or converted to infinity before request authentication,
persistence, or audit hashing.

## Verification

- Canonical JSON regression: 5/5 pass, including exponent thresholds,
  negative zero, precision-changing integers, rounding-divergent fractions,
  underflow, and overflow rejection.
- Full physical-Darwin regression: 593/593 pass, 0 skipped, 0 failed.
- `npm run typecheck`, `npm run lint`, `npm run verify:contracts`,
  `npm run verify:canonical:native`, and `git diff --check` pass.

## Remaining boundary

This closes the implemented Node input gate for values that cannot reproduce
the native lexical canonical form. Independent native number-vector expansion,
runtime fuzzing, and final release acceptance remain open.

## Rollback

Revert `c31f82a`. Strict JSON parsing would no longer reject numeric spellings
that diverge after Node's floating-point conversion.
