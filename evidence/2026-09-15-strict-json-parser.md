# Strict JSON Parser Boundary Evidence

Date: 2026-09-15  
Source commit: `ecc3a98`  
Host: physical Darwin arm64 development host

## Implemented boundary

The contracts package now scans JSON text before `JSON.parse` with a bounded
recursive validator. Implemented Broker/Edge protocol, protected
configuration, persistence, audit, and guest readers reject duplicate object
keys (including escaped equivalents), unpaired UTF-16 surrogates, malformed
grammar, and trailing data. Strict fatal UTF-8 decoding runs before the scan.
Canonical serialization also rejects unpaired surrogates in values and object
keys, keeping JavaScript behavior aligned with the native `jcs-utf8-v1`
canonicalizer at these trust boundaries.

## Verification

- Focused trust-boundary tests pass 49/49.
- Full physical-Darwin regression with install, sandbox, and Keychain gates:
  588/588 pass, 0 skipped, 0 failed.
- Native canonical JSON probe passes 5/5 fixed wire vectors.
- `npm run build`, `npm run typecheck`, `npm run lint`,
  `npm run verify:contracts`, and `git diff --check` pass.

## Remaining boundary

This closes duplicate-key, lone-surrogate, malformed-grammar, and trailing-data
parser divergence for implemented boundaries. Broader cross-runtime numeric
canonicalization, property/fuzz coverage, and final release acceptance remain
open.

## Rollback

Revert `ecc3a98`. A rollback would restore the previous JSON readers and reopen
the duplicate-key and lone-surrogate divergence described above.
