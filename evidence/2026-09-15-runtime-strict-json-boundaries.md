# Runtime Strict JSON Boundary Evidence

Date: 2026-09-15
Source commit: `0bcb354`
Host: physical Darwin arm64 development host

## Implemented boundary

Runtime JSON returned by Broker-owned child adapters, Authority Control IPC,
stored Job/result metadata, audit evidence, and encrypted-backup records now
passes through the bounded `parseJsonStrict` scanner before validation or
canonical hashing. Duplicate keys (including escaped equivalents), unpaired
surrogates, malformed grammar, and trailing data fail closed. Static schema
files and the scanner's own internal token parsing remain separate trusted
implementation inputs.

## Verification

- `rg` confirms no direct runtime `JSON.parse` remains outside static schema
  loading and canonical parser internals.
- Targeted adapter/IPC/persistence regression: 79/79 pass.
- Full physical-Darwin regression: 592/592 pass, 0 skipped, 0 failed.
- `npm run typecheck`, `npm run lint`, and `git diff --check` pass.

## Remaining boundary

This closes parser divergence at implemented runtime readers only. Broader
numeric canonicalization across runtimes, schema-file supply-chain identity,
runtime fuzzing, and final release acceptance remain open.

## Rollback

Revert `0bcb354`. Runtime readers would return to direct JSON parsing at the
listed boundaries.
