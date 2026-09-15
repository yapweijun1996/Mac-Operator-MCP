# Nested authenticated data evidence

Date: 2026-09-15
Source commit: `54fe71a`
Host: physical Darwin arm64 development host

## Boundary

Authenticated IPC is not safe merely because its outer object is a plain
record. Nested payloads, result objects, verification records, evidence, and
failure objects are also untrusted representation boundaries and must not
carry prototype, accessor, hidden, or symbolic fields into canonicalization,
redaction, or postcondition checks.

## Implementation

The Broker and privileged-helper status readbacks now require plain data
records. Helper command payloads, execution results, verification records,
evidence records, and nested failure objects are checked before field access
or redaction. Authority-control and Broker-status failure objects likewise
reject non-data nested values.

## Verification

- The focused authority-control, Broker-status, and privileged-helper suites
  pass 17/17, including nested payload/result rejection.
- The non-overlapping package regression passes 506 total (500 pass,
  6 skipped, 0 fail).
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This evidence covers nested local representation integrity only. It does not
prove OS peer identity, production packaging, VM isolation, credential
isolation, or privileged-helper enablement.

## Rollback

Revert commit `54fe71a`. No wire schema or persisted record format changes
are introduced.
