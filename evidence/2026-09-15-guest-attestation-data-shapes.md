# Guest attestation data-shape evidence

Date: 2026-09-15
Source commit: `d276615`
Host: physical Darwin arm64 development host

## Boundary

Guest provenance is a signed trust input. The verifier must reject
prototype-provided values, accessors, symbols, and hidden fields before it
canonicalizes claims, checks the payload digest, or verifies an Ed25519
signature.

## Implementation

The guest attestation envelope, attestation payload, and nested guest identity
now require the shared `isPlainDataRecord()` representation. A malformed
object shape fails closed as `POLICY_DENIED`; no attestation is accepted or
used to enable the Virtualization task runner.

## Verification

- The focused guest attestation suite passes 6/6, including inherited and
  accessor-field rejection regressions.
- The non-overlapping package regression passes 505 total (499 pass,
  6 skipped, 0 fail).
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This evidence covers attestation representation integrity only. It does not
prove a native attestation producer, protected private-key distribution, VM
boot, guest isolation, remount resistance, or `mac_task_run` enablement.

## Rollback

Revert commit `d276615`. No attestation wire fields or persisted records are
changed.
