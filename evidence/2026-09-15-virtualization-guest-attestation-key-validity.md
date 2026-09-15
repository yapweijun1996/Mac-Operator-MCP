# Virtualization guest attestation key-validity evidence

Date: 2026-09-15
Source commit: `5aa7d2e`
Host: physical Darwin arm64 development host

## Boundary

A trusted Ed25519 key's validity window must contain the complete lifetime of
the guest attestation it signs. Checking only the verifier's current clock
would allow a proof issued before key activation or expiring after key
retirement to pass during an overlapping clock interval.

## Implementation

`VirtualizationGuestAttestationVerifier` now requires
`issuedAtMs >= key.notBeforeMs` and `expiresAtMs <= key.expiresAtMs`, in
addition to the existing current-time, clock-skew, revocation, freshness,
payload-digest, and signature checks. Key validity is therefore part of the
signed-provenance admission boundary rather than only a current lookup check.

## Verification

- Guest attestation tests pass 5/5.
- The regression rejects an assertion issued before key activation and an
  assertion whose expiry extends past key retirement.
- The non-overlapping package regression passes 495 total (489 pass, 6
  skipped, 0 fail).
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This evidence covers key-window binding only. It does not provide a native
attestation producer, protected private-key distribution, approved VM image,
guest boot/isolation proof, or `mac_task_run` enablement.

## Rollback

Revert commit `5aa7d2e`. No key material, persisted state, or wire contract
was changed.
