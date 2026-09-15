# Operator IPC data-shape evidence

Date: 2026-09-15
Source commit: `8ed6e298`
Host: physical Darwin arm64 development host

## Boundary

The owner-only policy-signer and approval operator channels must treat only
plain data from an authenticated wire envelope as authority input. Inherited
properties, accessors, symbols, and hidden properties must not influence
signature verification, replay admission, approval issuance, or policy
signer mutations.

## Implementation

`PolicySignerIpcServer` command parsing and `ApprovalAuthority` issuance
parsing now use the shared `isPlainDataRecord()` guard. Approval payloads are
checked independently as plain records before their signed digest and issuer
binding are evaluated. Malformed object shapes fail closed before persistence
or lifecycle execution.

## Verification

- The focused policy-signer and approval suites pass 14/14, including
  inherited and accessor-field rejection regressions.
- The non-overlapping package regression passes 504 total (498 pass,
  6 skipped, 0 fail).
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This evidence covers operator parser data-shape integrity only. It does not
prove production packaging, protected key distribution, installed launchd
startup, privileged helper installation, VM isolation, or capability
enablement.

## Rollback

Revert commit `8ed6e298`. No wire schema or persisted record format changes
are introduced.
