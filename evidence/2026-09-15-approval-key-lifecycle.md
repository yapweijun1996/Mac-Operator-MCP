# Approval Issuer Key Lifecycle Evidence

Date: 2026-09-15
Source commit: `f55fe05`
Host: physical Darwin arm64 development host

## Implemented boundary

`ApprovalAuthority` now owns defensive copies of issuer HMAC keys and
provides an idempotent `dispose()` boundary that wipes and clears those
copies. Once disposed, issuer-key addition and approval issuance fail closed
with the stable `CANCELLED` error. The source key supplied by the lifecycle
owner remains separate and is not modified by authority disposal.

## Verification

- Approval authority and owner-only approval IPC tests: 8/8 pass.
- The disposal regression covers repeated disposal, post-disposal issuance,
  and post-disposal key addition.
- `npm run build` and `git diff --check` pass.

## Remaining boundary

This closes issuer-key memory lifetime for the approval authority instance.
It does not provide a human approval UI, protected production Keychain
distribution, unattended profile ownership, or privileged approval release.

## Rollback

Revert commit `f55fe05`; approval issuance authentication and persistence
semantics remain otherwise unchanged.
