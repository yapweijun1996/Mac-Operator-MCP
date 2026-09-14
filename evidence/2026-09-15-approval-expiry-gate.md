# Approval Issuance Expiry-Gate Evidence

Date: 2026-09-15
Source commit: `8552210`
Host: physical Darwin arm64 development host

## Implemented boundary

Broker-owned Approval Authority issuance now checks the current clock against
the signed issuance nonce expiry before persistence, approval creation, or
audit. A current-expired nonce receives stable `AUTH_EXPIRED` and cannot
consume an issuance identity or create an unusable approval record.

## Verification

- Approval Authority and owner-only IPC tests: 9/9 pass, including a signed
  current-expired nonce whose Approval and audit records remain absent.
- Full physical-Darwin regression with install, sandbox, and Keychain gates:
  582/582 pass, 0 skipped, 0 failed.
- `npm run build`, `npm run typecheck`, `npm run lint`,
  `npm run verify:contracts`, and `git diff --check` pass.

## Remaining boundary

This closes current-clock nonce expiry admission for Approval issuance only. It
does not prove a human approval UI, protected production issuer-key storage,
unattended profile ownership, or final release-gate acceptance.

## Rollback

Revert `8552210`. The prior authority would still validate issuance shape and
timestamp age, but could accept a nonce that had already expired at the
current clock before the persistence transaction.
