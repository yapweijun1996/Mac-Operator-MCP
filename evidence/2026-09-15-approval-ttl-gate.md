# Approval TTL-Gate Evidence

Date: 2026-09-15
Source commit: `0ab3fc9`
Host: physical Darwin arm64 development host

## Implemented boundary

Broker-owned Approval Authority issuance now rejects an Approval whose signed
TTL has already elapsed at the current Broker clock, before persistence or
audit. This is separate from the issuance nonce gate and prevents creation of
an immediately unusable authorization record.

## Verification

- Approval Authority and owner-only IPC tests: 10/10 pass, including current-
  expired nonce and already-expired Approval cases with no Approval or audit
  records created.
- Full physical-Darwin regression with install, sandbox, and Keychain gates:
  583/583 pass, 0 skipped, 0 failed.
- `npm run build`, `npm run typecheck`, `npm run lint`,
  `npm run verify:contracts`, and `git diff --check` pass.

## Remaining boundary

This closes current-clock expiry checks for Approval issuance. It does not
prove a human approval UI, protected production issuer-key storage,
unattended profile ownership, or final release-gate acceptance.

## Rollback

Revert `0ab3fc9`. The prior authority still rejects current-expired issuance
nonces, but could persist an Approval whose own TTL had already elapsed.
