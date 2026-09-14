# Broker Status IPC Error-Proof Evidence

Date: 2026-09-15
Source commit: `ad3adc9`
Host: physical Darwin arm64 development host

## Implemented boundary

The Broker Status IPC server now recovers a structurally valid unsigned status
request before freshness or HMAC checks. This lets a caller authenticate stable
`AUTH_EXPIRED` or `REPLAY_DENIED` failures without allowing the candidate to
enter replay admission, authorization, or status execution. Unknown fields and
other malformed envelopes remain on the invalid-request fallback proof.

## Verification

- Broker Status IPC test: 1/1 pass, including an expired signed request whose
  `AUTH_EXPIRED` response authenticates against the original request.
- Full physical-Darwin regression with install, sandbox, and Keychain gates:
  581/581 pass, 0 skipped, 0 failed.
- `npm run build`, `npm run typecheck`, `npm run lint`,
  `npm run verify:contracts`, and `git diff --check` pass.

## Remaining boundary

This closes error-proof consistency for the local status channel only. It does
not prove installed launchd ownership, production key distribution, remote
revocation propagation, or final release-gate acceptance.

## Rollback

Revert `ad3adc9`. The prior status channel remains available, but its client
cannot authenticate freshness failures that occur before request assignment.
