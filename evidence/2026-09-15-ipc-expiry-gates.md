# IPC Expiry-Gate Evidence

Date: 2026-09-15  
Source commit: `6947608`  
Host: physical Darwin arm64 development host

## Implemented boundary

Privileged Helper command and status authentication now reject requests whose
current nonce/command expiry has elapsed before replay admission, authorization,
adapter dispatch, or status readback. Policy Signer command authentication now
applies the same current nonce-expiry gate before manager mutation. Structurally
valid stale Helper requests retain an authenticated `AUTH_EXPIRED` response;
malformed envelopes remain on the invalid-request fallback proof.

## Verification

- Privileged Helper focused tests: 9/9 pass, including stale command and status
  requests with authenticated `AUTH_EXPIRED` responses and no dispatch/readback
  side effects.
- Policy Signer focused tests: 2/2 pass, including a current-expired nonce
  request that leaves the policy store unchanged.
- Full physical-Darwin regression with install, sandbox, and Keychain gates:
  581/581 pass, 0 skipped, 0 failed.
- `npm run build`, `npm run typecheck`, `npm run lint`,
  `npm run verify:contracts`, and `git diff --check` pass.

## Remaining boundary

This closes current-clock expiry admission for the Helper and Policy Signer
IPC paths only. It does not prove installed launchd ownership, production key
distribution, root helper provenance, real privileged adapter execution, or
release-gate acceptance.

## Rollback

Revert `6947608`. The prior channels remain available, but an already-expired
request could progress farther before failing and its side-effect boundary was
not explicitly regression-tested.
