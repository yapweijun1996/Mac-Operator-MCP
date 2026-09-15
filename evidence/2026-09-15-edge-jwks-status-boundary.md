# Edge JWKS response-status boundary evidence

Date: 2026-09-15
Source commit: `fc04641`
Host: physical Darwin arm64 development host
Scope: remote OAuth JWKS retrieval and HTTP response handling

## Finding

The bounded JWKS fetch path validated endpoint identity, MIME type, and body
size, but it did not explicitly require a successful HTTP response before
handing response bytes to the key parser. An error response carrying JSON must
not be treated as key material.

## Implementation

The Edge-owned JWKS fetch wrapper now requires `response.ok` and a 2xx status
before reading or parsing the response body. Non-success responses fail closed
and are mapped to the verifier's generic invalid-token error. Redirect and
final-URL checks, strict JSON MIME validation, the 256 KiB streaming body cap,
timeout, cache, and cooldown remain in force.

## Verification

- JWT verifier tests pass 8/8, including 199, 300, 404, and 500 responses.
- All Edge tests pass 41/41 with 0 skipped tests.
- The non-overlapping physical-Darwin regression passes 491 total: 485 pass,
  6 skipped, 0 fail.
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

## Boundary

This closes the response-status interpretation boundary before `jose` parses
remote key material. It does not prove external OAuth issuer availability,
DNS/TLS pinning, issuer-side rotation/revocation propagation, or public Edge
deployment.

## Rollback

Revert commit `fc04641`. The prior endpoint-identity, MIME, and body-size
checks remain in the repository.
