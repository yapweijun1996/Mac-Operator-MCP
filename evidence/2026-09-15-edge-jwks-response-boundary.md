# Edge remote JWKS response boundary evidence

Date: 2026-09-15
Source commit: `3cca22c`
Host: physical Darwin arm64 development host
Scope: remote OAuth JWKS retrieval and untrusted response parsing

## Finding

The Edge delegated remote JWKS response parsing to `jose` without a
project-owned response-body cap or MIME check. A misconfigured or hostile
endpoint could therefore return an unexpectedly large body before JSON
validation, increasing memory and parser pressure at the authentication
boundary.

## Implementation

The Edge now supplies `jose` with an Edge-owned fetch wrapper for every remote
JWKS source. It accepts only `application/json` or
`application/jwk-set+json`, rejects invalid or oversized `Content-Length`, and
streams the body into a bounded 256 KiB buffer before reconstructing the
response for strict JWKS parsing. The existing 3-second timeout, cache age,
unknown-key cooldown, issuer/audience checks, and generic invalid-token mapping
remain in force.

## Verification

- JWT verifier tests pass 5/5, including oversized and non-JSON responses that
  fail closed as invalid tokens.
- All Edge tests pass 38/38 with 0 skipped tests, covering HTTPS, MCP, IPC,
  JWT, rate limiting, startup, contracts, and TLS boundaries.
- The physical-Darwin regression over all non-overlapping test files passes
  487/487 with 0 skipped tests. The repository already had a separate
  long-running `broker.test.js`/`persistence.test.js` process, so those two
  files were excluded rather than duplicated.
- `npm run build`, `npm run typecheck`, `npm run lint`, `npm run verify:contracts`,
  `npm run verify:canonical:native`, `npm audit --audit-level=high`, and
  `git diff --check` pass.

## Boundary

This bounds and classifies the remote JWKS response before parsing. It does not
prove external OAuth issuer availability, certificate-chain deployment,
issuer-side rotation/revocation propagation, or remote production hosting.

## Rollback

Revert commit `3cca22c`. The remote JWKS resolver returns to the previous
project-unwrapped fetch path; no Broker policy or persisted schema changes are
involved.
