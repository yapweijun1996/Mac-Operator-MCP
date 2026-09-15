# Edge JWKS redirect boundary evidence

Date: 2026-09-15
Source commit: `c97140a`
Host: physical Darwin arm64 development host
Scope: remote OAuth JWKS retrieval and endpoint identity

## Finding

The platform fetch implementation may follow HTTP redirects. A redirect from
the configured JWKS endpoint could otherwise make the Edge accept key material
from a different host or path than the startup-owned configuration.

## Implementation

The Edge-owned JWKS fetch wrapper now rejects responses marked as redirected
and rejects any non-empty final response URL that does not exactly match the
configured JWKS URL. The existing HTTPS URL validation, response MIME check,
256 KiB streaming body cap, timeout, cache, and generic invalid-token mapping
remain in force.

## Verification

- JWT verifier tests pass 7/7, including redirected response rejection.
- All Edge tests pass 40/40 with 0 skipped tests.
- The non-overlapping physical-Darwin regression passes 490/490 with 0
  skipped tests.
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass. Contract, canonical-JSON, and dependency-audit checks were already
  rerun for the preceding JWKS boundary and remain unchanged by this
  fetch-only hardening.

## Boundary

This prevents the configured remote JWKS request from accepting a followed
redirect or a mismatched final URL. It does not prove external OAuth issuer
availability, DNS/TLS pinning, issuer-side rotation/revocation propagation,
or public Edge deployment.

## Rollback

Revert commit `c97140a`. The 256 KiB body, MIME, token, and issuer checks from
the preceding boundary remain in the repository.
