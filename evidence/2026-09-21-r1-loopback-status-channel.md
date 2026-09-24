# R1 Loopback Revocation Channel Evidence

Date: 2026-09-21

Scope: MOP-101/MOP-106 Edge-to-Auth grant status reliability.

## Implementation

The Edge now supports an explicit, disabled-by-default loopback status
transport for newly provisioned personal snapshots. The logical request still
targets the issuer-bound public `/oauth/status` URL, while the transport:

- connects only to `127.0.0.1` over HTTPS;
- sends the issuer hostname as Host and TLS SNI;
- validates a protected owner CA bundle;
- requires the existing separate status-key bearer credential;
- bounds the request body, response body, timeout, method, content type, and
  exact status path; and
- fails closed on endpoint, certificate, host, response, abort, or timeout
  errors.

Startup configuration requires the loopback URL, issuer hostname, and CA path
to appear together. The CA path must be a canonical non-symlink file under the
Edge data root and must parse as a certificate authority. The personal
provisioner copies the protected origin CA into the new snapshot and binds the
Auth port from the owner config. Existing snapshots without these fields keep
the public status URL only while their older release remains running; the
current owner startup contract rejects missing loopback fields before opening
the new Edge listener.

## Verification

- Real local TLS server test: 1 passed, including CA validation, Host/SNI,
  issuer URL binding, JSON POST, bounded response readback, and loopback
  rejection.
- Edge startup/config and protected TLS focused tests: 11 passed.
- Full repository regression: 947 passed, 14 explicit skips, 0 failed (961
  total).
- `npm run typecheck`, `npm run lint`, `npm run verify:docs`,
  `npm run verify:matrix`, and `git diff --check` passed.
- Current physical-host Auth loopback readback returned HTTP `200` for a
  random nonexistent session with `active=false` and zero scopes. The
  protected status key, CA, and response body were not printed.
- The new read-only `npm run verify:personal:snapshot` rollout preflight
  rejected the currently running older snapshot because it does not bind the
  loopback OAuth status channel. The preflight performed no writes, restart,
  permission change, or authority mutation.

## Deployment boundary

No current PM2 process was restarted, no protected deployment files were
overwritten, and no tunnel, permission, policy, or authority state changed.
The currently running older snapshot has not yet been reprovisioned with the
loopback fields. A separate owner-authorized snapshot rollout, service
readback, repeated public verifier run, and revocation readback are still
required before claiming stable live R1 acceptance.
