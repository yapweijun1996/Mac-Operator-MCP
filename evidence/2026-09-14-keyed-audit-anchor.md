# Keyed audit-tail anchor evidence

Date: 2026-09-14
Host: development macOS host; no production service installation
Scope: `AuditAnchorManager` and optional `BrokerStore` audit-tail binding

## Decision

The Broker can optionally bind the SQLite audit tail to a separate, owner-only
0600 sidecar. The sidecar stores only the latest sequence, event hash, key ID,
and an HMAC-SHA-256 over those non-secret fields. The key is supplied at startup
by an explicit protected source and remains memory-only; a dedicated Keychain
factory binds that source to the canonical Broker executable ACL. The MCP Edge
cannot select the sidecar path or key identity.

SQLite commits publish the sidecar only after the transaction commits. If the
publication fails, the database is ahead of the sidecar and the next startup
fails closed rather than inferring trustworthy audit state. Startup also rejects
a missing, stale, forged, or unexpected sidecar.

## Verification

- `AuditAnchorManager` publish/verify, monotonicity, forged-sidecar, and missing
  anchor tests pass.
- BrokerStore restart readback accepts a matching sidecar and rejects a forged
  sidecar while the SQLite audit rows remain unchanged.
- Persistence test suite: 43/43 passed.
- Full regression with real sandbox and Keychain opt-ins: 475 tests, 474
  passed, 0 failed, 1 explicit skip.
- `npm run typecheck` passed.
- `npm run lint` passed.
- `npm run verify:contracts` passed for 44 tool contracts and the ledger schema.
- `npm audit --omit=dev --audit-level=high` reported 0 vulnerabilities.
- `git diff --check` passed.

## Limits

This is a local keyed-integrity boundary, not an external immutable log. An
attacker who can read the configured HMAC key can forge the sidecar; an attacker
who can roll back both the database and sidecar remains outside this evidence.
The implementation is not enabled by packaged startup, and cross-process
sidecar locking plus a production Keychain anchor item still require a reviewed
single-owner service policy and real signed-artifact evidence.
