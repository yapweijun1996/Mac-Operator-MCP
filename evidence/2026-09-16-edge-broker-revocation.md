# Edge-to-Broker Revocation Evidence

Date: 2026-09-16
Source revision: `8b3e8e2`
Host: physical Mac mini test runtime

## Boundary implemented

The Edge keeps a bounded, short-lived capability projection per verified
principal/session because the MCP HTTP handler constructs a fresh server for
each request. This projection is routing metadata only: every tool call still
crosses the authenticated Broker IPC gateway and the Broker rechecks edge,
edge-key, principal, session, policy, scope, target, and active-work
authority. If a previously verified session is revoked while a fresh MCP
server is being constructed, the cached projection lets the call reach the
Broker and return its stable `REVOKED` result instead of becoming an internal
server-construction error.

The cache is bounded to 256 identities and expires after 30 seconds. It never
stores bearer tokens or authorization keys.

## Verification

The authenticated Edge/Broker HTTPS integration now performs a successful MCP
call, persists an Edge revocation through the Broker store, and repeats the
call over the same client session; the result is `ok=false` with
`result_class=REVOKED`. The focused MCP/revocation suites pass 10/10, and the
complete Edge test set passes 66/66. Build, typecheck, lint, documentation,
matrix, and diff checks pass.

This proves stable revocation propagation through the tested local HTTPS/IPC
path; production revocation distribution, launchd installation, and physical
failure-injection evidence remain open.

