# OAuth authority revocation IPC boundary

- Date: 2026-09-22
- Scope: Auth-derived Edge token revocation propagation into the unprivileged Broker
- Status: authenticated local IPC, durable Broker session revocation, and bounded idle-session polling verified; direct issuer push remains open
- Host boundary: HTTPS Edge, owner OAuth status check, unprivileged Broker, owner-authenticated Unix IPC

## Implemented boundary

The Edge now emits a separate versioned `oauth_authority_revoked` event when its
verified OAuth status check reports that a token's issuer authority is no longer
valid. The event binds `edgeId`, `authenticationKeyId`, principal, session,
timestamp, request ID, and nonce; the existing Edge-to-Broker key authenticates
both the event and the Broker response.

After a successful token verification, a bounded Edge monitor retains only the
session identity, scopes, expiry, and token identity. It polls the existing
owner-authenticated status channel for those recently accepted sessions, so an
idle Job can observe an explicit issuer revocation without a new MCP request.
Transport or malformed-status failures remain retryable monitor failures; the
request verifier still fails closed, but the watcher does not convert a status
outage into a Broker revocation.

The Broker parses the event outside the MCP tool request shape, rechecks its
own trusted Edge/key policy, rejects stale/revoked authority, and admits the
event into a durable schema-version-16 replay ledger. A first accepted event
revokes the named Broker session and cancels matching queued Jobs. Active work
observes the durable authority loss on its next control check and preserves an
`UNKNOWN` outcome when completion cannot be proven. Replayed request IDs or
nonces are denied.

The Edge IPC client validates socket identity before and during connection,
requires a strict authenticated revocation response, and the gateway exposes
the propagation method only as a host lifecycle seam rather than an MCP tool.

## Verification

Focused contract, Broker, persistence, schema, replay, JWT, and real Unix IPC
tests passed:

```text
npm run build
node --test --test-timeout=120000 \
  packages/edge/dist/jwt-verifier.test.js \
  packages/edge/dist/ipc-client.test.js \
  packages/contracts/dist/auth.test.js \
  packages/broker/dist/broker.test.js \
  packages/broker/dist/persistence.test.js \
  packages/broker/dist/schema-layout-invariants.test.js \
  packages/broker/dist/replay-row-invariants.test.js
```

Result: 178 tests total, 172 passed, 6 skipped, 0 failed.

The IPC test exercises `AuthenticatedIpcBrokerGateway.revokeSession()` over a
real owner-bound Unix socket and reads the resulting durable Broker session
revocation. The JWT test proves that a verified authority loss invokes the
propagation callback and still returns a generic invalid-token result. The
monitor tests prove bounded session polling, retry after a temporary status
outage, and propagation of an idle-session revocation. The Broker test proves
response authentication, session revocation, and replay denial. Persistence
tests prove replay identity retention across restart and exact expiry
reclamation.

The final full repository run passed 1,042 tests: 1,027 passed, 15 explicit
skips, and 0 failures. An earlier full run had one isolated timing failure in
the existing process-supervisor descendant test; that test passed 3/3 when
rerun alone and the subsequent full runs passed.

## Limits and rollback

This boundary is not an Auth-to-Edge push. The Edge watcher polls the existing
status endpoint and only tracks sessions that have successfully crossed the
Edge; it is bounded and stops with the Edge service. A future direct issuer
push/webhook remains optional and would need its own authenticated channel and
lifecycle policy. Public mutation/task scopes, root helper deployment, and
unrestricted shell/GUI access remain disabled.

The change is reversible by disabling the OAuth status/revocation propagation
configuration; no live R1 grant, tools list, or public mutation scope was
changed by this work.
