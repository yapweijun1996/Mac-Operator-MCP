# Native HTTPS Edge-to-Broker Evidence

Status: Partial real-Mac transport boundary; installed deployment remains open

## Scope

This smoke closes the previously separate HTTPS Edge and native Broker IPC
paths in one test. On Darwin, the HTTPS Edge gateway reaches a Broker served by
`MacOsNativeBrokerIpcServer`; non-Darwin runs retain the generic UDS fallback
for portable regression coverage.

## Procedure and result

- Created a temporary zero-capability Broker policy with one read scope and a
  protected Edge HMAC key.
- Captured the current process PID/start-time identity and configured the
  native Broker listener with exact UID/GID and process identity binding.
- Started the HTTPS MCP Edge with TLS, OAuth JWT verification, Host/Origin
  allowlists, bounded rate limits, and the authenticated `BrokerIpcClient`.
- Used the official MCP client to discover `mac_capabilities`/`mac_health`,
  invoked `mac_health`, verified the signed Broker response, then replayed the
  same request and observed `REPLAY_DENIED`.
- Confirmed the bearer token was absent from Broker audit rows; temporary
  sockets, database, TLS material, and keys were removed in `finally` cleanup.

## Verification

`node --test packages/edge/dist/edge-broker-https.test.js` passed on the
physical Darwin arm64 host after the test selected the native transport.

## Boundary

This proves the local HTTPS-to-native-UDS composition, response authentication,
replay rejection, peer start-time binding, and audit redaction. It does not
prove a separately spawned production Edge process, installed LaunchAgent
configuration, Developer ID/notarization, remote OAuth issuer operation, or
production key rotation/hot reload.

Host: Darwin arm64, Node v25.5.0. No secret bytes or private keys are recorded.
