# Edge-to-Broker HTTPS and Authenticated IPC Evidence

Status: PASS for the local layered prototype; not a deployment or release record
Recorded: 2026-09-13 (Asia/Kuala_Lumpur)

## Source identity

- Exact source commit: `1fecf5ba2dcb19046caf3bc55905a06515d6df96`
- Working tree: clean before this evidence document was added
- Host: macOS 26.2, arm64
- Runtime: Node.js v25.5.0
- Tool contract version: `0.1`
- Policy version: `policy-0.1`
- Test fixture SHA-256: `packages/edge/src/edge-broker-https.test.ts` = `09acc248cabb75c5562ced24b05bf5febef40dbb14e1956c88a2581313710d71`
- Lockfile SHA-256: `package-lock.json` = `e46ddc3690f8b07cc7b807e14410f821e5224f5a877c2e83e38f45cd5957c4f7`

## Procedure

The test creates a temporary owner-only directory containing SQLite state, a
temporary TLS certificate/key, and a Unix-domain Broker socket. It starts a
real `BrokerIpcServer` with the current-process peer verifier and a Broker
policy that enables only the `mac.control.read` capability family for the
test principal. The Edge uses `EdgeRequestFactory` and `BrokerIpcClient` to
sign requests and verify the complete HMAC-bound response over local IPC.

The HTTPS Edge uses a real RS256 JWT verifier with a local JWKS, exact issuer
and resource binding, and a pinned MCP SDK protocol version. The official MCP
client connects through TLS 1.3, discovers the Broker-filtered capabilities,
and calls `mac_health`. The Broker executes the request, verifies the signed
request, authorizes the principal and target, and returns the authenticated
result through the same chain.

## Results

- Focused test: `node --test packages/edge/dist/edge-broker-https.test.js` — 1 passed, 0 failed.
- Full default suite: `npm test` — 350 tests, 348 passed, 0 failed, 2 opt-in real-sandbox tests skipped.
- Opt-in real-host suite: `MOPS_REAL_SANDBOX=1 npm test` — 350 tests, 350 passed, 0 failed, 0 skipped.
- The discovered tools were exactly `mac_capabilities` and `mac_health` for the granted scope.
- `mac_health` returned a `SUCCEEDED` result through HTTPS, signed local IPC, Broker authorization, and MCP response handling.
- The bearer token was not present in Broker audit rows.
- Reusing one signed Broker request over the same IPC boundary returned
  `REPLAY_DENIED` on the second admission.
- Temporary TLS material, SQLite state, socket, and test directory were removed during cleanup.

## Boundary and limitations

This closes the local layered path only. The test does not install launchd
services, expose a public endpoint, use a production OAuth issuer or
certificate chain, distribute production keys, enable mutations, or prove
remote tunnel, multi-instance rate-limit, restart, or installed-service
evidence. The Broker and Edge run in one test process while communicating
through the real authenticated UDS boundary; a separately packaged process
deployment remains open.
