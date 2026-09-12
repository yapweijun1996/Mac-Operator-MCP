# Signed OAuth Access-Token Boundary Evidence

Status: PASS for the local issuer-compatible prototype; not a release record
Recorded: 2026-09-13 (Asia/Kuala_Lumpur)

## Source identity

- Exact implementation commit: `b851984c7e721cef319936ef03ee5f0f904c262b`
- Working tree: clean before this evidence document was added
- Runtime source manifest SHA-256: `7a3827656067e34ea643dfc8e6d872306b5ac0a292ac28d7facea34e8865fb2b`
- Tool-contract manifest SHA-256: `656ebeede8a828c68022915b54c85c4a9b3f146df0668ca8464b677a7781945d`

This record covers the Edge JWT/JWKS verifier and its local HTTPS client path. It does not prove a deployed Authorization Server or public release.

## Implemented boundary

`createJwtAccessTokenVerifier` accepts exactly one HTTPS issuer/resource configuration and exactly one local or remote JWKS source. It pins asymmetric algorithms, bounds token size and token age, requires `iss`, `aud`, `sub`, `iat`, `exp`, and `jti`, checks the exact resource URL, filters scopes against the governed contract taxonomy, maps the issuer URL to a bounded internal issuer ID, and returns only the projected identity fields required by the Broker. A host-owned revocation callback receives only issuer/subject/session/jti/expiry metadata and any positive or callback-failure path rejects the token.

Remote JWKS retrieval has a 3-second fetch timeout, bounded cache age, and cooldown. The verifier does not log or return token contents on failure.

## Evidence

- JWT tests accepted a valid RS256 token and verified signature, issuer, resource/audience, expiry, iat, jti, client identity, known scopes, and internal issuer projection.
- Negative tests rejected wrong audience, expired token, missing jti, malformed configuration, and a revocation callback decision.
- Remote-JWKS tests fetched once and reused the bounded cache for a second verification.
- The official MCP client HTTPS test used a signed RS256 JWT against the local TLS 1.3 Edge, completed pinned `2026-07-28` `server/discover`, and listed exactly the Broker-enabled `mac_health` tool.
- The same HTTPS boundary returned protected-resource metadata (`200`), rejected a malformed token (`401`), rejected a scope-reduced token (`403`), rejected an expired token (`401`), and rejected a token after the host-owned revocation callback was activated (`401`); no Broker capability call was made for the rejected requests.
- The full repository test suite passed 193 tests with no failures, skips, cancellations, or todos.

## Remaining boundary

The issuer URL and token were generated inside the test process; no external Authorization Server issued the token. Authorization-code/PKCE or client-credentials issuance, live issuer metadata/JWKS rotation, remote revocation propagation, certificate-chain deployment, tunnel operation, multi-instance rate limits, and production key storage remain open. The local self-signed certificate is accepted only by the test fetch adapter and must never be used as a production trust policy.
