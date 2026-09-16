# HTTPS Edge new-session revocation evidence

Date: 2026-09-16
Source revision: `c0fa6f0`
Host: Darwin arm64, Node.js 25.5.0

## Boundary exercised

The HTTPS Edge authenticates a new MCP client request without an
`Mcp-Session-Id`, projects only the verified token identity, and probes the
Broker capability authority before handing the request to the MCP SDK. When
the Broker returns `REVOKED`, the Edge fails closed with a stable HTTP
authorization response instead of allowing the SDK's generic internal-error
fallback.

## Verification

- The test first completes a normal HTTPS MCP discovery and verifies the
  Broker-enabled tool projection.
- After the test gateway begins returning `REVOKED` for `mac_capabilities`, a
  different verified token starts a session-less `server/discover` request.
- The Edge returns HTTP `403` with the exact redacted body
  `{ "error": "revoked", "result_class": "REVOKED" }`.
- Session-bound requests continue through the normal MCP handler; the Broker
  remains the final authority for tool execution.
- Capability discovery and MCP factory tests continue to verify that bearer
  tokens are not forwarded as Broker identity data.

## Verification commands

```text
npm run typecheck -- --pretty false
node --test packages/edge/dist/https-edge.test.js packages/edge/dist/mcp-server.test.js
node --test packages/edge/dist/*.test.js
npm run lint
npm run verify:docs
npm run verify:matrix
```

Results: focused HTTPS/MCP tests pass 11/11; the complete Edge suite passes
66/66; typecheck, lint, documentation links, and matrix checks pass.

## Limits

This proves the local HTTPS session-start authorization boundary only. It does
not prove remote revocation distribution, installed launchd lifecycle,
physical worker termination, or production key rotation.
