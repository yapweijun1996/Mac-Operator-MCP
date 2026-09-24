# R1 Public 29-Call Probe and Revocation

Date: 2026-09-21
Profile: `R1` owner-only bounded read-only
Verifier: `scripts/verify-personal-connection.mjs`
Endpoint: `https://mac.yapweijun1996.com/mcp`

## Result

The repeat public HTTPS probe completed successfully after the verifier's
per-request timeout was increased from 15 seconds to 30 seconds. The first
owner token exchange in the preceding run completed just after the old timeout
window, so the earlier failure was a verifier timing issue rather than a
credential or MCP contract failure.

Verified in one run:

- Public OAuth discovery and the unauthenticated MCP challenge
- Owner login, explicit consent, and S256 authorization-code exchange
- Exact discovery of all 30 R1 read-only tools
- 29 real read-only MCP calls with successful bounded result envelopes
- Revocation of the temporary verifier grant
- Rejection of the next MCP request using the revoked access token

## Safety boundary

The verifier creates and revokes its own temporary grant. It does not replace
the separate real-ChatGPT acceptance path, and it records no credentials,
tokens, or response payloads. No mutation, GUI, destructive, or privileged
operation is part of the probe.

Conclusion: the R1 public OAuth, tool-discovery, read-call, and revocation
boundaries pass together at the service/API level. ChatGPT UI acceptance and
client-side revocation evidence remain separate gates.
