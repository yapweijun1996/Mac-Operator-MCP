# Official MCP Client HTTPS Boundary Evidence

Status: PASS for the local authenticated prototype; not a release record
Recorded: 2026-09-13 (Asia/Kuala_Lumpur)

## Source identity

- Exact commit: `5fd6b6b514bf108b6e409e61d45ccdf26436a2d9`
- Working tree: clean before this evidence document was added
- Runtime source manifest SHA-256: `cd97d56f653c95747e881b25091cc7dfc798f2f458d30f0d0ded4af113f5d4c2`
- Tool-contract manifest SHA-256: `656ebeede8a828c68022915b54c85c4a9b3f146df0668ca8464b677a7781945d`

This record covers only the local HTTPS Edge and injected-verifier prototype. It does not enable a tool or close a deployment gate.

## Procedure

The Edge test generated a one-day self-signed certificate in a temporary directory, served HTTPS on loopback, and removed the certificate and key in `finally` cleanup. The official `@modelcontextprotocol/client` SDK was configured with a pinned `2026-07-28` version negotiation mode and a test-only fetch adapter that connected to loopback while preserving the allowed Host and Origin headers.

The injected verifier returned a bounded test `AuthInfo` record. Its OAuth issuer URL was not forwarded as a Broker identity; the test used the constrained internal issuer ID expected by `PrincipalContext`. The gateway returned only `mac_health` as enabled.

## Observed results

- `Client.connect()` completed the modern `server/discover` exchange over HTTPS.
- Negotiated protocol version was `2026-07-28`.
- Server identity read back as `Mac-Operator-MCP` version `0.1.0`.
- `Client.listTools()` returned exactly `mac_health`; disabled capabilities were not advertised.
- TLS certificate material, the bearer token, and issuer credentials remained in the test process and did not enter the repository or Broker result.
- The test suite passed with 190 tests and no failed, skipped, cancelled, or todo cases after this slice.

## Boundary and limitations

The fetch adapter deliberately disables certificate verification only for this ephemeral self-signed test certificate; production clients must validate the deployed certificate chain. This is not evidence for a real OAuth issuer, remote DNS/tunnel, refresh/revocation propagation, multi-instance rate limiting, pagination/notification behavior, installed service lifecycle, or production key distribution. The SDK's default legacy mode is intentionally rejected by this Edge; clients must opt into the supported modern protocol revision.
