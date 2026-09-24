# R1 Revocation-Channel Timeout Evidence

Date: 2026-09-21

Scope: MOP-101/MOP-106 fresh owner-only R1 acceptance diagnosis.

## Reproduction

The verifier was run against the existing protected owner deployment:

```sh
node scripts/verify-personal-connection.mjs "/Users/yapweijun/Library/Application Support/MacOperator" .env
```

The redacted access-token boundary check reported matching issuer, audience,
and subject; all 17 requested scopes were present; `sid`, `azp`, and `jti`
were present; and the token was freshly issued. The MCP transport diagnostic
reported `authorization=true` on every request:

- `server/discover`: `200`
- `tools/list`: `200`
- first `tools/call` (`mac_docker_status`): `200`
- next `tools/call` (`mac_app_list`): `401`, `challenge=invalid_token`

The client did not omit the bearer header, and the failure was not a scope
denial. No token or response body was printed.

## Service-side evidence

The PM2 edge log for the same run recorded three successful protected MCP
requests followed by a `tools/call` that took `3003ms` and returned `401`.
The successful requests each had a corresponding `/oauth/status` `200`
request. The failed request had no corresponding `/oauth/status` arrival in
the service log.

The source revocation check uses a 3000ms bounded request to `/oauth/status`
and returns `true` on timeout or any malformed/unavailable response. The edge
then converts that fail-closed revocation result into the generic OAuth
`invalid_token` response. Therefore the observed timing and missing status
arrival are strong evidence of a public HTTPS revocation-channel timeout or
transport failure, not proof of a bad JWT. The server intentionally does not
expose the internal rejection reason.

## Boundary conclusion

The OAuth authorization-code flow and MCP bearer transport are functioning for
the initial requests, but fresh repeat R1 acceptance is not stable while the
Edge validates every token through the public status URL. This run is not
counted as full live acceptance. Existing successful R1 evidence remains
scoped to its recorded calls.

No deployment, service restart, permission change, policy change, GUI action,
or authority-state mutation was performed.

## Follow-up requirement

The deployment needs a separately authenticated local revocation channel or a
verified equivalent that does not depend on the public tunnel hairpin. Any
change must retain fail-closed behavior, exact session and scope validation,
startup binding to the owner issuer, and a real repeat acceptance plus
revocation readback.
