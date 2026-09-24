# R1 Full Verifier Timeout Evidence

Date: 2026-09-21

Scope: MOP-101/MOP-106 owner-only R1 live acceptance.

## Attempt

The repository verifier was run against the existing protected owner deployment:

```sh
node scripts/verify-personal-connection.mjs "/Users/yapweijun/Library/Application Support/MacOperator" .env
```

The verifier completed public OAuth discovery and the unauthenticated MCP
challenge. The owner login POST returned a redirect and the consent page GET
returned `200`. The verifier then timed out while submitting the consent POST;
the service diagnostics show no completed consent POST and no subsequent token,
MCP discovery, or tool call from this attempt.

The verifier did not print credentials or response bodies. It did not change
policy, scopes, permissions, deployment configuration, or host GUI state. The
PM2-managed personal service remained online. Because the consent POST did not
complete, this attempt is not counted as R1 tool acceptance.

## Follow-up attempt

A follow-up verifier run completed the same public discovery, owner login,
explicit consent, and S256 token exchange. The redacted claim-boundary check
reported matching issuer, audience, and subject; all 17 requested scopes were
present; `sid`, `azp`, and `jti` were present; and the token was freshly issued.
The first MCP client handshake nevertheless received `401 Unauthorized`.
Origin diagnostics showed the Edge calling the protected OAuth status endpoint
successfully with `200` before returning the `401`; no Broker tool result was
published. This confirms that the remaining failure is after token issuance,
but it does not yet identify whether the deployed MCP transport or its
authorization gate is responsible.

## Verification after the failed attempt

- `npm test`: 946 passed, 14 skipped, 0 failed.
- `npm run lint`: passed for 821 tracked files.
- `npm run verify:docs`: passed for 31 README links and 8 runbooks.
- `npm run verify:matrix`: passed for 29 targets, 25 threats, 31 tasks, and 7 evidence references.

## Boundary conclusion

The existing earlier R1 evidence remains valid for its recorded successful
calls. This attempt adds no new successful live tool evidence and leaves the
final owner-side live acceptance/revocation gate open.

## Rollback and readback

No source rollback is required. The service remained online and no host
configuration or authority state was intentionally changed by the verifier.
