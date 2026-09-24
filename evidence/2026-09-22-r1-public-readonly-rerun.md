# R1 public HTTPS read-only rerun

- Date: 2026-09-22
- Scope: current owner-only public OAuth/MCP deployment
- Status: public R1 read-only verification passed and the temporary grant was revoked
- Mutation: only the probe's own temporary OAuth client/grant was created and revoked

## Verification

The read-only verifier ran against the protected `MacOperator-r1f` state root:

```text
MOPS_VERIFY_PROJECT_ROOT="$PWD" \
  node scripts/verify-personal-connection.mjs \
  "/Users/yapweijun/Library/Application Support/MacOperator-r1f" .env
```

The public HTTPS flow passed:

- protected-resource discovery and unauthenticated MCP challenge;
- owner login, explicit consent, S256 PKCE exchange, and public HTTPS token delivery;
- issuer, audience, subject, SID, AZP, JTI, expiry, and 17/17 required scope claims;
- exact 30-tool `tools/list` parity;
- 29/29 real read-only `tools/call` operations across app, capabilities,
  filesystem, Git, Docker, package, process, network, logs, service, storage,
  and system inspection;
- temporary grant revocation, with the next MCP request rejected.

The probe printed only bounded diagnostics and did not persist access tokens or
passwords. It did not call mutation, GUI-control, task, root-helper, or
privileged tools.

## Limits

This is current API/client evidence, not a fresh ChatGPT UI call. It confirms
R1 read-only availability only; D1/G1/P1 scopes and public tools remain gated by
approval, sandbox, Accessibility, Developer ID/notarization, helper lifecycle,
rollback, and independent review evidence.
