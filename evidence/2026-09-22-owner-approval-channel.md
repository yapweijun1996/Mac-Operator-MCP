# Owner approval channel evidence — 2026-09-22

## Result

The owner-only approval channel now has a reusable client and a deliberately
small local CLI surface. The remote MCP request cannot create or attach its
own approval. A local owner command creates a single-use, non-unattended
approval bound to the exact principal, tool, contract, target, payload digest,
policy version, and expiry, then sends a signed issuance to the separate local
approval IPC server.

## Implemented boundary

- `ApprovalIpcClient` signs the canonical issuance envelope, validates the
  owner approval payload, checks the owner-only socket parent and socket
  device/inode before sending, and verifies the exact approval readback.
- `mac-operator-approval issue` requires the protected Broker database,
  activated issuer-key configuration, issuer/key identity, exact target and
  payload digest, bounded TTL, `--confirm issue`, and a TTY confirmation of the
  displayed `APPROVE <approvalId>` token.
- The same command accepts `--request-id` to load one live Broker-owned
  `approval_previews` row. The CLI copies only those exact binding fields,
  derives a deterministic approval ID from the request ID, and never accepts
  caller-supplied target or payload fields in this mode.
- The CLI does not expose raw key material and cannot request unattended mode;
  `useLimit` is fixed to one for this owner path.
- Before transport, the CLI renders a bounded preview containing the exact
  issuer, requesting principal, tool/contract, target, payload digest, policy,
  approval class, expiry, and use limit. It rejects non-TTY input, mismatched
  confirmation tokens, overlong input, and confirmation timeout.
- When a real Broker mutation reaches the approval boundary without a
  matching approval, Broker persistence records a 120-second `approval_previews`
  row containing only the exact non-secret binding facts. Startup validates
  the preview-to-Request linkage, and the request's raw arguments are never
  copied into the preview ledger.
- Preview lifecycle is durable and single-use: `pending` becomes `issued`
  only after exact approval readback/linkage, then becomes `consumed` in the
  same Broker transaction that records mutation intent. A restart after IPC
  success can recover the deterministic approval instead of issuing a second
  random approval.
- The optional browser workflow now uses a separate approval session and
  owner login, same-origin/CSRF-protected review and decision forms, and a
  non-secret preview page. Auth sends only bounded preview/issuance messages
  over supervisor IPC; issuer-key bytes remain in the supervisor/Broker
  process and never enter the browser-facing Auth process.
- Browser approval is assembled only when the protected issuer runtime is
  explicitly enabled. The default provisioned profile has no `/approval`
  route, no approval socket, and no mutation/public tools enablement.
- Issuer-key bytes are copied only into the client and wiped on disposal. The
  current personal R1 profile remains read-only and no public OAuth scope,
  tools-list entry, or live mutation switch was changed.

## Protected personal supervisor assembly

The reusable Broker startup factory is now connected to the personal supervisor
through a fixed owner-controlled `personal/approval-issuer.json` document. New
provisioning writes this document with `enabled: false`; it does not create or
activate issuer key material. A missing document is also treated as disabled so
existing R1 installations retain their current behavior.

When explicitly enabled by a protected local configuration, startup accepts
only the fixed `personal/approval-keys.json` and `personal/run/approval.sock`
locations, restores an already activated key configuration, binds the channel
to the supervisor's owner UID/GID, and starts it only after the Broker socket.
Shutdown closes the approval channel before the Broker/store cleanup. Invalid,
partial, non-canonical, or misplaced configuration fails closed.

The live personal deployment was not changed, no issuer key was activated, and
no mutation scope or public tools-list entry was enabled. The browser route is
covered as an optional assembled Auth workflow; it is not enabled in the live
R1 deployment.

## Verification

- Approval Authority/IPC/client tests: 13/13 pass.
- Owner CLI parser/execution/preview tests: 6/6 pass.
- Browser approval checks: 2/2 pass; the complete Auth suite is 20/20,
  including absent-route, owner-login, CSRF, non-secret preview, issuance, and
  one-use session checks.
- Protected personal startup/config checks: 13/13 pass across the auth and
  Broker startup suites.
- Typecheck and lint pass.
- Full repository regression: 1021/1036 pass, 15 explicit skips, 0 failures.
- The existing approval server tests continue to verify denied peer handling,
  trailing-frame rejection, signed issuer provenance, nonce replay denial, and
  durable approval persistence.

## Remaining gates

This now includes an optional browser owner-confirmation workflow, but not
public mutation enablement. Production still requires an installed activated
issuer configuration, browser-to-supervisor process evidence, OAuth scope and
public tools-list parity, ChatGPT end-to-end mutation evidence,
revocation/active-work semantics, and the complete audit/recovery gate. The
default R1 deployment remains unchanged.

## OAuth profile parity follow-up

Auth now selects an explicit `r1` or staging-only `d1` profile. D1 carries the
17 R1 scopes plus six materialized developer scopes, while the generated policy
continues to enable only the 30 read-only tools. The generated Edge fragment
records the full `oauthScopes` profile separately from the MCP `requiredScopes`
initialization gate, so discovery cannot accidentally shrink to the bearer
minimum. Personal supervisor startup rejects D1 and keeps the live deployment
R1-only. Auth/Edge focused checks pass 26/26; no public mutation scope, tool
list entry, deployment, or live mutation call changed. The isolated D1 canary
is recorded separately in `evidence/2026-09-22-d1-oauth-canary.md`.
