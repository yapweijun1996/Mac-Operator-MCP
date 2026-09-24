# Mac Operator username/password OAuth design

Status: Implemented in `packages/auth` and running as the R1 owner-authorized
[personal deployment](personal-deployment.md). Formal signed-package release
acceptance and actual ChatGPT UI reauthorization remain separate.

## Scope

Provide an owner login and explicit OAuth consent for the
`https://mac.yapweijun1996.com/mcp` endpoint. The live personal R1 service
exposes the bounded read-only tool set selected by the signed Broker policy.
Existing release gates and Broker authorization remain authoritative.

## Ownership and topology

Cloudflare Tunnel provides HTTPS reachability to the Edge and a separate
unprivileged authorization service. It never exposes Broker IPC. Route OAuth
and JWKS paths to the authorization service, and `/mcp` plus protected-resource
metadata to the Edge. Preserve the current Edge HTTPS origin requirements;
do not disable origin certificate verification to simplify forwarding.

The authorization service owns accounts, password verification, browser
sessions, consent, OAuth grants, signing keys, and refresh-token lifecycle.
The Edge owns access-token verification and principal projection. The Broker
owns tool and target authorization, revocation enforcement, and audit.

Reuse KB-MCP's discovery, registration, login, consent, and lifecycle patterns
after review. Do not import its tenant store, tokens, signing material, or
KB-specific authorization into this service. KB-MCP uses opaque access tokens;
this design issues signed JWTs compatible with the existing Edge verifier.

## User experience

1. The user connects the MCP URL from ChatGPT.
2. Discovery and supported client registration establish an OAuth client.
3. `/authorize` validates the client, exact redirect URI, resource, requested
   scopes, state handling, and S256 PKCE challenge before starting login.
4. `/oauth/login` shows a username field, password field, and Sign in button.
   Password-manager autofill and paste are allowed. Failed login returns one
   generic message regardless of whether the account exists.
5. A consent page identifies the client as untrusted display metadata and lists
   the actual requested access: health, capability discovery, and system facts.
   Allow and Cancel are equally clear. Login alone does not grant consent.
6. Allow creates a short-lived, single-use authorization code. ChatGPT exchanges
   it with its PKCE verifier at `/token`; the password is never an OAuth token
   exchange parameter or an MCP argument.
7. The owner can revoke all connections using a local command. OAuth clients can
   revoke their grants using `/revoke`. Allow or Cancel consumes the browser
   session; it otherwise expires after ten minutes. Password reset revokes all
   owner sessions and grants. A connection-list UI is not implemented.

No password grant, public signup, default password, or unauthenticated remote
account-creation endpoint is provided.

## Account provisioning and storage

Start with one locally provisioned owner account. An owner-only local command
accepts the username as an option and prompts for the password twice with terminal echo disabled. Do not
accept passwords in command arguments, URLs, source files, or chat messages.
At the owner's request, initialization also accepts `--env-file` with
`MAC_OPERATOR_USERNAME` and `MAC_OPERATOR_PASSWORD`. The Git-ignored file must
be owner-only and is parsed without shell evaluation or process-environment
export. It is used only for initial hashing, never as a runtime password source.
Use a stable opaque principal ID independent of the editable username.

Store an Argon2id password hash with a unique salt, never reversible password
ciphertext. Schema version one fixes native Node Argon2id at 64 MiB, three
passes, one lane, and a 32-byte output. Benchmark these costs on the deployment
host before release. Store account and grant
state outside the repository in an owner-only directory. Keep JWT signing
private keys separate from the Edge and Broker keys, using the reviewed host
secret-storage mechanism. Public JWKS contains verification keys only.

Browser session identifiers and refresh tokens are cryptographically random;
persist their hashes rather than their bearer values. Writes must be atomic
and durable. Corrupt state or failed persistence prevents token issuance and
refresh; restarting must not resurrect revoked grants.

## Endpoint contract

| Endpoint | Responsibility |
| --- | --- |
| `/.well-known/oauth-protected-resource/mcp` | Edge resource and issuer discovery |
| `/.well-known/oauth-authorization-server` | Authorization server metadata |
| `/register` | Bounded public-client registration if DCR is selected |
| `/authorize` | Validated authorization transaction and consent |
| `/oauth/login` | Browser-only login GET/POST |
| `/oauth/consent` | CSRF-protected approval or denial POST |
| `/token` | Authorization-code exchange and rotating refresh |
| `/revoke` | Token/grant revocation with ownership validation |
| `/jwks` | Public asymmetric verification keys |
| `/oauth/status` | Shared-key authenticated grant-state check for the Edge |
| `/mcp` | Existing authenticated MCP tools |

All advertised addresses use the `mac.yapweijun1996.com` HTTPS origin. Fix the
canonical issuer to `https://mac.yapweijun1996.com/` and the resource/audience
to `https://mac.yapweijun1996.com/mcp`; URL serialization must match existing
Edge validation. Configure the internal issuer ID as `mac-operator-auth`.

Discovery advertises RFC 9207 issuer identification. Successful authorization
and consent-denial redirects include `iss` exactly equal to the canonical
issuer, allowing eligible ChatGPT connections to use the stable callback.

Protocol mechanics use pinned `@node-oauth/oauth2-server` 5.3.0. Actual
ChatGPT registration and protocol compatibility still need a deployment probe;
local tests do not establish that compatibility.

## Token and authority contract

Issue ES256 JWT access tokens with `kid` and `typ: at+jwt`, containing `iss`,
`aud`, `sub`, `iat`, `exp`, `jti`, a stable grant/session `sid`, `azp`, and
space-separated `scope`. IDs must satisfy existing Edge/Broker grammars.
Initial lifetimes are five minutes for access tokens, 60 seconds for codes,
and seven days absolute for a refresh grant.
Refresh rotates the refresh token atomically and detects reuse, revoking the
affected grant family. It never increases scopes or resets absolute expiry.

The live personal service grants the exact 17-scope R1 read-only profile. A
separate staging-only D1 profile adds five planned developer scopes, but its
generated policy still enables only the existing 30 read-only tools. Mutation,
GUI, destructive, and privileged families remain disabled until their signed
policy, approval, isolation, recovery, and real-Mac gates are complete. OAuth
consent cannot change signed Broker policy.

The Edge verifier checks `/oauth/status` over HTTPS on each authenticated
request using a separate shared key. Unavailable or malformed responses fail
closed. This prevents new requests after revocation; a request already admitted
can finish. The status endpoint is authenticated, but is routed through the
public issuer origin. Broker-owned session-revocation propagation is not yet
implemented; it remains a release gate for broader or long-running capabilities.

## Browser and abuse controls

Use Secure, HttpOnly, host-only SameSite=Lax session cookies; rotate the session
after login and expire it at a ten-minute absolute lifetime.
Login and consent POSTs require CSRF tokens bound to the browser session and
authorization transaction. Verify Origin when available; permit missing
Origin only through the tested session-bound CSRF path; opaque Origin
is rejected. Do not use permissive credentialed CORS.

Use no-store responses, restrictive CSP, frame protection, escaped client
metadata, and same-origin validated return paths. Never trust Host headers to
construct redirects. The single-owner implementation limits login attempts to
ten per minute globally, two concurrent password computations, and all requests
to 300 per minute. Each record category is capped at 1,000; bodies at 8 KiB.
Proxy trust is disabled so forwarded addresses cannot bypass limits. Global
limits can temporarily deny the owner access under attack; the deployment
requires perimeter rate limits. No permanent account lockout is used.

Audit outcomes and opaque IDs only. Redact passwords, cookies, bearer tokens,
codes, authorization URLs, and request bodies from application and proxy logs.

## Acceptance and rollout

Before public connection, verify login success/failure, CSRF, redirect binding,
PKCE mismatch, code replay/expiry, scope escalation, token audience/signature,
refresh reuse, revocation, restart persistence, and signing-key rotation.
Verify that unauthenticated `/mcp` returns 401 with resource metadata.

Run one real ChatGPT flow through the proposed domain: sign in, approve,
discover exactly three tools, call `mac_system_summary`, and find a matching
redacted Broker audit record. Reject all file, task, GUI, and privileged calls.
Then revoke the connection and prove further calls fail. Record the tested
source revision, transport, and protocol version without credentials.

The owner-authorized personal service is now deployed with protected state,
reviewed tunnel routing, and a successful public SDK connection. See
[personal deployment](personal-deployment.md) for verified behavior and
operational limits. Actual ChatGPT UI acceptance and formal signed-package
release acceptance remain pending.
