# Independent owner terminal connection

The default `/mcp` connection retains the V2 coding profile (27 OAuth scopes).
An explicit `ownerTerminalConnection: true` opt-in in both protected Auth and Edge
configuration adds `/terminal/mcp`, with issuer `/terminal/` and the O1 profile
(24 scopes). Both connections share the owner account, signing key, policy and
Broker, but have separate clients, consent sessions, token audiences and MCP
handlers. Terminal consent includes owner shell access and owner-accessible CLI
authentication state. It does not confer root privileges or bypass macOS TCC.

Auth owns grant binding. Client, transaction, authorization code and grant
records for the terminal connection carry its resource URL. Existing records
without a resource remain bound to the origin's original `/mcp`. Every endpoint
checks the binding before consuming credentials, changing scopes or revoking a
grant. Edge uses separate JWT verifiers and issuer-bound status checks.

Discovery uses `/.well-known/oauth-protected-resource/terminal/mcp` and
`/.well-known/oauth-authorization-server/terminal`. Browser routes and the
`__Host-mac-terminal-session` cookie are independent of the default connection.
The existing approval bridge remains at the root owner approval routes.

Rollout requires a stopped-service backup of all protected state, followed by
paired Auth/Edge opt-in and a new immutable release. Startup rejects mismatched
configuration. Rollback restores both the old release and the complete backup:
an older binary may not understand the newly bound records. Verification covers
both discoveries, fresh consent, cross-resource rejection, refresh/revocation,
legacy grants, real terminal execution and continued default V2 behavior.


## Enable and verify

After stopping the supervisor and taking the complete backup, run from the new
release (replace the placeholders with verified absolute paths and its commit):

```sh
node packages/auth/dist/personal-service.js terminal-connection /absolute/state/root SOURCE_REVISION --enable
```

Keep the existing tunnel TLS and Host pinning. Its Mac-specific routes must send
`/mcp`, `/terminal/mcp` and the protected-resource discovery paths to Edge, and
root/terminal OAuth, JWKS and browser paths to Auth. The terminal authorization
server discovery path is `/.well-known/oauth-authorization-server/terminal`.
Restart the supervisor with the new immutable release and verify both profiles:

```sh
MOPS_VERIFY_FULL_SCOPES=1 node scripts/verify-personal-connection.mjs /absolute/state/root /absolute/owner.env
node scripts/verify-personal-connection.mjs /absolute/state/root /absolute/owner.env --owner-terminal
```

Add a separate MCP client connection pointing to
`https://mac.yapweijun1996.com/terminal/mcp` and complete its owner login and
terminal consent. Existing `/mcp` registrations cannot be reused there.
Fresh default V2 tokens have 27 scopes and cannot call the terminal. Terminal
consent has 24 O1 scopes; under the shared V2 policy it also exposes five Git
worktree/review tools using its existing Git/project/job scopes (43 tools total).
It has no task, coding-agent or execution-audit scopes. Existing root O1 grants
retain their original approved scope set until expiry or revocation.
