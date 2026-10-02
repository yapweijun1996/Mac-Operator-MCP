# Independent owner terminal OAuth rollout

Status: PASS, October 2, 2026. The owner selected the independent terminal
connection while preserving the existing V2 connection. Source implementation
is `81657216c3699e3278b2272b58867803f91549c6` on
`codex/owner-terminal-oauth`.

## Deployed behavior

| Connection | Issuer | Fresh consent | Observed tools |
| --- | --- | --- | --- |
| `https://mac.yapweijun1996.com/mcp` | `https://mac.yapweijun1996.com/` | V2, 27 scopes, excludes terminal | 48 |
| `https://mac.yapweijun1996.com/terminal/mcp` | `https://mac.yapweijun1996.com/terminal/` | O1, 24 scopes, includes terminal | 43 |

O1's existing Git/project/job scopes also map to five V2 worktree/review tools
under the shared policy. Terminal consent excludes task, coding-agent and audit
scopes. The Broker remains authoritative for capability projection. Owner
terminal execution uses the current macOS account and its available files and
CLI authentication state; it does not provide root privileges, bypass TCC or
claim container isolation.

Both connections share the account, signing keys and signed policy-3. OAuth
clients, transactions, codes and grants are resource-bound. Legacy records
without a resource stay at the origin's original `/mcp`. Cookies, JWT verifiers,
issuer-bound status readers, revocation monitors and MCP handlers are separate.
Neither connection's token is accepted at the other MCP resource. An existing
V2 client registration cannot be reused for terminal authorization.

## Verification

| Check | Result |
| --- | --- |
| Native build and TypeScript compilation | PASS |
| Full regression after all source changes | 1603 tests: 1585 passed, 18 existing opt-in skips, zero failures |
| Style, documentation links, process-boundary audit, final diff | PASS |
| Independent resource/client/cookie/code/refresh/status/revoke tests | PASS |
| Legacy root O1 refresh compatibility | PASS; existing scopes retained, fresh V2 cannot authorize terminal |
| Independent architecture/security review | PASS after fixing the reproduced monitoring P1 |
| Offline opt-in live-lock protection | PASS; refuses a running supervisor |
| Offline production opt-in | PASS; signed V2 policy verified, paired settings enabled |
| Public exact discovery and challenges | PASS; root 27 scopes, terminal 24 scopes |
| Fresh default V2 login/consent and MCP discovery | PASS; 48 tools, 26 real read calls |
| Fresh terminal login/consent and MCP discovery | PASS twice; 43 tools, 26 real read calls each |
| Cross-resource token use | PASS; rejected in both directions |
| Real terminal execution | PASS; 31-second shell, Git/Node/Codex CLI, HTTPS access, file write/read |
| Terminal lifecycle | PASS; idempotent replay writes once, Job readback, timeout prevents late write |
| Active explicit grant revocation | PASS; command returns CANCELLED, Job is durably cancelled, process metadata cleared, late write absent |
| Active terminal scope reduction | PASS; narrower token admitted before next poll, command still cancelled with the same durable checks |
| Existing connected Mac-MCP | PASS; healthy, 48 enabled tools, task enabled, terminal remains outside its root V2 grant |
| Existing account, grants and protected authority | PASS; account unchanged, three existing active grants unchanged, 21 policy/key/runtime files byte-identical |
| Release identity | PASS; 884 runtime and contract files match the tested build |
| Supervisor | PASS; correct immutable cwd/entrypoint, online, zero automatic restarts, saved PM2 dump mode 0600 |

The independent reviewer reproduced a monitor bug before rollout: accepting a
narrower token for the same subject/session replaced the old terminal scope,
which could hide permission loss for an active command. Monitoring now records
the latest accepted expiration for each scope, retaining only unexpired scopes.
Independent tests verified both token arrival orders, exact per-scope expiry,
status outages and failed Broker propagation retries. The real public
scope-reduction test confirmed durable cancellation.

The first terminal probe ran before restarted listeners were ready and received
502. After both public MCP endpoints returned their expected 401 challenges, the
complete probe passed. No service failure or unexpected automatic restart
occurred. Initial PM2 restart retained the old cwd despite updating arguments;
recreating only the target PM2 entry applied the new cwd, and both public profile
verifications passed afterward.

## Release and rollback

- Release: `/Users/yapweijun/Library/Application Support/MacOperator/releases/personal-20261002-terminal-a`.
- State: `/Users/yapweijun/Library/Application Support/MacOperator-o1-20261001a`.
- Complete stopped-state backup and private rollback/deploy configurations:
  `/Users/yapweijun/Library/Application Support/MacOperator/backups/v2-before-20261002-terminal-a`.
- Previous release: `MacOperator/releases/personal-20261002-v2h`, source `de97766bc45a09b4837c468d4657b8843deca086`.

Only paired Auth/Edge opt-in, release paths/revision and Mac-specific tunnel
routes changed. Signed policy, keys, approval configuration and development
runtime profiles were preserved. Tunnel route validation passed; the existing
TLS certificate/CA and Host pinning remain in use. Release workspace symlinks
resolve internally. `.env`, private state and Git metadata were excluded.
The primary checkout's pre-existing uncommitted files were preserved.

Rollback requires stopping this supervisor, preserving the post-rollout state
separately, restoring the entire backup `state` tree to the original state path,
restoring the backed-up tunnel configuration, and starting the private
`rollback.config.cjs` with only `mac-operator-personal`. Restart the tunnel and
verify the root V2 connection before saving PM2. Restoring only old binaries is
insufficient because older Auth binaries do not accept resource-bound records.
Do not overwrite the live state while the supervisor is running.

## Client handoff

Keep the existing root V2 connection. Add a separate MCP connection using
`https://mac.yapweijun1996.com/terminal/mcp` and complete its owner login and
terminal consent. Reconnecting the root URL alone continues to issue V2 grants.
The verification clients were revoked and removed; no verification credential
was retained. Public verification logs remain in the private rollback folder;
this record contains no credentials or raw bearer material.
