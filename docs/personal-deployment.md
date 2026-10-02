# Personal always-on deployment

Status: V2 coding and independent owner terminal OAuth connections are running
as of October 2, 2026. This is an owner-managed, unsigned personal deployment,
not a Developer ID/notarized package or the formal production installer.

October 2 GUI repair: PM2 runs
`MacOperator/releases/personal-20261002-terminal-protocol-c`, which carries
forward the GUI repair from `personal-20261002-gui-a` together with the latest
terminal compatibility changes. The four GUI runtime modules and native source
match the workspace; `GUI-HOTFIX.json` records their committed source revision.
The V2/O1 state, OAuth connections, signed policy and scopes are preserved.
The original GUI rollout backup is under `MacOperator/backups/gui-20261002`.
It predates the terminal compatibility update; use the current release for any
new rollback baseline. The native app update needs TCC re-binding. Prior GUI
regression passed; the owner requested no additional tests and will perform
live GUI acceptance. See the
[repair evidence](../evidence/2026-10-02-chrome-gui-reusable-grant.md).

## Current V2 and owner terminal connections

The default `https://mac.yapweijun1996.com/mcp` retains the V2 coding profile:
27 OAuth scopes and 48 tools, including approved worktree/container development.
A separate connection at `https://mac.yapweijun1996.com/terminal/mcp` uses issuer
`https://mac.yapweijun1996.com/terminal/` and explicit O1 consent: 24 scopes and
43 tools under the shared V2 policy, including owner shell and CLI execution.
The five additional Git worktree/review tools use already granted Git/project/job
scopes; task, coding-agent and execution-audit scopes remain excluded. Each
connection has separate OAuth clients, cookies, audience binding and MCP handler.
Existing root grants keep their original scopes. Add the terminal URL as a new
connection and complete its owner login; reconnecting only the root V2 URL
continues to authorize the coding profile.

PM2 `mac-operator-personal` runs immutable release
`MacOperator/releases/personal-20261002-terminal-a`, source
`81657216c3699e3278b2272b58867803f91549c6`, with protected state still at
`MacOperator-o1-20261001a`. Paired `ownerTerminalConnection: true` settings enable
the extra endpoint. Signed policy-3, keys, runtime profiles and existing grants
are preserved. Rollback must restore the complete stopped-state backup at
`MacOperator/backups/v2-before-20261002-terminal-a/state` together with the old
`personal-20261002-v2h` release and tunnel configuration. See
[connection operations](owner-terminal-connection.md) and the
[verified rollout](../evidence/2026-10-02-independent-terminal-oauth.md).

## Historical O1 source rollout

The following records the earlier O1 source rollout before V2 was enabled.

The public MCP URL remains `https://mac.yapweijun1996.com/mcp`. O1 retains G1's
37 tools and adds `mac_terminal_exec` under `mac.terminal.exec`: 38 tools and
24 OAuth scopes in total. The terminal executes shell commands and local CLIs
with the macOS owner's permissions. Its exact delegated approval is enabled
by the owner's local opt-in and OAuth consent; each command has a durable Job.
Existing OAuth grants retain their original scopes. Reconnect the MCP client
and consent to the additional terminal scope to use the new tool.

PM2 process `mac-operator-personal` runs
`~/Library/Application Support/MacOperator/releases/personal-20261002-v2a`
with state at `~/Library/Application Support/MacOperator-o1-20261001a`.
Runtime source revision is `2c37194d9bd822e78ad088f61d79a5f91061e152`, merged to
local `main`. The 57-contract catalog includes the disabled V2 interfaces;
enabled owner tools and scopes remain 38 and 24. The signed policy is unchanged.
The immediate source rollback uses preserved release `personal-20261001-o1a`
and the protected offline backup `MacOperator/backups/o1-before-20261002-v2a`.
Only `packageRoot`, `contractsDirectory` and `sourceRevision` in unsigned
`personal/edge-service.json` were changed. PM2 configuration is saved.
See the [October 2 rollout record](../evidence/2026-10-02-v2-o1-personal-rollout.md)
for validation and exact rollback steps. The older G1 release/state pair remains:
`personal-20260925-g1a` and `MacOperator-g1-20260925a`. The new state contains
protected `rollback-launch.json` supervisor arguments without credentials.
The selected supervisor configuration is saved in PM2.

Public verification passed owner OAuth login and consent, exact tool discovery,
26 read calls, a 31-second command, Git/Node/Codex CLI invocation, HTTPS access,
file writes, idempotent replay, Job readback, timeout and active grant revocation.
Revocation returned `CANCELLED`, persisted a cancelled Job and cleared process
ownership. A separate grant restricted to the old read scopes listed 27 tools,
passed 26 reads and did not expose the terminal. The loopback snapshot preflight
also passed. The October 2 source rollout repeated the public owner and old-read
grant checks successfully. See [original verification evidence](../evidence/2026-10-01-owner-terminal-control.md)
and [terminal operations](owner-terminal.md) for limits and rollback details.

## Historical W1 personal project deployment

The live service uses a separate `w1` owner profile for one canonical Git
repository under the owner's home. It keeps 27 R1 read tools and adds `mac_write_file_atomic`,
`mac_apply_patch`, `mac_git_stage`, `mac_git_commit`, and `mac_job_cancel` to
form 32 tools total. Docker's three read tools remain on R1 because the newer
Broker requires a kernel descriptor launcher that this host does not provide.
The signed policy gives write access only to that project;
other home paths remain read-only. Each write requires an attended owner browser
approval bound to the exact tool, target, and payload. W1 does not grant task
execution, service control, GUI control, privileged operations, or arbitrary
shell access.

The selected project is `/Users/yapweijun/Documents/GitHub/Mac-Operator-MCP`.
The MCP URL remains `https://mac.yapweijun1996.com/mcp`; the owner signs in
through its OAuth page with the configured local username and password.
PM2 runs the snapshot at
`~/Library/Application Support/MacOperator/releases/personal-20260924-w1d`
with protected state at
`~/Library/Application Support/MacOperator-w1-20260924d`.
The preserved R1 snapshot and state are the immediate rollback path.

The public OAuth discovery advertises 20 W1 scopes and the MCP endpoint lists
32 tools. A real owner OAuth grant completed 26 read calls; a project-external
write returned `POLICY_DENIED` without creating a file, and revocation blocked
the next request. The live PM2 process had zero restarts at this check. A new
ChatGPT app connection and owner OAuth grant completed on September 25. Its
management page listed the 32 W1 tools, and a real ChatGPT conversation called
`mac_health` successfully. The origin recorded the authenticated `tools/call`
with HTTP 200 in 145 ms at 2026-09-24 22:20:40 UTC. An in-project write with
attended browser approval remains pending. Existing R1 grants did not expand
into W1; this acceptance used a fresh connection and grant.

## Historical R1 rollback state

The preserved R1 snapshot exposes 30 read-only tools under 17 scopes, including
Docker reads. Its earlier ChatGPT acceptance is historical evidence and does
not prove that the new W1 connection has been completed. The R0 paragraphs
retained later in this document are also historical.

## Historical R1 connection

- MCP URL: `https://mac.yapweijun1996.com/mcp`
- Authentication: OAuth, public-client dynamic registration (DCR).
- Username: the locally provisioned owner username.
- Password: the owner's configured password, entered only on the Mac Operator
  login page. No manually issued client ID or client secret is needed for DCR.
- R1 scopes: `mac.control.read`, `mac.policy.explain`,
  `mac.system.read`, `mac.storage.read`, `mac.process.read`, `mac.log.read`,
  `mac.network.read`, `mac.service.read`, `mac.package.read`,
  `mac.files.read`, `mac.files.search`, `mac.files.hash`, `mac.project.read`,
  `mac.git.read`, `mac.docker.read`, `mac.app.read`, `mac.job.read`.

The R1 service/API enables exactly 30 read-only tools. Its policy grants two
filesystem roots: the canonical owner home with metadata/content read and no
write, and `/` with metadata-only read. No root has write access and no system
content is readable. Mutation, GUI, destructive and privileged adapters remain
disabled; process and network read tools are enabled in R1. Docker objects are
matched dynamically only by the fixed local inspector, never through a raw
Docker socket.

## Historical R1 components

PM2 manages `mac-operator-personal`. Its supervisor owns the real Broker and
spawns separate Auth and Edge processes, bound to loopback ports 3444 and 3443.
Native IPC admits only the exact Edge process identity; requests and responses
are authenticated. A separately signed owner policy is restored from the
durable Broker store. An HMAC audit anchor uses an owner-only local key file
in this personal deployment, rather than the formal installer's Keychain path.

The runtime executes the protected snapshot at:

`~/Library/Application Support/MacOperator/releases/personal-20260921-r1f`

State is under `~/Library/Application Support/MacOperator-r1f` in the sibling
`auth`, `personal`, and `tls` directories. The
provisioning `.env` is not copied into the release or passed to child processes.
The snapshot is not a signed release; only the Broker policy is signed.

Newly provisioned personal snapshots keep the public OAuth status URL as the
issuer-bound logical resource but perform Edge-to-Auth grant checks through a
fixed `127.0.0.1` HTTPS endpoint. The request uses the issuer hostname for
Host/SNI, a protected owner CA bundle, and the separate status key. Endpoint,
certificate, host, response, and timeout failures still fail closed. Older
snapshots without these loopback fields remain compatibility-only while their
older release is still running; the current startup contract rejects such an
owner configuration before opening the new Edge listener.

If either child exits, the supervisor closes the other child and Broker before
exiting unsuccessfully. PM2 retries after five seconds. IPC channels explicitly
close via process exit, preventing a stopped child from appearing alive.
Repeated startup failure remains visible; no corrupt state is silently reset.
The deployment was saved to PM2's process list. The existing user LaunchAgent
restores that list on login. This does not make the Mac available while powered
off, asleep, disconnected, or awaiting a FileVault/user login after restart.

## Network routing

The existing shared Cloudflare tunnel routes the MCP and resource-discovery
paths to Edge, and OAuth/JWKS paths to Auth. Origin TLS validates against the
private origin CA with exact Host/SNI. No TLS verification is disabled.
The tunnel configuration generator now preserves path-specific and per-route
TLS settings; all 21 pre-existing route dictionaries were retained.

The local router retained NXDOMAIN for the newly created hostname after public
DNS was live. The personal Edge and live verifier therefore use application-
scoped public DNS resolution (1.1.1.1, 8.8.8.8) only for the configured issuer.
Other hosts use normal DNS. This does not change system DNS or disable HTTPS
certificate checks. Authenticated grant checks still fail closed if unavailable.
An older snapshot demonstrated an intermittent public status-channel timeout
during repeated verification; it returned `401 invalid_token` after the bounded
3-second check. The preserved r1f snapshot uses the fixed loopback status channel
and passed the repeated public verifier. See the historical incident record:
[`evidence/2026-09-21-r1-revocation-channel-timeout.md`](../evidence/2026-09-21-r1-revocation-channel-timeout.md).

The tunnel change is recorded in the tunnel repository commit `3ef92182`.
OAuth protected-resource discovery is served at both the origin well-known
path and `/.well-known/oauth-protected-resource/mcp`, with identical resource,
issuer and scope values. The origin path initially returned 404; it was added
after ChatGPT reported that OAuth was unavailable. The correction passed local
and public probes, but that error's exact cause awaits a ChatGPT retry.
Rollback backup: `~/.cloudflared/config.yml.before-mac-operator-20260921`.
Do not blindly restore that backup after unrelated later tunnel changes;
remove only the two Mac hostname rules in both current live config and SSOT.

## Operations

```sh
pm2 status mac-operator-personal
pm2 restart mac-operator-personal
pm2 stop mac-operator-personal
```

After deliberately changing whether the service should start at login, use
`pm2 save` and protect `~/.pm2/dump.pm2` with mode 0600. Do not print PM2's full
environment dump. Service output contains no request bodies or credentials.
Logs are in the protected `personal` directory and use the host's existing
PM2 log rotation module.
Personal Auth and Edge emit bounded connection diagnostics (up to 300 records
per minute per child): timestamp, component, allowlisted path/method, status,
coarse client category and whether an Authorization header was present. Unknown
strings become `other`; query strings, header values and bodies are never
logged. These records distinguish requests reaching the origin from failures
before the tunnel, but client categories are not proof of caller identity.

Use the auth CLI's `revoke-all` or `reset-password` for account recovery. Changing
`.env` does not rotate an existing password. Client registrations now outlive
individual user grants; access tokens last five minutes and user refresh grants
have a seven-day absolute lifetime, so periodic user reauthorization is expected.

Origin leaf certificates expire December 19, 2026 (UTC). The private origin CA
expires September 20, 2027; the signed Edge key authorization also needs renewal
before its one-year validity ends. Certificate/policy renewal is not automated.
Renew before expiry, copy the renewed Edge certificate into `personal/edge.crt`,
and restart this service. Update the tunnel CA only when changing the CA; do not
disable certificate validation to recover an expired deployment.

## Historical R1 verification

Live verification used the real owner account from the protected `.env` without
printing credentials. It performed public HTTPS discovery, browser-session
login, explicit consent, S256 code exchange, an official MCP client connection,
exact 30-tool listing, 29 real read calls, Docker readback, and grant
revocation followed by rejection of the next request. `mac_job_status` remains
available for an owner-owned Job but had no live Job record to read during this
read-only probe. Verification-created client registrations were removed and
their grants revoked.

An intentional Edge process stop caused automatic supervisor replacement and
both listeners to recover. The full public login/tool/revocation probe then
passed again. KB-MCP discovery remained 200 and unauthenticated KB MCP remained
401 after the shared tunnel restart.

This proves the deployed R1 protocol path using the SDK client pinned to
2026-07-28. The owner-approved R1 ChatGPT app was also verified separately:
the management page showed the full 17-scope grant and 30 discovered actions,
and real calls to representative system, storage, process, network, project,
Git, Docker, and app tools returned bounded results with matching service-side
200 responses. See the dated R1 evidence files in `PROGRESS.md`. The earlier
direct ChatGPT UI probes below are historical incident evidence; they reproduced empty OAuth
endpoint fields and unavailable DCR, with no corresponding origin requests.
A fresh verifier run against r1f reached token issuance and sent Authorization
on every request. The complete 30-tool/29-call probe passed, including Git
inspection, Docker readback, and grant revocation. Full API-side R1 acceptance
is therefore complete for this snapshot. A post-cutover ChatGPT smoke also
selected the R1 app and successfully executed `mac_health`; see
[`evidence/2026-09-21-chatgpt-r1-post-cutover-smoke.md`](../evidence/2026-09-21-chatgpt-r1-post-cutover-smoke.md).
R1 acceptance is complete for this personal snapshot; formal signed-release
acceptance and broader D1/G1/P1 capability gates remain distinct.
A second probe with a query parameter had the same result. Some automated
User-Agents independently receive Cloudflare 403 / 1010. After owner dashboard
login, Cloudflare events confirmed that the ChatGPT discovery probe at
2026-09-21 12:02:47 GMT+8 hit the `GeoIP` custom Block rule from Australia,
including `/.well-known/openid-configuration/mcp` on the Mac hostname. The rule
allows MY, SG, US and GB, with existing exceptions for the KB and yap hosts.
A Mac-host-only exception was saved after explicit owner confirmation. The
GeoIP rule remains active for other hosts; no bot/WAF skip was added for Mac.
After propagation, a ChatGPT probe reached `/mcp` and received the expected
401 challenge at 12:15:58 GMT+8. The UI still returned empty discovery fields;
OAuth discovery in ChatGPT is not yet accepted as working.
Manual entry of the published authorization, token, registration, issuer and
resource URLs enabled DCR in the ChatGPT creation form. A subsequent controlled UI test submitted both automatic and manually entered
OAuth configuration. Both failed before login; registration, callback handling
and actual ChatGPT tool discovery remain unverified. The public SDK owner-login,
three-tool and revocation probe still passed after the GeoIP change.
The initial UI probes did not confirm successful connector creation or authorization.
The owner confirmed that Create times out before the login page. Browser network
inspection reproduced HTTP 500 with `{"detail":"Request timeout"}` from both
`/backend-api/aip/connectors/mcp/oauth_config` and
`/backend-api/aip/connectors/mcp` on ChatGPT. Manual OAuth endpoints bypass the
first discovery call but do not resolve the creation timeout.
Cloudflare sampled events show an Australian aiohttp POST to `/mcp` at
04:27:53 UTC matching a Skip rule, with no corresponding completed origin
response. Later origin diagnostics show `/mcp` 401 at 04:28:50 and protected
resource metadata 200 at 04:28:52, but no corresponding registration request.
Skip is a firewall decision, not proof that the origin response reached the
client. The remaining network failure location is not established. The public
SDK login, three-tool, and revocation probe passed again around 04:29:49 UTC.
Do not diagnose this as an owner password problem or declare ChatGPT working
from the SDK probe alone.
Follow-up verification at 04:40 UTC reached the real Mac Operator login page
from the existing ChatGPT plugin `Mac Operator MCP`. The owner still needs to
complete login/consent before ChatGPT tool discovery can be accepted.
A different negotiated protocol must also be validated after authorization.

### September 21 connection recovery

Personal-service diagnostics now distinguish receipt, completion and client
abort, with per-process request IDs, elapsed milliseconds and a strictly
validated Cloudflare Ray ID. Headers, bodies, query values and credentials are
never recorded. This showed actual ChatGPT metadata requests completing in
1–3 ms at the origin, rather than hanging in the application.

The shared tunnel was reconnected at 04:36:29 UTC without changing routing,
TLS verification, firewall policy or OAuth requirements. The public SDK probe
passed afterward. A manual-configuration creation attempt then returned a
specific PKCE validation error rather than a timeout. Resetting the form and
using automatic discovery returned HTTP 200 with `pkce_required: true`,
`pkce_methods: ["S256"]` and the correct registration URL. Do not reuse the
manual override prepared while discovery was failing.

A creation response reported that `Mac Operator MCP` already existed. The
existing plugin's management page confirmed the canonical MCP URL, OAuth
support and no available actions yet. Its Connect another account / Sign in
flow successfully redirected through `/authorize` (303) to `/oauth/login`
(200) at 04:40:49 UTC. The browser displayed the expected username/password
form and was left open for the owner.

Recovery followed the tunnel reconnection and a fresh automatic discovery;
this establishes recovered behavior, not a proven underlying cause of the
previous intermittent network delay. Final owner consent and real ChatGPT
MCP protocol/tool compatibility remain unverified.

For a repeat live probe (it creates then revokes its own test grant):

```sh
MOPS_VERIFY_PROJECT_ROOT="$PWD" \
node scripts/verify-personal-connection.mjs \
  "$HOME/Library/Application Support/MacOperator-w1-20260924d" .env
```

Before switching a future personal snapshot, build the repository and run the
owner-only read-only preflight against that snapshot state root:

```sh
npm run build
npm run verify:personal:snapshot -- \
  "$HOME/Library/Application Support/MacOperator-w1-20260924d"
```

The preflight must report `loopbackStatus=bound`. It rejects older snapshots
that would fall back to the public OAuth status channel; it does not restart
PM2 or change protected deployment state.

The verifier allows 30 seconds per public request because the first owner
token exchange can exceed the normal origin latency while the public tunnel
and auth store are waking. It still records only bounded pass/fail summaries,
never credentials or response payloads.


### Browser form origin correction

The owner's login POST at 04:42:16 UTC returned 400 before password hashing.
The auth app applied `Referrer-Policy: no-referrer` to its native HTML forms,
which can cause browser form POSTs to send `Origin: null`. This conflicts with
the app's same-origin CSRF check; the SDK probe explicitly supplied Origin and
therefore did not cover this browser behavior.

Only `/oauth/login` and `/oauth/consent` now use `Referrer-Policy: same-origin`.
Other endpoints keep `no-referrer`. Null/foreign Origin values and invalid CSRF
tokens are still rejected. The correction is deployed, the public response
header is verified, all 14 auth tests pass, and the public login/tool/revocation
probe passes. A fresh login form was opened for the owner. Automated browser
submission was blocked by Chrome with `ERR_BLOCKED_BY_CLIENT`, so the owner's
browser submission and final ChatGPT tool discovery remain the acceptance gate.

Reference: [MDN Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy).


### Consent callback correction

The next owner browser run confirmed login success (04:45:26 UTC, 303) and
consent page delivery (200). The first consent POST at 04:45:29 returned 303;
a second POST two seconds later returned 400 because the one-use session was
already consumed. No token exchange followed the first redirect.

The consent document's `form-action 'self'` was incompatible with Chromium's
checks on cross-origin redirects after form submission. Consent responses now
allow self plus only the callback origin from the validated transaction.
Login pages retain self-only form actions; redirect allowlist validation,
CSRF, PKCE and one-use authorization codes remain unchanged. Expired or
consumed browser sessions now display a recovery page rather than opaque JSON.

All 15 auth tests pass, including consent CSP and replay recovery regressions;
type/style checks and the public SDK login/tool/revocation probe also pass.
The corrected app is deployed, and a new ChatGPT sign-in flow is prepared.
Real browser callback completion and ChatGPT tool discovery are still pending.
Reference: [MDN form-action](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/form-action).


### Real ChatGPT acceptance completed

At 04:48 UTC the owner completed the corrected browser flow. The browser
reached ChatGPT's `/connector_platform_oauth_redirect`; the issuer returned
200 for OpenAI's token exchange. ChatGPT displayed the primary connected
account, then refresh populated `mac_health` and `mac_capabilities`.

At 04:52:05 UTC a real ChatGPT conversation called `mac_health` and displayed
`healthy`. Origin diagnostics independently confirmed an authenticated
`tools/call` with protocol revision `2026-07-28`, HTTP 200, and 639 ms handling
time. No legacy MCP compatibility relaxation was needed. The real ChatGPT
login, consent, callback, token exchange, tool discovery and health-call path
is now accepted; broader capabilities are outside this verified grant.
The earlier pending statements above describe historical investigation stages.

### ChatGPT scope compatibility correction

The first ChatGPT app was created while the MCP endpoint challenged for only
`mac.control.read`. Its active owner grant therefore contained only that scope,
so ChatGPT correctly discovered `mac_health` and `mac_capabilities` but could
not discover `mac_system_summary`, which requires `mac.system.read`. Advertising
both values in protected-resource metadata did not expand an already configured
app's requested scopes. Reconnecting that app reused its stored scope
configuration.

The generic Edge still defaults to `mac.control.read`. Personal provisioning now
sets `requiredScopes` explicitly to both initial read scopes, and the deployed
401 challenge advertises `mac.control.read mac.system.read`. Individual tools
continue to enforce their own scopes. This keeps the security boundary explicit
instead of silently treating one scope as another.

A new development app, `Mac Operator MCP Read Only`, was created with both
values selected as ChatGPT OAuth default scopes. Its authorization transaction
and active grant contain both scopes. At 05:34:58 UTC, a real ChatGPT
conversation called `mac_system_summary`; the UI displayed macOS, CPU, memory,
uptime and load data. Origin diagnostics independently recorded an authenticated
`tools/call` using protocol `2026-07-28`, HTTP 200, and 263 ms handling time.
The app management UI also lists exactly `mac_health`, `mac_capabilities`, and
`mac_system_summary`. The earlier app remains installed for reversible cleanup.

When scopes change, inspect the actual active grant and the app's configured
default or action scopes. Refreshing tools cannot add a missing OAuth scope.
Create or reconfigure the app, authorize again, then require both a real UI call
and an origin-side `tools/call` success for acceptance. See OpenAI's
[OAuth guidance](https://developers.openai.com/plugins/build/auth).

### Persistent browser control

The review page also offers **Allow this browser for 30 minutes**: one OAuth
session, one browser, at most 500 operations, revocable and cleared on restart.

G1 owners can select **Allow this browser until revoked** on a focus approval
page. This permits focus, click/scroll/key and input for the same browser, owner
account and policy version without a time or use limit. The grant survives
service restart and owner reconnection, and is stored in the protected AuthStore.
Existing temporary consent is not automatically upgraded.

`/approval/access` provides independent owner login to view and revoke grants.
Management login expiry does not revoke persistent browser access. OAuth
sessions, policy and macOS permissions remain required; file writes and system
operations remain outside the grant. An explicitly authorized local owner can
also enable this using the stopped-service `browser-access` setup command.
See [persistent browser access](gui-computer-use.md#persistent-browser-access)
for the exact command, validation, revocation and rollback constraints.

The tunnel Auth ingress allowlist must include `/approval/access`,
`/approval/gui-session` and `/approval/gui-session/revoke`, in addition to the
existing login/review/decision routes. Validate ingress before restarting the
connector. Otherwise local route tests pass but the public management UI returns
404. These paths still require owner authentication and CSRF checks in Auth.
