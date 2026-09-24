# Owner OAuth service: local operations

The owner-authorized [personal deployment](personal-deployment.md) is now
running at `https://mac.yapweijun1996.com/mcp`. The earlier
[attended trial plan](chatgpt-readonly-trial.md) was superseded by the owner's
request for a persistent personal service. Actual ChatGPT UI linking remains
to be completed by the owner.
Use Node.js 24.7 or newer. The password verifier uses native Argon2id; SQLite
and Argon2 may emit experimental-runtime warnings on supported Node releases.

## Provision an owner

For personal setup, copy `.env.example` to the repository's `.env`, set mode
0600, and fill in `MAC_OPERATOR_USERNAME` and `MAC_OPERATOR_PASSWORD` locally.
Quote the password, especially if it contains `#`. Use a new password with at
least 14 characters. Run `scripts/setup-owner-auth.command`; when `.env` exists
it automatically uses that file without terminal credential prompts.

The file is Git-ignored and is parsed as data, never sourced or exported into
the process environment. Only the password hash is stored in the account
database. The original `.env` remains on disk; remove its password after
successful provisioning if you do not want to retain plaintext credentials.
Changing `.env` does not change an existing account. The normal password-reset
command remains interactive and revokes existing grants. For another file
location, use `init --env-file PATH` instead of `--username NAME`; the file must
be an owner-only, non-symlink regular file. No default password is provided.

Without `.env`, run `scripts/setup-owner-auth.command` directly in an interactive
terminal after building. It defaults the username to `yapweijun`, automatically
configures the documented ChatGPT stable callback, and uses the hidden-password
CLI prompt. The interactive wrapper asks only for a username and password. State
goes to `~/Library/Application Support/MacOperator/auth`. Existing auth state
is never replaced. No service is started and no route is published.

Local preparation on September 20 created a private origin CA and separate
90-day Auth/Edge certificates in the sibling `tls` directory. Trust is explicit
through `caPool`; no system trust was installed. The sibling
`prepared/cloudflared.yml` is a validated route draft for ports 3443 (Edge) and
3444 (Auth). It is not the live shared tunnel config. Merge only its hostname
rules through the tunnel's current configuration workflow after release gates
pass. Certificate renewal is not automated.

Current
[OpenAI authentication documentation](https://developers.openai.com/plugins/build/auth)
permits the stable `https://chatgpt.com/connector_platform_oauth_redirect`
when RFC 9207 issuer identification is supported. The issuer now advertises
that support and includes its exact `iss` in success and denial callbacks.
The setup wrapper fixes this URL; if the client management page displays a
different callback for an existing connection, use the direct CLI below with
that exact value instead.

Build using `npm run build`. In a local interactive terminal, run:

```sh
node packages/auth/dist/cli.js init \
  --dir /ABSOLUTE/PRIVATE/PARENT/mac-operator-auth \
  --username YOUR_USERNAME \
  --redirect-uri HTTPS_CALLBACK_FROM_THE_ACTUAL_CLIENT
```

Replace the placeholders. The parent must already exist and be controlled by
the service owner; the final directory must not exist. The command prompts
twice with echo disabled. Use a unique password of at least 14 characters,
up to 1,024 UTF-8 bytes. Never send it to an agent or put it in an argument,
shell environment variable, tracked file, screenshot, or log. The explicit,
Git-ignored owner-only `.env` provisioning option above is also supported.

The command creates a 0700 directory and 0600 files: `auth-config.json`,
`auth.sqlite`, `signing.key`, `status.key`, and two integration fragments.
The database stores the password hash and salted-password parameters, hashed
browser/code/refresh bearer values, public client metadata, and grant state.
The signing private key never belongs in the Edge or Broker configuration.

Only HTTPS callback URLs explicitly listed in `allowedRedirectUris` are
accepted, with exact matching and no wildcard. Obtain the actual callback from
the client setup. If more callbacks are required, edit this protected config
while stopped and restart. Client registrations do not expire automatically;
grants expire after seven days even when refreshed.

Initialization is exclusive and does not overwrite an account. If interrupted,
inspect the partial protected directory locally; do not rerun with overwrite
or delete an existing database as a recovery shortcut.

## Assemble the current R1 connection

The live personal supervisor provisions the signed R1 policy. It grants the 17
scopes listed in [personal deployment](personal-deployment.md), enables the
exact 30 read-only tools, and binds filesystem, project, service, log, process,
Docker, app and job targets before the Broker accepts requests. The provisioning
root is the canonical owner home for content reads plus `/` for metadata-only
reads. `MAC_OPERATOR_PROJECT_ROOT` may explicitly bind the owner project root;
it is a non-secret path setting, not a credential.

An existing ChatGPT OAuth connection must be reauthorized after new scopes are
introduced. OAuth metadata advertises available scopes but cannot expand a
stored grant. The expected UI result after reconnect is the R1 tool list; until
then the existing app correctly remains at its original three-tool R0 list.

## Owner project write profile and D1 staging

The Auth initializer accepts `--grant-profile r1|w1|d1`; `r1` is the default.
The personal supervisor accepts R1 and the owner project write profile W1.
W1 advertises the R1 scopes plus `mac.files.write`, `mac.project.write`,
`mac.git.write`, and `mac.job.cancel`. Its signed policy enables only the four
file/Git write tools and job cancellation in addition to R1, and requires an
attended owner approval for each write. The current live snapshot remains R1;
see [personal deployment](personal-deployment.md) for the W1 rollout boundary.

The staging-only D1 profile advertises
the 17 R1 scopes plus `mac.files.write`, `mac.project.write`, `mac.git.write`,
`mac.service.control`, `mac.task.run`, and `mac.job.cancel`. The generated
`edge-auth-settings.json` records this full list as `oauthScopes`, while an
Edge startup document may keep a smaller `requiredScopes` list for the MCP
initialization gate. These fields must not be conflated.

D1 initialization remains a scope and contract-parity check only: generated
Broker policy input still enables the 30 read-only tools, and the personal
supervisor refuses the D1 profile. Public W1 deployment additionally requires
real-Mac readback and recovery evidence, and an end-to-end ChatGPT mutation
probe before claiming live acceptance.

## Historical R0 policy assembly

The following section records the original three-tool connection for rollback
and incident history. It is not the current R1 policy.

`edge-auth-settings.json` is a fragment, not a complete Edge startup config.
Merge it into the existing strict Edge configuration described in
[configuration](../CONFIGURATION.md). Copy `status.key` through the operator's
protected local provisioning process into the Edge data root, retaining 0600
permissions and owner-only parents. Replace the generated placeholder path;
the generated SHA-256 digest binds that file. This credential is independent
of the Edge-to-Broker authentication key. For issuer ID `mac-operator-auth`,
startup requires all three `oauthStatus*` settings and the exact issuer status
URL. There is no cached allow result when the status service is unavailable.

`broker-policy-input.json` is also an input fragment, not a signed policy.
Use the existing reviewed policy provisioning process to grant the generated
owner principal and issuer exactly `mac.control.read` and `mac.system.read`
against `host:broker`, and enable only:

- `mac_health`
- `mac_capabilities`
- `mac_system_summary`

Keep filesystem roots empty. Provisioning OAuth alone does not enable any
Broker capability or modify its policy. See [deployment](../DEPLOYMENT.md)
for the existing service, policy, and certificate gates.

## Start and route

```sh
node packages/auth/dist/cli.js serve \
  --dir /ABSOLUTE/PRIVATE/PARENT/mac-operator-auth \
  --tls-cert /ABSOLUTE/PRIVATE/TLS/auth.crt \
  --tls-key /ABSOLUTE/PRIVATE/TLS/auth.key
```

The foreground service binds only `127.0.0.1:3444` by default, with TLS 1.3.
SIGINT/SIGTERM closes it. TLS files and their direct parent must be owner-only
and canonical, without symlinks. Use a certificate chain the forwarding
service trusts; do not disable certificate validation. No launchd service or
tunnel is installed by this command.

Configure the reviewed tunnel to preserve the public Host header and route:

| Public path | Destination |
| --- | --- |
| `/mcp`, `/.well-known/oauth-protected-resource/mcp` | Existing HTTPS Edge |
| `/.well-known/oauth-authorization-server` | Auth HTTPS listener |
| `/authorize`, `/token`, `/register`, `/revoke`, `/jwks`, `/oauth/*` | Auth HTTPS listener |

Do not expose Broker IPC. The Edge calls the public issuer's authenticated
`/oauth/status` endpoint on every token use; include it in tunnel routing and
capacity planning. Its credential is sent only over verified HTTPS with no
redirects. Public request flooding can exhaust the single-owner global rate
budget; apply perimeter limits before release. Do not log query strings,
request bodies, cookies, authorization headers, token responses, or passwords.
The auth service deliberately emits no per-request logs; operational audit
coverage beyond the Broker remains a release follow-up.

## Revoke and recover

```sh
node packages/auth/dist/cli.js revoke-all --dir /ABSOLUTE/PRIVATE/PARENT/mac-operator-auth
node packages/auth/dist/cli.js reset-password --dir /ABSOLUTE/PRIVATE/PARENT/mac-operator-auth
```

These commands work against the durable store while the auth service is
running. Reset prompts for a new password and atomically revokes all browser
sessions, pending codes, and OAuth grants. Refresh-token reuse revokes the
entire affected grant. A subsequent Edge request is rejected, including after
restart. An already admitted Broker call may complete: this implementation
does not propagate revocation into Broker-owned task cancellation.

Protect backups as credentials. Do not restore an older database into a live
issuer: doing so can restore revoked state. For recovery, stop public routing,
restore only a trusted backup, revoke all grants before serving, and verify
the principal and key bindings. Corrupt or unsupported state is rejected,
never silently replaced. Signing-key rotation automation and dual-key overlap
are not implemented; their deployment procedure and live verification remain
required before public acceptance.

## Verification and remaining gates

Local automated coverage includes login/consent, CSRF, exact callback binding,
S256 mismatch, code replay/expiry, JWT verification, three-tool Broker calls,
scope reduction, refresh replay/concurrency and absolute expiry, restart
persistence, local revoke-all, rate limits, weak/symlinked files, and corrupt
database rejection. Run `npm test` for the repository regression suite.

The local owner account and personal public service are now provisioned.
The public login, three-tool and revocation path has passed an SDK-client probe
and automatic process recovery testing. Actual ChatGPT UI linking, signing-key
rotation and formal signed-package installation acceptance remain separate.
See [personal deployment](personal-deployment.md) for evidence and maintenance.
