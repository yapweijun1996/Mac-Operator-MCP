# ChatGPT read-only connection trial

Status: Historical and superseded by the owner's request for an always-on
personal deployment. The current service/API is the R1 profile documented in
`personal-deployment.md`; this file retains the earlier R0 trial proposal.
See [current deployment](personal-deployment.md). The design below records the
earlier unimplemented 60-minute trial proposal.

## Objective

Connect ChatGPT to `https://mac.yapweijun1996.com/mcp`, sign in with the
provisioned owner account, explicitly approve access, and call three real
Broker read-only tools. This is an attended, temporary interoperability trial,
not installation or acceptance of a production Mac operator service.

## Selected topology

ChatGPT and the browser reach verified HTTPS through the existing Cloudflare
tunnel. OAuth routes reach the separate Auth process on loopback port 3444;
MCP routes reach the separate Edge process on loopback port 3443. The Edge
reaches the Broker only over native macOS Unix-domain IPC authenticated with
the exact child process UID/GID, PID and start-time identity plus signed
requests and responses. The Broker socket is never tunnel-routed.

Reuse the native cross-process assembly demonstrated in
`packages/edge/src/edge-broker-https.test.ts`, not its test keys, synthetic
tokens, certificate bypasses, test principal, or broad default read policy.
Use the real owner issuer, JWT verifier, per-request grant revocation check,
protected origin certificates, and the explicitly bounded policy below.

## Bounded authority

The runner must verify a signed trial policy with an expiry no later than the
trial deadline, tied to the provisioned owner's principal and issuer. Start
from default-deny and enable exactly:

- `mac_health`
- `mac_capabilities`
- `mac_system_summary`

Grant only `mac.control.read` and `mac.system.read` for `host:broker`.
Filesystem roots are empty. Do not construct filesystem, task, GUI, network,
or privileged executors. Assert the enabled set before opening the listener.
OAuth scopes do not independently enable Broker capabilities.

## Lifecycle and isolation

Implement a foreground supervisor with a maximum 60-minute duration and
explicit `SIGINT`/`SIGTERM` handling. Auth, Edge and Broker must stop together
when a child exits unexpectedly or the deadline expires. No launchd/PM2
registration, auto-restart, root execution, OS-permission change, or shared
tunnel restart belongs to the runner.

Keep session IPC keys, sockets, a separate trial Broker database, policy and
redacted audit records in a fresh owner-only trial directory outside the
repository. Do not load the provisioning `.env` into child environments.
Preserve the owner account and OAuth signing keys. Failed cleanup must be
reported; do not report the trial stopped until listeners and child processes
are confirmed absent. Keep audit output without bearer values or request URLs.

The existing production installer and its Developer ID/notarization gates
remain unchanged. The runner is a separately identified temporary trial path;
it must not call production installation APIs with weaker signature settings.
Its evidence does not satisfy persistent installation or public release gates.

## Start sequence

1. Build and verify the trial runner locally, including expiry, child failure,
   exact tool allowlist, denied operations and cleanup.
2. Start real Auth/Edge/native-Broker processes on loopback. Verify TLS without
   disabling certificate checks, an unauthenticated MCP 401 challenge, protected
   resource metadata, OAuth discovery, public-only JWKS, and revocation denial.
3. Compare a hostname-only tunnel change against the actual current shared
   configuration and its source of truth. Preserve unrelated routes, including
   KB-MCP. Apply the route and DNS only for this explicit trial after local
   preflight passes; use verified origin TLS and redact proxy request data.
4. Check the public endpoint and OAuth metadata before instructing the owner
   to create the ChatGPT connector. Select OAuth/public-client DCR; there is no
   manually provisioned client secret. Use the callback shown by the client,
   with the documented stable ChatGPT callback as the setup default.
5. The owner signs in and approves. Verify actual protocol negotiation, list
   exactly three tools, call `mac_system_summary`, and correlate a redacted
   Broker audit event. Do not call a pinned local-client test ChatGPT evidence.
6. Revoke the test grant and prove another call fails. Stop the runner, verify
   closed listeners and absent children, and remove only the trial hostname
   routing/DNS added for this run without disturbing other tunnel entries.

## Existing evidence and missing work

Owner provisioning and local Auth TLS/discovery are verified. The existing
native cross-process Edge/Broker test was rerun successfully on September 21.
The auth suite separately proves owner token projection and the three-tool
policy. These pieces are not yet assembled into the foreground runner.

Missing: bounded runner and lifecycle tests, signed trial policy provisioning,
reviewed tunnel/DNS application, and real ChatGPT login/tool/revocation evidence.
Do not reuse an integration test itself as a long-running public service.
