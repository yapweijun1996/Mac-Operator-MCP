# App Sandbox Broker Network Proxy Boundary

Date: 2026-09-22
Host: Darwin arm64 physical Mac, macOS 26.2, current process UID 501
Status: `candidate-integrated`; production task networking remains disabled

## Boundary

The App Sandbox task executor now supports an independent `networkEvidenceAccepted`
gate for `networkPolicy: "allowlist"`. When accepted for a probe, the Broker
creates a per-run Unix socketpair and passes only one endpoint through the
authenticated descriptor handoff. The helper passes the endpoint to the fixed
`/bin/sh` child on FD 7 with a run-bound capability token. The child-facing
protocol is bounded newline-delimited JSON with strict fields, canonical base64
payloads, single-use request IDs, and stable error responses.

The child never receives a network entitlement or a raw network socket. The
Broker endpoint validates the token, target, request budget, response budget,
timeout, cancellation, replay identity, and secret-shaped content before the
Broker-owned proxy opens a numeric loopback TCP connection. The policy is
constructed from the resolved Broker task profile and the existing task
descriptor digest continues to bind the allowlist to the admitted task.

## Physical verification

The controlled probe was run with:

`MOP_PROBE_NETWORK_PROXY=1 npm run probe:app-sandbox:executor`

It passed the existing App Sandbox executor checks and additionally verified:

- the child used FD 7 and the run-bound token to send one framed request;
- the Broker proxy reached only the exact loopback allowlisted fixture;
- the fixture returned the expected bounded response through the channel;
- direct child `/dev/tcp` access remained denied, even while proxy access succeeded;
- the fixture observed exactly one proxy request; and
- helper, task, socket, staged-root, and temporary-run cleanup completed.

The focused TypeScript suites for the proxy, channel, App Sandbox executor, and
App Sandbox runner pass 10/10. This is physical boundary evidence for the
candidate transport, not production signing, entitlement, installed identity,
or public `mac_task_run` enablement.

## Remaining gates

The network evidence gate is not accepted by default in startup assembly. The
helper is still ad-hoc signed, Developer ID/notarization and installed
identity readback are unavailable, and the App Sandbox task runner remains
outside the public MCP catalog. Production release also requires rollback,
recovery, and final readback review.

## Rollback

Rollback is source-level removal of the channel, native network-FD mode,
focused tests, probe option, and this evidence. The probe created no persistent
listener or policy and changed no MCP scope, OAuth grant, credential, or host
service state.
