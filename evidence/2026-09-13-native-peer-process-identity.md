# Native IPC peer process-identity evidence

Status: PARTIAL local caller-identity evidence for MOP-011 / MOP-081 / VT-AUTH-01

## Latest lifecycle evidence

Commit `9c48359` extends the stronger native identity binding into a
fail-closed lifecycle boundary. The native server checks the captured PID and
`startTimeMicros` before listener creation and then rechecks that identity on a
bounded unref'd monitor. If the Edge exits or the PID is replaced, the listener
and accepted sockets are closed, the socket path is removed, and the runtime
revokes the exact Edge in the Broker's durable authority store. The revocation
rejects new work and causes active authority polling to stop late success
publication; the host callback is not an MCP-exposed operation.

On the Mac mini host, a separately spawned `/bin/sleep` Edge fixture was
started with explicit `cwd`, minimal `PATH`, ignored stdio, and a 25 ms monitor.
After SIGTERM, the loss callback observed the originally captured identity,
`edge-1` was durably revoked, and the native socket returned `ENOENT`.
The Broker lifecycle test also verifies the redacted revocation intent and
completion audit pair and a signed request returning stable `REVOKED`.

## Boundary exercised

The macOS native peer policy now supports an explicit `allowedProcessIdentity`
containing a PID and the native `startTimeMicros` observed for that PID. After
`getpeereid` and `LOCAL_PEERPID` produce the accepted peer credentials, the
Broker reads the current native process identity and requires both values to
match before constructing a Node socket or parsing a request. A mismatched
start time is therefore rejected even when the peer has the expected UID/GID
and the same numeric PID. The legacy PID-only policy remains available only as
an explicit compatibility configuration; it does not receive the stronger
start-time guarantee.

The same check is used by the compatibility `MacOsPeerCredentialVerifier`.
`capturePeerProcessIdentity` provides a bounded, native readback primitive for
an installation/startup layer to capture the intended Edge identity. No peer
identity is accepted from request arguments.

## Host evidence

- Host: Darwin arm64, macOS `26.2` build `25C56`.
- Runtime: Node `v25.5.0`, npm `11.8.0`.
- Source commits: `f76e8a0` (`security: bind native IPC peers to process identity`),
  `752f73a` (`security: require peer identity for native runtime`),
  `cd84e37` (`test: prove cross-process peer identity binding`), and
  `9c48359` (`security: fail closed on Edge peer identity loss`).
- Captured: `2026-09-13`; source working tree was clean at test capture.
- Focused native IPC/peer/runtime tests: 13 passed, 0 failed.
- Full regression: 302 passed, 0 failed, 2 opt-in real-sandbox tests skipped
  (304 total).
- `MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/sandbox-profile.test.js` —
  7 passed, 0 failed.
- The native server rejects a deliberately mismatched start time before JSON
  parsing and leaves the Broker audit ledger empty.
- `createMacOsNativeBrokerRuntime` rejects a PID-only peer policy before it
  constructs the native listener; the production assembly boundary therefore
  cannot silently select the compatibility policy.
- The compatibility verifier accepts the current process with the captured
  start-time identity and rejects the same PID with a substituted start time.
- The native identity-loss fixture closes the listener and revokes the Edge
  before any replacement request can be admitted.

## Source identity

- `packages/broker/src/peer-credentials.ts` SHA-256:
  `3c156002695404a4385c32414c720687445e7162f20f6a255aedc3479df4702b`
- `packages/broker/src/native-peer-ipc-server.ts` SHA-256:
  `eb189c20d80c64158e7104d42e8a76a014b64aedd71ebebe811a8c5ed0ebd720`
- `packages/broker/src/peer-credentials.test.ts` SHA-256:
  `98c556ee3113a20531617a5b7e27a53d02a0b0f663c4d0e9d59b3670be3482e9`
- `packages/broker/src/native-ipc-server.test.ts` SHA-256:
  `8fa7c0292672b814b6797c87d49b658ba5f12af75d239adfa08551d3637bd63d`
- `packages/broker/src/runtime.ts` SHA-256:
  `c17803500d756cfe958ac28b52e6f424bd94e44ed8f8ba491729e6a17c8192c8`
- `packages/broker/src/broker.ts` SHA-256:
  `7474a3dc4d29c41a8e6482686c722409ea2bb8d95c8d45c39ca9aed109ca03cc`
- `packages/broker/src/broker.test.ts` SHA-256:
  `b4d2a5da1d7095de91160414038885af8a210efec635adff3b0d8dc55f8cacb0`

## Limits and next gate

This proves the reusable identity-check boundary, the native runtime's
fail-closed construction and peer-loss gates, and durable Broker revocation;
it does not prove the installed caller chain. The LaunchAgent/Edge packaging
layer must capture the intended Edge identity before startup, configure the
stronger policy, and provide signed provenance and restart/readback behavior.
Production packaging, Developer ID provenance, Keychain-backed key
distribution, live launchd readback, remote issuer integration, and capability
enablement remain open.
