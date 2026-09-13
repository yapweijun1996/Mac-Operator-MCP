# Native IPC peer process-identity evidence

Status: PARTIAL local caller-identity evidence for MOP-011 / MOP-081 / VT-AUTH-01

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
- Source commits: `f76e8a0` (`security: bind native IPC peers to process identity`)
  and `752f73a` (`security: require peer identity for native runtime`).
- Captured: `2026-09-13`; source working tree was clean at test capture.
- Focused native IPC/peer tests: 11 passed, 0 failed.
- Full regression: 299 passed, 0 failed, 2 opt-in real-sandbox tests skipped.
- The native server rejects a deliberately mismatched start time before JSON
  parsing and leaves the Broker audit ledger empty.
- `createMacOsNativeBrokerRuntime` rejects a PID-only peer policy before it
  constructs the native listener; the production assembly boundary therefore
  cannot silently select the compatibility policy.
- The compatibility verifier accepts the current process with the captured
  start-time identity and rejects the same PID with a substituted start time.

## Source identity

- `packages/broker/src/peer-credentials.ts` SHA-256:
  `3c156002695404a4385c32414c720687445e7162f20f6a255aedc3479df4702b`
- `packages/broker/src/native-peer-ipc-server.ts` SHA-256:
  `54d2ed52332f427a7d496a48dc66fbba7aaf3e156518dad2d21fc839623bd4c6`
- `packages/broker/src/peer-credentials.test.ts` SHA-256:
  `98c556ee3113a20531617a5b7e27a53d02a0b0f663c4d0e9d59b3670be3482e9`
- `packages/broker/src/native-ipc-server.test.ts` SHA-256 at `f76e8a0`:
  `5ceb7162d3f7fdaf9716dcc71596135be8b70f279cf8f99d9b0b14c617073ce7`
- `packages/broker/src/runtime.ts` SHA-256:
  `95aa51569d69d74216d85fdb7ff126c792b545944f8881846a85052c4aa5d416`
- `packages/broker/src/native-ipc-server.test.ts` after the runtime-assembly
  guard SHA-256:
  `607aadcf702a7fbe62217a6e426e69d66d6bdf22d8cbce8c8e774067889e3563`

## Limits and next gate

This proves the reusable identity-check boundary and the native runtime's
fail-closed construction gate, not the installed caller chain. The
LaunchAgent/Edge packaging layer must capture the intended Edge identity,
configure the stronger policy, and fail closed when the Edge exits or restarts
with a new identity. Production packaging, signed caller provenance,
Keychain-backed key distribution, live launchd readback, and capability
enablement remain open.
