# LaunchAgent Edge identity startup evidence

Status: PARTIAL installed-startup identity assembly for MOP-072 / MOP-081 / VT-AUTH-01

## Boundary exercised

Commit `f3fc18e` adds `captureLaunchdEdgeProcessIdentity` and
`createMacOsNativeBrokerRuntimeForLaunchdEdge`. The startup boundary accepts
only an exact `gui/<uid>/com.mac-operator.<label>` service ID and expected
non-root UID, runs a fixed `/bin/launchctl print <service-id>` command with an
empty environment and bounded output, requires an exact service header, the
`running` state, and a bounded PID, then captures the PID's native
`startTimeMicros`. The resulting identity is passed into the production native
runtime factory; PID-only policy and request arguments cannot override it.

If the service is absent, stopped, malformed, or native identity readback
fails, startup returns a stable failure and does not construct a listening
runtime. Once listening, the existing native monitor and Edge revocation hook
still handle exit or PID replacement.

## Host evidence

- Host: Darwin arm64, macOS `26.2` build `25C56`.
- Runtime: Node `v25.5.0`, npm `11.8.0`.
- Source commit: `f3fc18e` (`security: capture Edge identity from launchd startup`).
- Focused startup/native IPC tests: 10 passed, 0 failed.
- Full regression: 307 passed, 0 failed, 2 opt-in real-sandbox tests skipped
  (309 total).
- A fake bounded `launchctl print` response for the current process proves
  positive PID/start-time capture, wrong-domain/stopped/malformed denial, and
  runtime assembly wiring through a real native listener start/close.
- Typecheck, contract verification, high-severity npm audit, and diff checks
  passed after the implementation.

## Source identity

- `packages/broker/src/native-runtime-startup.ts` SHA-256:
  `7333144a3528628f6f4edf8d983b56bb3547b05fc3a952933f3b2e887b62c6c8`
- `packages/broker/src/native-runtime-startup.test.ts` SHA-256:
  `8a83f6cf9a32abc53c53ba6b7f4205ce9597c1e4d2b915f57e6826efeb4067f5`
- `packages/broker/src/runtime.ts` SHA-256:
  `c17803500d756cfe958ac28b52e6f424bd94e44ed8f8ba491729e6a17c8192c8`
- `packages/broker/src/native-peer-ipc-server.ts` SHA-256:
  `eb189c20d80c64158e7104d42e8a76a014b64aedd71ebebe811a8c5ed0ebd720`

## Limits and next gate

No Mac-Operator LaunchAgent was installed or bootstrapped on the host, so this
does not prove a live Edge service, signed package provenance, or launchd
restart/readback. The service identity source is still launchd metadata rather
than a protected package/Keychain attestation; Developer ID signing,
notarization, protected key distribution, live installed readback, remote
issuer propagation, and capability enablement remain open.
