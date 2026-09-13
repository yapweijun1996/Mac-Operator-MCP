# Privileged Helper Native Caller Evidence

- Date: 2026-09-13
- Source commit: `7a4a788`
- Scope: real macOS cross-process helper IPC caller boundary
- Test: `packages/broker/src/privileged-helper-native.test.ts`

## Verified

The test starts a separately spawned Node process as the authorized Broker
fixture, captures its native PID/start-time identity, and constructs
`PrivilegedHelperIpcServer` with that exact identity and the current UID/GID.
The authorized process connects through a temporary Unix socket and sends a
malformed request. It receives the stable `PRECONDITION_FAILED` response,
proving that the accepted peer reaches the helper parser after native peer
authorization.

A second independently spawned process connects to the same listener and sends
the same malformed request. Native peer authorization rejects it before the
helper parser, so the attacker result file remains empty. The fixture keeps the
authorized process alive long enough for the listener's identity monitor and
cleans the socket and temporary files after the assertion.

## Boundary and limits

No launchd service, root process, privileged operation, or persistent socket was
installed. This evidence proves the cross-process native caller boundary only;
it does not prove Developer ID provenance, root-domain installation, helper
adapter enablement, or production deployment.

## Reproduction

```text
npm run build
node --test packages/broker/dist/privileged-helper-native.test.js
```

The focused test passed on the real macOS host. The full suite passed 346 tests
(344 passed, 2 opt-in real-sandbox tests skipped).
