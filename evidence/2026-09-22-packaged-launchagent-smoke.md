# Packaged Edge and Broker LaunchAgent smoke — 2026-09-22

Status: `PASS` for the temporary production-shaped user-domain startup
boundary; formal production release and public capability enablement remain
closed.

The opt-in smoke copied the reviewed Edge and Broker entrypoints into a
temporary owner-only package and bootstrapped both as real user-domain
LaunchAgents. It verified the exact Node executable and entrypoint readback,
LaunchAgent type, PID identity, Edge TLS readiness, authenticated Broker IPC,
owner-only `0600` Broker/status sockets, and the authenticated Broker status
channel reporting `running` with zero enabled capabilities. The cleanup then
booted out both jobs, verified absence, retired the temporary Keychain audit
item, and removed the disposable root.

Verification:

```text
npm run build
MOPS_REAL_INSTALL=1 node --test --test-timeout=120000 packages/broker/dist/packaged-service-smoke.test.js
```

Result: 1 test passed, 0 failed, 0 skipped in about 3.6 seconds. A follow-up
read-only check confirmed `gui/<uid>/com.mac-operator.broker` was absent and
the live R1 snapshot preflight still passed.

This is real Darwin arm64 staging evidence. It does not prove Developer ID or
notarization provenance, persistent production installation, external OAuth
transport, root-helper installation, public D1/G1/P1 enablement, or
independent P0/P1 review.
