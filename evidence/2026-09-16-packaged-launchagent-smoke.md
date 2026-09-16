# Packaged Edge and Broker LaunchAgent smoke evidence

Date: 2026-09-16
Source revision: `2e5d08b`
Host: physical Darwin arm64 Mac mini; macOS 26.2

## Boundary exercised

The opt-in smoke copied the reviewed Edge and Broker service entrypoints into
a temporary owner-only package and bootstrapped both as temporary user
LaunchAgents. It exercised the production-shaped startup assembly without
installing the package or changing any fixed production label when one was
already present.

## Verification

- Temporary policy, Edge key, TLS material, audit-anchor Keychain item, and
  owner-only runtime/data directories were created under a disposable root.
- Edge was bootstrapped first; launchd readback matched the exact Node binary,
  entrypoint, LaunchAgent type, and captured PID/start-time identity.
- Broker was then bootstrapped; readback matched its exact entrypoint and
  captured identity, and both native sockets appeared with owner-only `0600`
  permissions.
- The authenticated Broker status channel returned `running`, zero enabled
  capabilities, and the configured source revision.
- Cleanup booted out both temporary jobs, verified their absence, retired the
  synthetic Keychain item, and removed the disposable root.

Command:

```text
MOPS_REAL_INSTALL=1 node --test packages/broker/dist/packaged-service-smoke.test.js
```

Result: 1/1 test passed in 3.6 seconds.

## Limits

This is temporary LaunchAgent/startup and authenticated status-channel
evidence. It does not prove persistent production installation, Developer ID
or notarization provenance, external OAuth/remote transport, privileged helper
installation, or final release approval.
