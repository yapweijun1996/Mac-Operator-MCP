# Packaged Service LaunchAgent Smoke Evidence

- Source revision: `42992e1`
- Date: 2026-09-15
- Host: physical macOS host used by the repository test harness
- Scope: temporary-user LaunchAgent lifecycle for packaged Edge and Broker
- Tool contract version: 0.1
- Policy version: 0.1

## Decision

The packaged service smoke may exercise `launchctl bootstrap` and `bootout`
only with generated temporary plist files, temporary package/data/runtime/log
roots, and a fixed test policy. It must skip without mutation when the reviewed
Mac-Operator LaunchAgent labels are already loaded. The test does not install,
replace, or remove a production service.

## Verification

Command:

```text
MOPS_REAL_INSTALL=1 node --test packages/broker/dist/packaged-service-smoke.test.js
```

Result: 1 test passed, 0 failed, 0 skipped. The physical host run:

- created temporary Edge and Broker LaunchAgent plists and package roots;
- bootstrapped both services in the current user's `gui/<uid>` launchd domain;
- read back the expected Node executable, entrypoint arguments, LaunchAgent
  type, PID/start-time identity, owner-only IPC sockets, and Broker status;
- completed an authenticated status readback with no enabled capabilities;
- booted both services out, confirmed both labels absent, retired the temporary
  Keychain audit key, and removed the temporary root.

No fixed `com.mac-operator.edge` or `com.mac-operator.broker` label was changed
when already present. The test uses bounded fixed commands and empty child
environments; no credentials or service output are persisted in this evidence.

## Boundary status

This closes the temporary packaged-user LaunchAgent lifecycle and shutdown
readback slice. Developer ID/notarization provenance, production fixed-label
ownership, persistent deployment/rotation, crash/remount durability, and
operator approval for installation remain release gates.
