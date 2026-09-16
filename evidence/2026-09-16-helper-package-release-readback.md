# Privileged helper package release readback

- Date: 2026-09-16
- Scope: authenticated final readback for a released helper capability

## Implementation

The package host observer now reads helper runtime metadata through the
authenticated status IPC client when the plan contains the explicit
`host-verified` `mac_priv_service_control` release. Final readback accepts the
matching `adapterAvailable: true` and exact capability list. A drifted helper
reporting `adapterAvailable: false` with an empty list is rejected with stable
`SERVICE_MISMATCH`.

## Verification

- `npm run typecheck --silent` passed.
- `npm run build --silent` passed.
- Focused package suite passed 17/17.
- Full `npm test --silent` passed: 871 tests, 857 passed, 14 explicit skips,
  0 failures.
- The test uses a temporary authenticated IPC socket and clears the key before
  cleanup; no host helper or credential store is changed.

This proves the observer and final package readback binding only. It does not
prove root LaunchDaemon installation, descriptor execution, signing
provenance, or live privileged mutation on the physical Mac.

## Rollback

Revert the test and documentation changes. No external service or persistent
host state was modified.
