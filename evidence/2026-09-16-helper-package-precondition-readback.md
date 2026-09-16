# Privileged helper package precondition readback

- Date: 2026-09-16
- Scope: host-owned existing-service precondition before root package mutation

## Implementation

`executePrivilegedHelperPackagePlan` now requires a host-owned
`readExistingService` callback. The callback is sampled twice before any
signature command, filesystem write, or `launchctl` transition. A caller
snapshot, when supplied for compatibility, is treated only as a consistency
hint and must match the two host samples exactly.

Malformed or unavailable host readback maps to a stable failure, and a change
between samples maps to `SERVICE_MISMATCH`. This prevents stale or model-shaped
state from authorizing install, upgrade, rollback, or uninstall.

## Verification

- Focused helper package suite passed 18/18.
- The new test proves two reads, rejects a service-identity drift, maps reader
  failure, and rejects a missing reader.
- `npm run typecheck --silent` and `npm run build --silent` passed.

The boundary remains host-only. It does not prove root LaunchDaemon
installation, Developer ID signing, descriptor execution, or live service
readback on the physical Mac.

## Rollback

Revert the precondition reader API, tests, and documentation. No external
service, credential, or host state was changed.
