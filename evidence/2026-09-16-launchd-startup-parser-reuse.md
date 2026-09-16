# Launchd startup parser reuse evidence

Date: 2026-09-16
Source revision: `3fa25e1`
Host: Darwin `25.2.0`, arm64; macOS `26.2`; Node.js `25.5.0`

## Boundary exercised

Edge startup identity capture and privileged-helper Broker-caller capture now
reuse the strict `launchd-readback` parser. Duplicate or nested launchd fields,
conflicting headers, and malformed PID values fail closed before native
process-identity capture. Existing stable startup error classes remain
preserved: unsupported/non-running states map to the component's
`*_PROCESS_NOT_RUNNING` error, while malformed service identity maps to the
component's unavailable error. `xpcproxy` retry is restricted to the exact
top-level state field.

## Verification

```text
npm run typecheck --silent
npm run build --silent
node --test packages/broker/dist/native-runtime-startup.test.js \
  packages/broker/dist/privileged-helper-runtime.test.js \
  packages/broker/dist/launchd-readback.test.js \
  packages/broker/dist/service-inspector.test.js
tests 23
pass 23
fail 0
```

The read-only `system/com.apple.logd` probe and the existing Edge/Helper
startup identity fixtures both pass. No launchd service or host configuration
was changed.

## Limits

This removes parser drift and closes conflicting-field ambiguity at startup.
It does not prove persistent launchd singleton ownership, Developer ID
provenance, descriptor-backed process execution, root-domain installation, or
remote issuer deployment.

## Rollback

Revert commit `3fa25e1`; no external state was changed.
