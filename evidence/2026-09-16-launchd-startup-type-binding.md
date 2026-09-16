# Launchd startup LaunchAgent type-binding evidence

Date: 2026-09-16
Source revision: `bd14cba`
Host: Darwin `25.2.0`, arm64; macOS `26.2`; Node.js `25.5.0`

## Boundary exercised

Edge startup identity capture and privileged-helper Broker-caller capture now
require the shared strict launchd readback to explicitly report
`type = LaunchAgent` after validating the requested `gui/<uid>` service.
Missing type readback fails closed as the component's stable service-unavailable
error before a PID is accepted. The shared parser still rejects a
domain/type mismatch, duplicate fields, nested-field shadowing, malformed PIDs,
and unsupported states.

## Verification

```text
npm run typecheck --silent
npm run build --silent
node --test packages/broker/dist/native-runtime-startup.test.js \
  packages/broker/dist/privileged-helper-runtime.test.js \
  packages/broker/dist/launchd-readback.test.js
tests 20
pass 20
fail 0
```

The tests ran on the physical Darwin host and include the read-only
`system/com.apple.logd` launchd probe. No launchd service or host configuration
was changed.

## Limits

This closes an explicit startup type-identity ambiguity. It does not prove
persistent launchd singleton ownership, Developer ID provenance,
descriptor-backed process execution, root-domain helper installation, or
remote issuer deployment.

## Rollback

Revert commit `bd14cba`; no external state was changed.
