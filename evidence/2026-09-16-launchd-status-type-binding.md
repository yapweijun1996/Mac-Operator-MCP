# Launchd status LaunchDaemon type-binding evidence

Date: 2026-09-16
Source revision: `583fa09`
Host: Darwin `25.2.0`, arm64; macOS `26.2`; Node.js `25.5.0`

## Boundary exercised

The system-domain `LaunchdServiceInspector` now requires the strict readback
to explicitly report `type = LaunchDaemon` before publishing a service status.
Missing identity is rejected as `EXECUTION_FAILED`; a domain/type mismatch is
rejected by the shared parser. Existing bounded state normalization, including
the conservative `xpcproxy -> loaded` mapping, remains unchanged.

## Verification

```text
npm run typecheck --silent
npm run build --silent
node --test packages/broker/dist/service-inspector.test.js \
  packages/broker/dist/launchd-readback.test.js \
  packages/broker/dist/native-runtime-startup.test.js \
  packages/broker/dist/privileged-helper-runtime.test.js
tests 25
pass 25
fail 0
```

The physical Darwin run includes a read-only `system/com.apple.logd` probe; no
launchd service or host configuration was changed.

## Limits

This closes status-publication ambiguity for system launchd services. It does
not prove persistent launchd singleton ownership, Developer ID provenance,
descriptor-backed process execution, root-domain helper installation, or
remote issuer deployment.

## Rollback

Revert commit `583fa09`; no external state was changed.
