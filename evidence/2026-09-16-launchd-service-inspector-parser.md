# Launchd service-inspector parser evidence

Date: 2026-09-16
Source revision: `917d479`
Host: Darwin `25.2.0`, arm64; macOS `26.2`; Node.js `25.5.0`

## Boundary exercised

The read-only `LaunchdServiceInspector` now consumes the shared strict launchd
readback parser instead of independent regular expressions. Service status
therefore rejects forged headers, duplicate singleton fields, nested-field
shadowing, malformed PIDs, and unsupported states before returning status.
The public `xpcproxy -> loaded` mapping and stable Broker error classes remain
unchanged.

## Verification

```text
npm run typecheck --silent
npm run build --silent
node --test packages/broker/dist/native-runtime-startup.test.js \
  packages/broker/dist/privileged-helper-runtime.test.js \
  packages/broker/dist/launchd-readback.test.js \
  packages/broker/dist/service-inspector.test.js \
  packages/broker/dist/macos-install-plan.test.js \
  packages/broker/dist/privileged-helper-package.test.js
tests 60
pass 60
fail 0
```

The physical read-only `system/com.apple.logd` status/readback probe succeeds;
no launchd service or host configuration was changed.

## Limits

This removes parser drift for launchd status consumers. It does not prove
persistent launchd singleton ownership, Developer ID provenance,
descriptor-backed process execution, root-domain helper installation, or
remote issuer deployment.

## Rollback

Revert commit `917d479`; no external state was changed.
