# Privileged-helper launchd bootstrap retry evidence

Date: 2026-09-16
Source revision: `316e303`
Host: Darwin `25.2.0`, arm64; macOS `26.2`; Node.js `25.5.0`

## Boundary exercised

Privileged-helper startup now handles the transient launchd `xpcproxy` state
without weakening identity checks. It retries only when the exact top-level
state is `xpcproxy`, stops after a five-second deadline, and then requires the
requested `gui/<uid>` service to report `LaunchAgent` before native PID and
start-time capture. Missing or malformed type readback is not retried.

## Verification

```text
npm run typecheck --silent
npm run build --silent
node --test packages/broker/dist/privileged-helper-runtime.test.js \
  packages/broker/dist/native-runtime-startup.test.js \
  packages/broker/dist/launchd-readback.test.js \
  packages/broker/dist/service-inspector.test.js
tests 26
pass 26
fail 0
```

The physical Darwin run includes native PID/start-time capture and the
read-only `system/com.apple.logd` launchd probe. No launchd service or host
configuration was changed.

## Limits

This closes the helper's transient launchd bootstrap race only. It does not
prove persistent launchd singleton ownership, Developer ID provenance,
descriptor-backed process execution, root-domain helper installation, or
remote issuer deployment.

## Rollback

Revert commit `316e303`; no external state was changed.
