# Launchd readback identity binding evidence

Date: 2026-09-16
Source revision: `cd9f0bf`
Host: Darwin `25.2.0`, arm64; macOS `26.2`; Node.js `25.5.0`

## Boundary exercised

The bounded `launchctl print` parser now binds a readback's declared service
type to its requested domain (`gui/<uid>` requires `LaunchAgent`, `system`
requires `LaunchDaemon`). When both fields are present, the first program
argument must also equal the declared program path. Mismatches are rejected as
`MALFORMED_READBACK` before package/install authority can use the observation.

## Verification

The focused suites cover the new type/domain and program/argv substitution
cases, fixed `/bin/launchctl` argv, bounded output, package-plan readback,
privileged-helper package readback, and the physical system launchd service
probe:

```text
npm run typecheck -- --pretty false
npm run lint
npm run build --silent
node --test packages/broker/dist/launchd-readback.test.js \
  packages/broker/dist/macos-install-plan.test.js \
  packages/broker/dist/privileged-helper-package.test.js \
  packages/broker/dist/service-inspector.test.js
tests 43
pass 43
fail 0
```

The physical probe read back `system/com.apple.logd`; no service was
installed, changed, or stopped.

## Limits

This closes a parser-level identity-substitution gap. It does not prove
launchd singleton ownership, code-signing provenance, persistent installation,
or root-domain helper execution. Those remain release-gated.

## Rollback

Revert commit `cd9f0bf`; no launchd state or host configuration changed.
