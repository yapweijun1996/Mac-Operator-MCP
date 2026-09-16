# Launchd conflicting-field rejection evidence

Date: 2026-09-16
Source revision: `f69090a`
Host: Darwin `25.2.0`, arm64; macOS `26.2`; Node.js `25.5.0`

## Boundary exercised

The bounded `launchctl print` parser now treats duplicate service headers,
duplicate top-level singleton fields, and duplicate program-argument blocks as
malformed. Nested launchd dictionaries are excluded from top-level extraction,
so a nested `state = active` cannot shadow the service's top-level state.
Conflicting observations fail closed as `MALFORMED_READBACK` before install,
helper, or service authority consumes them.

## Verification

```text
npm run typecheck --silent
npm run build --silent
node --test packages/broker/dist/launchd-readback.test.js
tests 5
pass 5
fail 0

node --test packages/broker/dist/macos-install-plan.test.js \
  packages/broker/dist/privileged-helper-package.test.js \
  packages/broker/dist/service-startup.test.js \
  packages/broker/dist/packaged-service-smoke.test.js
tests 44
pass 43
fail 0
skipped 1
```

The physical read-only probe of `system/com.apple.logd` still succeeds. The
packaged LaunchAgent smoke remains opt-in and was skipped because
`MOPS_REAL_INSTALL=1` was not set; no launchd service or host configuration
was changed.

## Limits

This closes parser ambiguity for conflicting launchd observations. It does
not prove persistent singleton ownership, code-signing provenance, installed
root-domain helper execution, or remote deployment.

## Rollback

Revert commit `f69090a`; no external state was changed.
