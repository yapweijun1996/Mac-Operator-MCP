# Launchd service identifier bound evidence

Date: 2026-09-16
Source revision: `c5d48fd`
Host: Darwin `25.2.0`, arm64; macOS `26.2`; Node.js `25.5.0`

## Boundary exercised

The system-domain `LaunchdServiceInspector` now applies the same 128-character
label grammar used by the strict launchd readback parser. A service identifier
whose label is 129 characters is rejected as `PRECONDITION_FAILED` before the
injected executor is invoked.

## Verification

```text
npm run typecheck --silent
npm run build --silent
node --test packages/broker/dist/service-inspector.test.js
tests 6
pass 6
fail 0
```

The physical Darwin test still performs only the existing read-only
`system/com.apple.logd` status probe; no launchd service or host configuration
was changed.

## Limits

This closes an adapter/parser input-bound mismatch. It does not prove
persistent launchd ownership, Developer ID provenance, descriptor-backed
execution, root-domain helper installation, or remote issuer deployment.

## Rollback

Revert commit `c5d48fd`; no external state was changed.
