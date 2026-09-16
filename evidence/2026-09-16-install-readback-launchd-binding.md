# macOS install readback LaunchAgent binding evidence

Date: 2026-09-16  
Source revision: `acc1924`  
Host: Darwin `25.2.0`, arm64; macOS `26.2`; Node.js `25.5.0`

## Boundary exercised

The composed Broker and Edge installation readbacks now retain the planned
`gui/<uid>` domain and `LaunchAgent` type. Final validation compares both
identity fields with the reviewed plan, so a forged domain or a substituted
`LaunchDaemon` cannot pass post-bootstrap verification even when the remaining
program and plist fields match.

## Verification

Focused install-plan, launchd-readback, and privileged-helper package suites
pass, including negative domain/type substitutions:

```text
npm run typecheck -- --pretty false
npm run lint
npm run build --silent
node --test packages/broker/dist/macos-install-plan.test.js \
  packages/broker/dist/launchd-readback.test.js \
  packages/broker/dist/privileged-helper-package.test.js
tests 40
pass 40
fail 0
```

No launchd state or host configuration was changed by this verification.

## Limits

This closes the final-object identity retention gap for reviewed user-domain
install plans. It does not prove persistent singleton ownership, Developer ID
provenance, production descriptor execution, or privileged helper enablement.

## Rollback

Revert commit `acc1924`; no launchd state or host configuration changed.
