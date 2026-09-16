# Privileged helper readback LaunchDaemon binding evidence

Date: 2026-09-16
Source revision: `866f4ee`
Host: Darwin `25.2.0`, arm64; macOS `26.2`; Node.js `25.5.0`

## Boundary exercised

The root-domain helper package readback now retains the reviewed
`LaunchDaemon` type in its final object. Validation requires both
`domain: "system"` and `type: "LaunchDaemon"`, so a post-composition type
substitution cannot pass even when the root flag and remaining launchd fields
match.

## Verification

```text
npm run typecheck -- --pretty false
npm run build --silent
npm run lint
node --test packages/broker/dist/privileged-helper-package.test.js \
  packages/broker/dist/privileged-helper-runtime.test.js \
  packages/broker/dist/privileged-broker-dispatch.test.js
tests 23
pass 23
fail 0
```

No root-domain service or host configuration was installed or changed.

## Limits

This closes final-object LaunchDaemon type retention for the helper package.
It does not prove root-domain installation, Developer ID provenance, helper
adapter execution, crash recovery, or independent review.

## Rollback

Revert commit `866f4ee`; no external state was changed.
