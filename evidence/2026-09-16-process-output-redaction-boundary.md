# Process output redaction boundary evidence

Date: 2026-09-16
Source revision: `16cc28c`
Host: Darwin `25.2.0`, arm64; macOS `26.2`; Node.js `25.5.0`

## Boundary exercised

`ProcessSupervisor` now applies Broker-owned bounded secret redaction to both
stdout and stderr before returning a `ProcessExecutionResult`. This is a
defense-in-depth boundary for fixed adapters: known credential signatures are
not exposed even if an adapter parser forgets to redact its child output.

## Verification

```text
npm run typecheck -- --pretty false
npm run build --silent
npm run lint
node --test packages/broker/dist/process-supervisor.test.js \
  packages/broker/dist/launchd-readback.test.js \
  packages/broker/dist/service-inspector.test.js
tests 51
pass 51
fail 0
```

A child-generated GitHub token is returned as `[REDACTED]`; public output and
stderr remain available within the existing byte budget. No host configuration
was changed.

## Limits

The policy is signature-based and does not detect every opaque or binary
credential format. It also does not replace adapter-specific structured
validation or production sandbox isolation.

## Rollback

Revert commit `16cc28c`; no external state was changed.
