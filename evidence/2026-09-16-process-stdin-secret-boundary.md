# Process stdin secret boundary evidence

Date: 2026-09-16
Source revision: `dddbdbc`
Host: Darwin `25.2.0`, arm64; macOS `26.2`; Node.js `25.5.0`

## Boundary exercised

`ProcessSupervisor` now applies the Broker secret-content policy to bounded
stdin before creating a child process. Plain and Base64-encoded known
credential signatures are rejected with stable `POLICY_DENIED`; non-secret stdin remains
bounded, non-persisted, and available to fixed adapters that need public input.

## Verification

```text
npm run typecheck -- --pretty false
npm run build --silent
npm run lint
node --test packages/broker/dist/process-supervisor.test.js \
  packages/broker/dist/secret-policy.test.js
tests 51
pass 51
fail 0
```

The negative tests cover a GitHub token in plaintext and as Base64. No child
process receives either payload, and no host configuration was changed.

## Limits

This closes the known-secret stdin path for the shared supervisor. It does not
prove opaque-secret detection, complete credential-store isolation, or kernel
sandbox enforcement; those remain separate release gates.

## Rollback

Revert commit `dddbdbc`; no external state was changed.
