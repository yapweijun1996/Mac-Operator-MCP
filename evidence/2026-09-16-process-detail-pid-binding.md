# Process detail PID-binding evidence

Date: 2026-09-16
Source revision: `a8cec0e`
Host: Darwin `25.2.0`, arm64; macOS `26.2`; Node.js `25.5.0`

## Boundary exercised

The native process-inspection adapter now binds the parsed detail payload's
`pid` to the requested PID after the before/after native identity fence. A
different adapter result is rejected before it can be returned to a caller;
the Broker-layer target check remains as defense in depth.

## Verification

```text
npm run typecheck --silent
npm run build --silent
node --test --test-name-pattern='mac_process_inspect' packages/broker/dist/broker.test.js
tests 2
pass 2
fail 0

node --test packages/broker/dist/process-inspector.test.js
tests 7
pass 7
fail 0
```

The tests include the physical Darwin native inspection path and a pure
adapter-result mismatch regression. No process is signalled or modified.

## Limits

This closes the adapter-result PID mismatch boundary and does not prove
continuous process identity after a read completes, full process-tree
attestation, descriptor-backed execution, or production sandbox isolation.

## Rollback

Revert commit `a8cec0e`; no external state was changed.
