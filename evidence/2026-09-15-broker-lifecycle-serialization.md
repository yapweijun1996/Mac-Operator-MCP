# Broker Lifecycle Serialization Evidence

Date: 2026-09-15

Source revision: `6297c58`

## Boundary

`BrokerServiceEntrypoint` now serializes `start()` and `stop()` transitions
through one lifecycle queue around `LocalBrokerRuntime`. A stop requested
while runtime startup is pending waits for startup to settle, then owns the
final transition to `stopped`; a failed startup remains recoverable through
the same ordered stop path.

This keeps service readback from publishing a stale `running` state after a
shutdown request and aligns the process-facing Broker lifecycle with the
Edge lifecycle boundary.

## Verification

- `npx tsc -b packages/broker/tsconfig.json --pretty false`: passed.
- `node --test --test-timeout=120000 packages/broker/dist/service-entrypoint.test.js`:
  3 passed, 0 failed, 0 skipped.
- `npm run lint`: passed for 615 tracked files.
- `git diff --check`: passed.

The existing Broker/Persistence test process remained undisturbed; this
evidence does not claim completion of the full repository regression or any
production installation and signing gate.
