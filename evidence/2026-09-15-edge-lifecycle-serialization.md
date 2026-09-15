# Edge Lifecycle Serialization Evidence

Date: 2026-09-15

Source revision: `04132fe`

## Boundary

`EdgeServiceEntrypoint` now serializes `start()` and `stop()` transitions
through one lifecycle queue. A stop requested while listener startup is
pending waits for the startup operation to settle, then owns the final
transition to `stopped`. A failed start remains recoverable through the same
serialized stop path.

This prevents an asynchronous listener callback from publishing `running`
after a stop request has already been accepted.

## Verification

- `npx tsc -b packages/edge/tsconfig.json --pretty false`: passed.
- `node --test --test-timeout=120000 packages/edge/dist/service-startup.test.js`:
  5 passed, 0 failed, 0 skipped.
- `npm run typecheck`: passed.
- `npm run lint`: passed for 614 tracked files.
- `git diff --check`: passed.

The old Broker/Persistence test process remained undisturbed; this evidence
does not claim completion of the full repository regression or any production
installation and signing gate.
