# Write-recovery regression verification

Date: 2026-09-16

## Scope

The restart-write recovery tests previously used a historical fixture clock
(`NOW`) after `BrokerStore` restart reconciliation had recorded the restart
boundary with the host wall clock. The recovery journal correctly rejected
the earlier timestamp, so the test observed `TEMPORARY_CLEANUP_SKIPPED`.
The retry test also closed its initial `BrokerStore` twice when setup had
already closed it.

The tests now use a recovery timestamp after the restart boundary and guard
the initial store close. No production recovery ordering or identity guard
was weakened.

## Verification

Commands run on the physical Darwin host:

```text
npm run build --silent
npm run build:native:fault-test --workspace @mac-operator/broker --silent
node --test --test-name-pattern='restart write recovery cleans only the recorded temporary artifact|restart write recovery retries a previously skipped temporary cleanup|real filesystem worker post-rename failure leaves' packages/broker/dist/broker.test.js
```

Result: 3/3 tests passed. The native post-rename fault fixture leaves the
committed target readable as `after`, while the Broker Job remains `unknown`.
The cleanup tests remove only the authorized temporary artifact and preserve
the outside symlink target.

