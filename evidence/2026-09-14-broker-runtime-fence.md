# Broker Runtime-Fence Evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: persisted Broker instance fencing; no capability enablement

## Boundary

Packaged Broker startup constructs `BrokerStore` with `runtimeFence: true`.
SQLite schema version 5 creates the owner-local `broker_runtime_fence` singleton
row. A service instance claims the next monotonic generation and a fresh
memory-only token before restart reconciliation. Every later write transaction
opens its `BEGIN IMMEDIATE` write lock and verifies the generation/token pair
before applying mutations, audit records, authority changes, or Job state.

When a second Broker instance takes over the same database, the first instance
is stale. Its attempted terminal Job completion is rejected with stable
`CONFLICT`; the restarted instance retains the reconciled `UNKNOWN` Job rather
than accepting the old writer's success.

## Commands

```text
npm run build
node --test packages/broker/dist/persistence.test.js
```

## Observed result

- The focused persistence suite passes 42/42 after the runtime-fence test and
  schema-version update.
- The complete `MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test` regression
  passes 484/485 with one explicit opt-in install skip.
- The takeover fixture observes the second generation and rejects the stale
  first-store completion before it can publish a terminal result.
- The production service-startup path explicitly enables the fence; generic
  persistence fixtures can leave it disabled for isolated concurrency tests.

## Limitations

This is a SQLite/service-instance fencing boundary, not kernel process
ownership. It does not prove that a crashed process, detached worker, or
launchd job has exited; it does not attribute post-snapshot descendants; and it
does not provide installed production service, Developer ID, external audit,
or privileged-helper evidence. Old processes must still be handled by the
separate process-tree and restart-recovery controls.
