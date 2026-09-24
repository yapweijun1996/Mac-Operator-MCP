# Cancellation revision fence

## Decision

The durable Job cancellation marker is an authority change and increments the
Job revision. A worker can therefore return with the revision it observed
before cancellation. `BrokerStore.finishJob` now accepts a stale revision only
for the conservative `UNKNOWN` outcome when the current row is still the same
running Job and already records `cancel_requested`; late success is never
accepted and the current lease identity is still checked when one exists.

## Evidence

- `packages/broker/src/persistence.ts` uses the current persisted row only for
  this cancellation-to-`UNKNOWN` recovery path.
- `packages/broker/src/job-state-invariants.test.ts` proves that a stale late
  success remains rejected while a stale late `UNKNOWN` transition converges
  the cancelled running Job without leaving it running.
- Focused build and cancellation/revocation regression: 88 passed, 6
  skipped, 0 failed.

## Limits

This is a local durable-state race regression. It does not prove physical
process termination, kernel-level cancellation, production task isolation, or
installed operator recovery. Those remain governed by VT-SBX-01/02,
VT-REV-01, and VT-OPS-01.
