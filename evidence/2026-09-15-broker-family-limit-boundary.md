# Broker capability-family limit boundary evidence

- Source revision: `0a97e3f`
- Boundary: `Broker` constructor configuration
- Change: `maxActiveRequestsByFamily` must be a plain data record before it is
  merged with Broker-owned defaults. Inherited keys, symbol/hidden properties,
  and accessor properties fail closed before any limit value is read.
- Focused verification: `Broker rejects unsafe request and session limits at
  construction` and `Broker rejects inherited or accessor capability-family
  limits before merge` — 2/2 passed.
- Regression verification: the non-overlapping package suite reports 539
  tests, 533 passed, 6 skipped, 0 failed. The two pre-existing long-lived
  `broker.test.js` and `persistence.test.js` processes were excluded and left
  untouched.
- Scope: this is local configuration-shape evidence. It does not prove
  process-wide quotas, adapter/kernel limits, disk exhaustion, production
  packaging, or capability enablement.
