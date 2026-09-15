# Durable request-admission limit boundary evidence

- Source revision: `999435d`
- Boundary: `BrokerStore.admitRequest` limit validation
- Change: admission-limit records and capability-family overrides must be plain
  data records before key enumeration or value reads. Inherited and accessor
  fields fail closed with `PRECONDITION_FAILED`; no request row is created.
- Focused verification: `BrokerStore rejects inherited or accessor admission
  limits before reading them` — 1/1 passed.
- Regression verification: the non-overlapping package suite reports 539
  tests, 533 passed, 6 skipped, 0 failed. The two pre-existing long-lived
  `broker.test.js` and `persistence.test.js` processes were excluded and left
  untouched.
- Scope: this covers the durable configuration-shape boundary only. It does
  not prove process-wide kernel quotas, disk exhaustion, or production
  service/packaging evidence.
