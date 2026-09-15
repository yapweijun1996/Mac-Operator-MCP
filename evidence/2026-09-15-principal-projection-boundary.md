# Edge principal projection boundary evidence

- Source revision: `ce198e1`
- Boundary: verified OAuth identity projection into Broker principal context
- Change: identity metadata must be a plain data record and scopes must be a
  dense data-only array bounded by the governed scope taxonomy. Inherited,
  accessor, symbolic, and sparse structures fail closed before scope filtering
  or request creation; bearer tokens remain excluded from the projected
  principal.
- Focused verification: the three `verified token projection` tests — 3/3
  passed.
- Regression verification: the non-overlapping package suite reports 543
  tests, 537 passed, 6 skipped, 0 failed. The two pre-existing long-lived
  `broker.test.js` and `persistence.test.js` processes were excluded and left
  untouched.
- Scope: this covers Edge identity projection only. It does not prove OAuth
  provider correctness, key rotation, remote deployment, or capability
  enablement.
