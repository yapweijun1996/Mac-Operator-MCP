# Direct policy authorization input boundary evidence

- Source revision: `88d9179`
- Boundary: exported Broker policy authorization functions
- Change: principal projections and target authorization now validate bounded,
  dense known-scope arrays, plain target records, canonical target kinds, and
  policy-root identities before any matching or grant lookup. Accessor,
  inherited, symbolic, and sparse authority inputs fail closed.
- Focused verification: `policy authorization rejects non-data projected
  scopes and targets` and the deterministic `policy mutation corpus never
  expands projected scopes or deny-overrides-allow` — 2/2 passed.
- Regression verification: the non-overlapping package suite reports 544
  tests, 538 passed, 6 skipped, 0 failed. The two pre-existing long-lived
  `broker.test.js` and `persistence.test.js` processes were excluded and left
  untouched.
- Scope: this is direct policy-input representation evidence. It does not
  close production signer/Keychain distribution, installed reload, or
  capability enablement.
