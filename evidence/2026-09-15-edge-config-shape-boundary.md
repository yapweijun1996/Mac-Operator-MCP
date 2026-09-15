# Edge configuration shape boundary evidence

- Source revision: `04fcffc`
- Boundary: Edge startup configuration and HTTPS hostname/origin allowlists
- Change: startup documents must be plain data records; Host/Origin lists must
  be dense data-only arrays bounded to 64 entries. Inherited fields, accessors,
  symbols, hidden properties, and sparse list entries fail closed before path,
  URL, or listener setup.
- Focused verification: `Edge service startup config rejects inherited,
  accessor, and sparse authority data` and `HTTPS Edge normalizes case and
  rejects host-list syntax smuggling` — 2/2 passed.
- Regression verification: the non-overlapping package suite reports 540
  tests, 534 passed, 6 skipped, 0 failed. The two pre-existing long-lived
  `broker.test.js` and `persistence.test.js` processes were excluded and left
  untouched.
- Scope: this is Edge configuration representation evidence. It does not
  prove TLS/key lifecycle, remote deployment, launchd installation, or
  capability enablement.
