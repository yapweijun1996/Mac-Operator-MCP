# Edge contract registry boundary evidence

- Source revision: `fa0dc50`
- Boundary: Edge `ToolContractRegistry` top-level contract parser
- Change: contract records must be plain data and may contain only the
  versioned contract-schema field set. Unknown top-level fields fail closed
  before the contract is exposed to MCP tool construction.
- Focused verification: `contract registry loads bounded regular files and
  exposes the parsed contract` and `contract registry rejects unknown
  top-level fields` — 2/2 passed.
- Regression verification: the non-overlapping package suite reports 541
  tests, 535 passed, 6 skipped, 0 failed. The two pre-existing long-lived
  `broker.test.js` and `persistence.test.js` processes were excluded and left
  untouched.
- Scope: this covers contract representation/loading only. It does not prove
  all runtime handlers, remote deployment, signing provenance, or capability
  enablement.
