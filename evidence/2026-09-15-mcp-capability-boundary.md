# MCP capability readback boundary evidence

- Source revisions: `0b8c7e2`, `3f65dc8`
- Boundary: Edge MCP capability discovery
- Change: capability response data and items must be plain data; capability
  arrays are dense and bounded to 128 entries; only the governed capability
  fields are accepted, including optional `scopes` and `reason` metadata used
  by Broker readback. Unknown fields and accessor/sparse structures fail
  closed before tool registration.
- Focused verification: `MCP factory rejects duplicate or unknown capability
  entries` and `MCP factory rejects non-data capability envelopes` — 2/2
  passed.
- Regression verification: the non-overlapping package suite reports 542
  tests, 536 passed, 6 skipped, 0 failed. The two pre-existing long-lived
  `broker.test.js` and `persistence.test.js` processes were excluded and left
  untouched.
- Scope: this covers Edge capability readback and registration only. It does
  not prove Broker handler completeness, remote deployment, or capability
  enablement.
