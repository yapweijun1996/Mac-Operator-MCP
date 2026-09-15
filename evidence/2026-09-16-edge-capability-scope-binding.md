# Edge capability-scope binding evidence

- Source revision: `d4c9bbf`
- Working tree: clean at capture
- Contract version: `0.1`
- Policy version: `policy-0.1`
- Host profile: Darwin `25.2.0`, arm64; local development checkout
- Procedure: load the regular, schema-pinned tool contracts, receive an
  authenticated Broker capability envelope, validate each scope list as a
  bounded unique runtime scope set, and compare it exactly with the
  registered contract before MCP registration.
- Focused command: `node --test packages/edge/dist/contract-registry.test.js packages/edge/dist/mcp-server.test.js`
- Result: 18 tests passed, 0 failed.
- Negative coverage: missing/duplicate/unknown scopes, scope substitution,
  incompatible contract versions, incomplete lifecycle state, duplicate or
  unknown capability names, non-data envelopes, and missing authentication
  context fail closed.
- Scope: this closes the Edge advertisement consistency boundary only. The
  Broker remains final authority; signed policy/custom contract deployment,
  network/filesystem/secret/audit metadata parity, native descriptor
  execution, production enablement, and installed-host evidence remain
  separate gates.
