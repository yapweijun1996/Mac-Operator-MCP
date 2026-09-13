# Capability discovery version-binding evidence

Status: PARTIAL implementation evidence for MOP-081 and VT-COMP-01

Source commit: `8061254` (`security: bind capability discovery versions`)
Working tree: clean before verification commands
Host: local macOS development host; no installed service or remote deployment
Scope: Broker capability readback and MCP Edge registration only

## Boundary implemented

`mac_capabilities` now returns the protocol version and contract version at the
top level, plus a contract version for every capability entry. The version
fields are covered by the versioned `mac_capabilities` output schema; disabled
entries may report a null per-tool contract version, while enabled entries must
carry the Broker policy's contract version.

The MCP Edge validates the top-level protocol and contract versions against the
shared constants before exposing any tools. It then requires every enabled
capability to have a matching local contract-registry entry and exact schema
version. Missing, malformed, stale, or mismatched version data fails closed
before an MCP tool is registered. The Broker remains the authority for which
capabilities are enabled; the Edge only checks compatibility and never grants
additional scope or target authority.

## Verification

- `npm test`: 327 tests, 325 passed, 0 failed, 2 opt-in real-sandbox tests skipped.
- Focused Broker conformance plus Edge MCP/HTTPS tests: 8 passed, 0 failed.
- `npm run typecheck -- --pretty false`: PASS.
- `npm run verify:contracts`: PASS, 44 unique contracts.
- `npm audit --omit=dev --audit-level=high`: PASS, 0 vulnerabilities.
- `git diff --check`: PASS.
- Negative coverage rejects an enabled capability with contract version `9.9`.
- Contract conformance validates the new capability output fields with
  `additionalProperties: false`.

No remote issuer, installed launchd service, privileged helper, or production
capability was enabled or contacted. This evidence closes only the local
Broker-to-Edge capability readback binding. The installed/remote/helper
compatibility matrix, cross-runtime canonicalization, upgrade/rollback
readback, and real deployment evidence remain open; VT-COMP-01 therefore stays
`OPEN`.
