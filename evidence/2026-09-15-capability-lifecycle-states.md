# Capability lifecycle-state wire evidence

Date: 2026-09-15
Source revision: `e22f025`

## Boundary

The Broker's `mac_capabilities` response now carries the three independent
runtime state fields for every planned tool: `planned`, `implemented`, and
`enabled`. The versioned output schema requires all three fields. The Edge
strictly parses them and rejects an enabled capability whose state claims it is
not planned or implemented, so an untrusted Broker response cannot expand the
advertised tool set through an inconsistent state.

## Verification

- Broker capability discovery and kill-switch tests — pass.
- Edge MCP server and HTTPS Edge tests — 8/8 pass.
- `npm run verify:contracts` — 44 contracts and the ledger schema validated.
- `npm run build` — pass.
- `npm run typecheck` — pass.
- `npm run lint` — pass.
- `git diff --check` — pass.

This closes the lifecycle-state representation and Edge admission check only.
It does not enable any previously disabled capability or provide production
host, VM, credential-isolation, privileged-helper, or remote deployment
evidence.

## Rollback

Revert source revision `e22f025`; no runtime data or host configuration is
changed.
