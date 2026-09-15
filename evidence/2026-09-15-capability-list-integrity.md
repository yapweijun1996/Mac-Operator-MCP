# Capability-list integrity evidence

Date: 2026-09-15
Source revision: `399a17c`

## Boundary

The HTTPS Edge now rejects duplicate capability names, unregistered tool
names, malformed tool-name syntax, and overlong contract-version values while
parsing the Broker's capability response. This prevents an ambiguous or
package-incompatible capability list from driving MCP tool registration.

## Verification

- Edge MCP server tests — 6/6 pass.
- Non-overlapping package regression (excluding the two pre-existing long-running broker test processes) — 494 total, 488 pass, 6 skipped, 0 fail.
- `npm run verify:contracts` — 44 contracts and the ledger schema validated.
- `npm run build` — pass.
- `npm run lint` — pass.
- `git diff --check` — pass.

This closes capability-list parsing integrity only. It does not enable any
capability or provide production host, VM, credential-isolation, privileged
helper, or remote deployment evidence.

## Rollback

Revert source revision `399a17c`; no runtime data or host configuration is
changed.
