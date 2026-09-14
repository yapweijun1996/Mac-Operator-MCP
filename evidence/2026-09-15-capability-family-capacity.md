# Durable Capability-Family Capacity Evidence

Date: 2026-09-15
Source commits: `db129b3`, `0b7d3b9`, `d7c4689`
Host: physical Darwin arm64 development host

## Implemented boundary

The Broker resolves capability families from the active policy and persists a
canonical family marker with every admitted request. BrokerStore enforces
configured per-family active-request caps inside the same SQLite `BEGIN
IMMEDIATE` transaction as nonce and request admission. Read, write, process,
network, GUI, destructive, and privileged families are independent. Empty
legacy markers conservatively count against every requested family, and
malformed stored markers return `AUDIT_UNAVAILABLE` before nonce persistence,
including for a family-less request. RequestRecord and the versioned ledger
schema expose the resolved family list; legacy empty markers map to an empty
list without weakening admission counting.

## Verification

- Focused Broker/persistence regression: 123 pass, 6 explicit skips, 0 fail.
- Full physical-Darwin regression: 597 pass, 0 skipped, 0 fail.
- `npm run typecheck`, `npm run lint`, `npm run verify:contracts`,
  `npm run verify:canonical:native`, and `git diff --check` pass.

## Remaining boundary

Adapter-specific semantic quotas, disk/depth/kernel resource limits, real
installed-service evidence, and final release acceptance remain open.

## Rollback

Revert `db129b3`. Requests would no longer carry durable independent family
admission markers or per-family capacity gates.
