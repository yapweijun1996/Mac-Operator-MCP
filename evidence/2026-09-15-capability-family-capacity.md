# Durable Capability-Family Capacity Evidence

Date: 2026-09-15
Source commit: `db129b3`
Host: physical Darwin arm64 development host

## Implemented boundary

The Broker resolves capability families from the active policy and persists a
canonical family marker with every admitted request. BrokerStore enforces
configured per-family active-request caps inside the same SQLite `BEGIN
IMMEDIATE` transaction as nonce and request admission. Read, write, process,
network, GUI, destructive, and privileged families are independent. Empty
legacy markers conservatively count against every requested family, and
malformed stored markers return `AUDIT_UNAVAILABLE` before nonce persistence.

## Verification

- Focused Broker/persistence regression: 122 pass, 6 explicit skips, 0 fail.
- Full physical-Darwin regression: 596 pass, 0 skipped, 0 fail.
- `npm run typecheck`, `npm run lint`, `npm run verify:contracts`,
  `npm run verify:canonical:native`, and `git diff --check` pass.

## Remaining boundary

Adapter-specific semantic quotas, disk/depth/kernel resource limits, real
installed-service evidence, and final release acceptance remain open.

## Rollback

Revert `db129b3`. Requests would no longer carry durable independent family
admission markers or per-family capacity gates.
