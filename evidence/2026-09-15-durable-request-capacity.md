# Durable Request-Capacity Evidence

Date: 2026-09-15
Source commit: `31e89f0`
Host: physical Darwin arm64 development host

## Implemented boundary

BrokerStore admission accepts optional bounded limits and checks active
requests inside its existing `BEGIN IMMEDIATE` transaction. Active states are
`RECEIVED`, `AUTHORIZED`, `INTENT_RECORDED`, and `RUNNING`. The Broker
supplies a default global cap of 64 and a principal/session cap of 8, bounded
by hard maxima 256 and 64. Saturation returns retryable `CONFLICT` before
nonce or request persistence. Terminal request transitions and startup
reconciliation remove rows from the active set.

## Verification

- Two BrokerStore handles sharing one SQLite database prove per-session and
  global saturation, no durable records for rejected requests, and capacity
  release after terminal failure.
- Broker constructor tests reject invalid global limits.
- Full physical-Darwin regression with install, sandbox, and Keychain gates:
  589/589 pass, 0 skipped, 0 failed.
- `npm run typecheck`, `npm run lint`, and `git diff --check` pass.

## Remaining boundary

This closes the durable request-admission cap only. It does not establish
process/adapter-specific quotas, disk/depth budgets, kernel-level resource
limits, or final release acceptance.

## Rollback

Revert `31e89f0`. The Broker would retain only the in-process session map and
would no longer enforce shared BrokerStore admission caps.
