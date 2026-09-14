# Persistence Migration Registry Evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: Broker SQLite migration ordering and rollback policy; no capability enablement

## Commands

```text
npm run typecheck
npm run build
node --test packages/broker/dist/persistence.test.js
```

## Observed result

- Focused persistence suite: 39 tests, 39 passed, 0 failed, 0 skipped.
- A fresh database records migration versions 1 through 4 with stable names in
  `schema_migrations` and reads back `PRAGMA user_version = 4`.
- Legacy databases are upgraded inside one `BEGIN IMMEDIATE` transaction and
  preserve existing revocation, request, and Job data.
- Future schema markers and registry gaps or identity changes are rejected
  before Broker authority or restart-recovery work.
- A forced migration DDL conflict rolls back the schema transaction: the
  legacy table, `user_version`, and registry remain unchanged.

## Boundary

Migration bodies are idempotent and are shape-checked on every open. The
registry and `user_version` marker advance only after all known steps and
records commit. The policy is forward-only: no automatic down-migration or
destructive in-place rollback exists. Recovery requires stopping the Broker and
restoring an authenticated `.sqlite.enc` backup into a fresh destination,
followed by a separately reviewed operator cutover.

## Limitations

This is host-only persistence evidence. It does not prove physical disk-full
behavior, external audit anchoring, Keychain ACLs, or production service
cutover/install evidence.
