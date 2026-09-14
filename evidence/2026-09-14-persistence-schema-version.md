# Persistence Schema-Version Evidence

> Superseded by the current migration-registry behavior recorded below and in
> the latest `PROGRESS.md`/`VERIFICATION.md` addenda. The original 35-test
> count is retained as historical evidence for the pre-registry revision.

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: Broker SQLite compatibility gate; no authority or host capability was enabled

## Commands

```text
npm run build
node --test packages/broker/dist/persistence.test.js
```

## Observed result

- Focused persistence suite: 35 tests, 35 passed, 0 failed, 0 skipped.
- A fresh Broker database reads back SQLite `user_version = 4`.
- A legacy revocation database preserves its rows and is upgraded to
  `user_version = 4`.
- A database marked `user_version = 5` is rejected before Broker startup work.

## Boundary

`BrokerStore` performs the known idempotent revocation, request, and Job
migrations inside one `BEGIN IMMEDIATE` transaction and advances the marker
only after those steps succeed. A runtime with an older schema implementation
does not open a database marked with a newer version, preventing unknown schema
state from reaching authority, replay, or recovery decisions.

## Limitations

The current implementation additionally records four stable migration
identities in `schema_migrations`, rejects registry gaps or identity changes,
and defines rollback as restore-from-authenticated-encrypted-backup into a fresh
destination; automatic down-migrations are not exposed. No privileged action
or capability enablement was performed.
