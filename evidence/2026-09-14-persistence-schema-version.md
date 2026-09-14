# Persistence Schema-Version Evidence

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

This proves the current version gate and migration set only. It does not prove
encrypted or Keychain-protected backups, a general migration registry,
cross-version downgrade/rollback, corruption repair, or production service
deployment. No privileged action or capability enablement was performed.
