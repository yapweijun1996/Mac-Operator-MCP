# Privileged Helper Durable Replay Ledger

Date: 2026-09-23

Status: PASS for the source-level replay-storage implementation and separate
process restart regression; root LaunchDaemon integration and host acceptance
remain open.

## Implemented boundary

- `createPrivilegedHelperRuntimeFromKeyMaterial` no longer accepts a caller-
  supplied object that merely claims `durability: "durable"`. It creates a
  dedicated `PrivilegedHelperReplayLedger` from the configured helper root.
- The package plan exposes the canonical location
  `<helperRoot>/state/replay-ledger.sqlite`; runtime and plan share the same
  path derivation.
- The helper state directory must be a canonical, owner-controlled directory
  with mode `0700`. The SQLite file must be a regular, single-link file owned
  by the effective helper identity with mode `0600`; symlinks and unsafe
  replacements fail closed.
- SQLite uses `journal_mode=DELETE`, `synchronous=FULL`, a bounded transaction,
  expiry cleanup, unique nonce and request-ID constraints, a 4,096-row cap,
  and startup/in-process integrity and schema checks. Storage errors deny
  command admission rather than allowing dispatch.
- Enabled helper IPC accepts only the concrete BrokerStore-backed or dedicated
  SQLite durable guard implementations. Process-local and marker-only guards
  are rejected.

## Verification

- The restart regression starts a child Node process to persist an admission,
  then starts new child processes and confirms both the same request ID and
  the same nonce produce `REPLAY_DENIED`.
- The tests verify the database owner/mode and reject a state directory whose
  permissions have been widened.
- Focused helper/runtime/package/ledger regression: 52/52 passed.
- Full `npm test`: 1,200 total, 1,185 passed, 15 skipped, 0 failed.
- `npm run typecheck`, `npm run lint`, `npm run verify:docs`, and
  `npm run verify:matrix` passed.
- `npm run verify:completion` remains fail-closed and `partial` at 92%; host
  readiness is blocked and the repository matrix remains 2 PASS, 23 OPEN,
  and 4 BLOCKED.
- No helper was installed or enabled. No LaunchDaemon, Keychain, credentials,
  policy, or host permissions were changed.

## Remaining release gates

The package plan now names the ledger path, but the production native helper
entrypoint is not yet wired to call the key-material runtime with that helper
root. Root-domain startup/readback, Developer ID provenance, actual installed
ownership, rollback acceptance, and external independent security review
remain required. VT-PRIV-01 therefore remains `BLOCKED`; this source-level
replay test is not production deployment evidence.
