# Configuration Ledger Invariant Evidence

Date: 2026-09-15

Source revision: `7a34191`

Command:

```text
npm run build && node --test \
  packages/broker/dist/configuration-row-invariants.test.js \
  packages/broker/dist/policy-loader.test.js \
  packages/broker/dist/policy-signer-keyring.test.js
26 tests, 26 passed, 0 failed, 0 skipped
```

## Decision

Persisted Policy and key-configuration records are authority state. The active
singleton must reference a valid historical identity; rollback timestamps may
advance, but the active revision, digest, and Policy metadata must remain
bound to the matching history row.

## Implemented boundary

Broker startup now validates every Policy/configuration history row and every
active singleton after schema migration. It checks positive revisions,
bounded Policy/key identities, SHA-256 digest shape, nonnegative timestamps,
active/history identity matching, and active timestamps that do not predate
their historical record. Active identity getters repeat the same checks before
returning authority to policy/key managers; malformed state fails closed as
`AUDIT_UNAVAILABLE`.

The focused tests corrupt each active table through a separate SQLite
connection and verify startup rejection. Existing Policy and policy-signer
activation, restore, and rollback tests remain green. No external authority,
privileged action, or destructive operation was invoked.

The non-overlapping package regression after the configuration-ledger change
reports 579 tests total (573 passed, 6 explicitly skipped, 0 failed). The
existing `broker.test.js` and `persistence.test.js` processes were excluded
because they were already running; this is bounded local evidence, not a
fresh run of those two suites.

This closes only the active/history configuration representation boundary.
Production Keychain distribution, installed operator recovery, external
rollback detection, and ADR acceptance remain open.
