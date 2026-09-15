# Replay Ledger Capacity Evidence

- Date: 2026-09-16
- Host: local development macOS host
- Source revision: `e1d6ff2`
- Contract/protocol versions: 0.1
- Evidence class: local persistence denial-of-service boundary

## Decision

Replay identities are authority state. Every replay ledger must remain bounded
even when the caller keeps changing nonce values. Expired rows may be reclaimed
inside the same admission transaction; an at-capacity ledger must fail closed
before inserting a new identity.

## Implemented controls

The request, authenticated-approval, policy-signer, Authority Control,
privileged-helper, Broker-status, and virtualization-guest replay ledgers now
share a 4,096-row admission limit. Startup integrity checks reject any ledger
already at or above the configured boundary, and each admission deletes only
expired rows before checking capacity. The capacity check runs in the same
transaction as the insert, so an `AUDIT_UNAVAILABLE` result leaves no partial
nonce or request row.

## Verification

Focused command:

```text
npx tsc -b --pretty false
node --test packages/broker/dist/replay-capacity.test.js
npm run lint
git diff --check
```

Result: the focused test passed 1/1. It fills the request ledger to 4,096
entries, proves the next admission is denied with `AUDIT_UNAVAILABLE`, proves
no request row was created for the rejected admission, and proves an expired
batch is reclaimed before a later admission. Typecheck, style, and diff checks
also passed.

This is local persistence evidence. It does not prove remote replay retention,
database disk exhaustion behavior, cross-runtime compatibility, or installed
service recovery.

## Boundary status

This closes unbounded replay-ledger growth in the Broker persistence layer. It
does not replace signature verification, timestamp windows, durable unique
constraints, startup corruption checks, or remote issuer evidence.
