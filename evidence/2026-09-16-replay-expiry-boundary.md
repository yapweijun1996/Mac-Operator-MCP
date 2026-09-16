# Durable replay expiry boundary

- Date: 2026-09-16
- Scope: BrokerStore replay-ledger retention and capacity admission

## Implementation

All durable replay ledgers now delete rows with
`expires_at_ms <= admission_now` before checking their bounded capacity. This
matches the protocol validity rule that an admitted nonce must satisfy
`expires_at_ms > now`; an entry expiring exactly at the admission instant is no
longer reusable and must not consume capacity.

The change applies to request, approval issuance, policy-signer,
Authority-Control, privileged-helper, Broker-status, and virtualization-guest
ledgers. No replay identity is accepted twice while its expiry is still in the
future.

## Verification

- `node --test packages/broker/dist/replay-capacity.test.js packages/broker/dist/replay-row-invariants.test.js` passed 9/9.
- Latest full `npm test --silent` passed: 873 tests, 859 passed, 14 explicit
  skips, 0 failures.
- The request and privileged-helper capacity tests fill the 4,096-row bound,
  verify a live-row denial, then admit a new row exactly at the prior expiry.
- Existing corruption tests still reject malformed persisted rows as
  `AUDIT_UNAVAILABLE`.

## Rollback

Revert the persistence comparison and the focused capacity test. No external
service, credential, or host state was changed.
