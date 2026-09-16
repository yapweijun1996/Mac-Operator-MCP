# Keychain delivery replay ledger

## Decision

The Edge-to-Broker Keychain delivery channel now uses a dedicated BrokerStore
replay ledger. Request IDs and nonces are admitted only after the fixed
Keychain key ID is checked, and the admission is transactional, bounded to the
shared replay capacity, and retained until its Broker-owned expiry window.

## Boundary

`KeychainDeliveryServer` requires an explicit `KeychainDeliveryReplayGuard`;
the production LaunchAgent startup path supplies
`BrokerStoreKeychainDeliveryReplayGuard`. The channel remains separately
authenticated by native peer UID/GID/PID-start identity, uses a fresh challenge,
and never accepts service/account coordinates from the Edge request.

The ledger is independent from MCP request replay so a restart cannot silently
forget a secret-delivery nonce. Expired rows are pruned at `expires_at_ms <=
admission_now`, and a full live ledger fails closed rather than evicting a
non-expired identity.

## Verification

- BrokerStore schema migration 12 creates and validates
  `keychain_delivery_nonces`.
- Replay-row and unknown-column corruption checks cover the new table.
- Focused persistence/replay/schema/keychain tests pass 72/72.
- Full `npm test --silent` regression passes 868/868 with 14 explicit skips.
- Typecheck and build pass.
- No real Keychain item was provisioned or read by this change, and no service
  or privileged helper was installed.

## Remaining risk

The protocol still uses the fixed 0.1 delivery envelope and a Broker-selected
five-minute replay retention window; production Keychain rotation, release
signing, and installed cross-process lifecycle evidence remain gated.
