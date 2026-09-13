# Edge-side Keychain delivery boundary evidence

Status: PARTIAL implementation evidence for MOP-081

## Boundary implemented

The Broker now exposes an opt-in `KeychainDeliveryServer` on a separate native
Unix socket. The channel requires an explicit UID/GID/PID-start-time peer
policy, loads one fixed Broker-owned Keychain service/account before listening,
checks the configured key digest, and never accepts service, account, or scope
values from the Edge request. The native peer accept boundary runs before the
bounded JSON handler sees a socket.

Each connection receives a fresh random challenge. The Edge must echo that
challenge in a strict versioned request containing only `requestId`, `nonce`,
and the configured `keyId`; the server rejects challenge mismatches, duplicate
request IDs/nonces, malformed fields, unexpected fields, oversized input, and
session-budget exhaustion. The response echoes the request identity and
challenge, carries only a base64-encoded 32-byte key plus its expected digest,
and is checked by the Edge before the bytes are handed to
`EdgeRequestFactory.fromKeychainDelivery`. The client revalidates the
owner-only socket parent and device/inode identity both before connect and
before sending the request.

Launchd startup assembly can attach this channel only when the active,
BrokerStore-approved config selects a Keychain entry and an explicit separate
delivery socket and key ID. File-only configurations retain the existing
startup path. A Keychain-backed config without a delivery channel, a missing
selected key, or a socket collision fails before launchd readback/listening.

## Verification

- `npm test`: 326 tests, 324 passed, 0 failed, 2 opt-in real-sandbox tests skipped.
- `npm run typecheck -- --pretty false`: PASS.
- `npm run verify:contracts`: PASS, 44 unique MCP tool contracts.
- `npm audit --omit=dev --audit-level=high`: PASS, 0 vulnerabilities.
- Native production and fault-test addons compile.
- `git diff --check`: PASS.
- Contract tests cover strict request/response fields, challenge-bound message
  shape, canonical 32-byte base64 output, malformed/error rejection, client
  startup binding validation, and key-ID binding.

No live Keychain item was created, modified, rotated, or deleted. No LaunchAgent
was installed or bootstrapped, and the delivery channel remains disabled unless
startup configuration explicitly adds it. This evidence does not prove live
Keychain ACL review, installed cross-process code identity, real Edge/Broker
delivery, rotation/deletion, or production capability enablement.
