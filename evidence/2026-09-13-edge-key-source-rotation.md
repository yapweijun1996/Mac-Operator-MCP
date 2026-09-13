# Edge authentication-key source and rotation evidence

Status: PARTIAL protected Edge-key distribution boundary for MOP-081 / VT-AUTH-01

## Boundary exercised

Commit `e9dd75e` adds an owner-only, versioned Edge authentication-key
metadata loader and atomic writer. Every entry must explicitly select
`keySource: "file"` or `keySource: "keychain"`; a Keychain entry must contain
only a bounded `com.mac-operator.*` service and account, while a file entry
must contain only a canonical absolute path. Mixed source metadata, unknown
fields, duplicate `(edge_id, key_id)` identities, invalid validity windows,
traversal-like paths, and non-canonical config paths are rejected.

The config reader requires an owner-only regular non-symlink file and rechecks
device/inode identity after opening. File-backed key bytes use the existing
owner-only, `O_NOFOLLOW`, bounded authentication-key loader. Keychain-backed
bytes use the native non-interactive Security.framework reader and remain in
process memory only. A BrokerStore is mandatory at load time, so a durable
`edge_key` revocation rejects the entry before the EdgeKeyring is constructed.

Rotation is represented by a new versioned config containing overlapping key
validity windows. The resulting `EdgeKeyring` retains independent identities;
the Broker still applies signed-policy validity and key-specific revocation on
every request, so retiring the old key is a separate revoke-before-retire
operation.

## Host evidence

- Host: Darwin arm64, macOS `26.2` build `25C56`.
- Runtime: Node `v25.5.0`, npm `11.8.0`.
- Focused source tests: 3 Edge key-config tests pass.
- Full regression: 312 passed, 0 failed, 2 opt-in real-sandbox tests skipped
  (314 total).
- The Keychain test queried a random missing account only; no Keychain item was
  created, modified, or deleted.
- Native production and fault-test addons compile; `npm run typecheck`,
  `npm run verify:contracts` (44 unique contracts), and `git diff --check`
  pass. No live launchd service was installed or changed.

## Source identity

- `packages/broker/src/edge-keyring-config.ts` SHA-256:
  `a17a7778a25f78c64f95ebbc2327f87e8ec062065e22b27db544bf6018ac1a04`
- `packages/broker/src/edge-keyring-config.test.ts` SHA-256:
  `bebd09624c3accb4b2cc87ccbb35a6a107da3672bc45be24b059ac296be3c839`
- `packages/broker/src/index.ts` SHA-256:
  `7f3581bdb41d8fac8509c4f8e1ab5d17130a9e5282f3e3f590e888496fc3cbd0`
- Existing native Keychain reader source remains covered by
  `evidence/2026-09-13-keychain-key-read.md`.

## Limits and next gate

This proves explicit source selection, protected metadata loading, durable
revocation preflight, and overlapping in-memory rotation. It does not prove
Keychain provisioning, ACL/access-control review, secret rotation or deletion
on a real item, cross-process delivery, signed package provenance, installed
Edge/launchd startup, remote issuer integration, or production capability
enablement. A future gate should add a persisted Edge-config activation and
restart/readback identity if operators need hot reload; until then startup
must load one exact config revision before constructing the Broker.
