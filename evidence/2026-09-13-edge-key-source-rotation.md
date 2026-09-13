# Edge authentication-key source and rotation evidence

Status: PARTIAL protected Edge-key distribution boundary for MOP-081 / VT-AUTH-01

## Boundary exercised

Commits `e9dd75e`, `7d91c8f`, and `49843cc` add an owner-only, versioned Edge
authentication-key metadata loader, atomic writer, and BrokerStore-backed
activation manager. Every entry must explicitly select
`keySource: "file"` or `keySource: "keychain"`; a Keychain entry must contain
only a bounded `com.mac-operator.*` service and account, while a file entry
must contain only a canonical absolute path. Mixed source metadata, unknown
fields, duplicate `(edge_id, key_id)` identities, invalid validity windows,
traversal-like paths, and non-canonical config paths are rejected.

Each entry also carries an expected lowercase SHA-256 digest of the secret
bytes. The loader verifies that digest after reading the protected file or
Keychain item, so replacing bytes under an otherwise unchanged path or account
fails closed.

The Edge package now has a matching protected-file loader and
`EdgeRequestFactory.fromProtectedKeyFile`. It checks the Edge user's
owner-only directory/file boundary, canonical path, `O_NOFOLLOW` identity,
bounded raw or hex key encoding, and expected digest before the request factory
receives the bytes. The ordinary constructor remains available for injected
test fixtures; production startup should use the protected-file factory. The
Edge package does not silently fall back to Keychain or environment-variable
lookup.

The config reader requires an owner-only regular non-symlink file and rechecks
device/inode identity after opening. File-backed key bytes use the existing
owner-only, `O_NOFOLLOW`, bounded authentication-key loader. Keychain-backed
bytes use the native non-interactive Security.framework reader and remain in
process memory only. A BrokerStore is mandatory at load time, so a durable
`edge_key` revocation rejects the entry before the EdgeKeyring is constructed.

Rotation is represented by a new versioned config containing overlapping key
validity windows. `EdgeAuthenticationKeyManager` records an audited monotonic
revision and payload digest in BrokerStore, rejects revision reuse/rollback,
and restores only an exact matching config after restart. The resulting
`EdgeKeyring` retains independent identities; the Broker still applies
signed-policy validity and key-specific revocation on every request, so
retiring the old key is a separate revoke-before-retire operation.

## Host evidence

- Host: Darwin arm64, macOS `26.2` build `25C56`.
- Runtime: Node `v25.5.0`, npm `11.8.0`.
- Focused source tests: 8 Edge/Broker key-source tests pass.
- Full regression: 317 passed, 0 failed, 2 opt-in real-sandbox tests skipped
  (319 total).
- The Keychain test queried a random missing account only; no Keychain item was
  created, modified, or deleted.
- Native production and fault-test addons compile; `npm run typecheck`,
  `npm run verify:contracts` (44 unique contracts), and `git diff --check`
  pass. No live launchd service was installed or changed.

## Source identity

- `packages/broker/src/edge-keyring-config.ts` SHA-256:
  `1b6bf0762b5b5d41830f87f57f3969ce3ad79a3efa9b47f10d6dad87379717c1`
- `packages/broker/src/edge-keyring-config.test.ts` SHA-256:
  `0e643d9df5937b6b7da28516e57e4056d52a0ce3f222b0b7b6ec78782e75a38d`
- `packages/broker/src/persistence.ts` SHA-256:
  `8782b9ce8f9d962516c4422eba146e06f2e53fc5b6028da1f6f188e861e36372`
- `packages/edge/src/authentication-key.ts` SHA-256:
  `36ad6e0b10949cbaebabf46663bafa0d87b08ae9c6fc1f91177469c3d60f3ddc`
- `packages/edge/src/authentication-key.test.ts` SHA-256:
  `14683576120a802054f9a13beb2001767765ff34a3bfb2d78bc9ac678a06a98a`
- `packages/edge/src/request-factory.ts` SHA-256:
  `c31add8be0f68cbb72cd9a8bcce5476c3a8afcf7a31eb0f01a25896e5f141295`
- `packages/broker/src/index.ts` SHA-256:
  `7f3581bdb41d8fac8509c4f8e1ab5d17130a9e5282f3e3f590e888496fc3cbd0`
- Existing native Keychain reader source remains covered by
  `evidence/2026-09-13-keychain-key-read.md`.

## Limits and next gate

This proves explicit source selection, protected metadata loading, secret-byte
digest binding on both Broker and Edge file boundaries, durable revocation
preflight, monotonic activation, exact restart restore, and overlapping
rotation. It does not prove Keychain provisioning, ACL/access-control review,
secret rotation or deletion on a real item, a shared Edge-side Keychain
reader, signed package provenance, installed Edge/launchd startup, remote
issuer integration, or production capability enablement. If Broker startup
selects a Keychain-backed Edge key, Edge-side distribution still needs an
approved cross-process mechanism; the Edge loader intentionally fails closed
instead of falling back to environment variables or raw MCP arguments. The
manager intentionally has no hot-reload or rollback bypass; operators must
activate a strictly newer revision and use the existing revocation path to
retire an old key.
