# Non-interactive Keychain key-read evidence

Status: PARTIAL protected key-distribution primitive for MOP-081 / VT-AUTH-01

## Boundary exercised

Commit `ef5e336` adds a macOS Security.framework native adapter operation for
reading exactly one generic-password item. The service must match the fixed
`com.mac-operator.<label>` namespace and the account must be a bounded
non-path identifier. The query requires one match, returns exactly 32 raw
bytes, and sets the legacy macOS authentication-UI policy to fail rather than
presenting a credential prompt to a background Broker. The returned bytes are
copied only into process memory; they are not logged or written back.

The TypeScript boundary is explicit (`loadKeychainAuthenticationKey`) and is
not selected by filesystem paths or MCP arguments. Missing items, malformed
service/account values, duplicate matches, and invalid lengths fail closed.
Commit `44c16ad` wires this source into Approval issuer configuration only when
an entry explicitly sets `keySource: "keychain"`, `service`, and `account`;
file-backed entries remain compatible, and mixed path/Keychain metadata is
rejected. Commit `e9dd75e` applies the same explicit-source boundary to Edge
authentication-key metadata and records separate overlapping-key rotation
evidence in `evidence/2026-09-13-edge-key-source-rotation.md`.

## Host evidence

- Host: Darwin arm64, macOS `26.2` build `25C56`.
- Runtime: Node `v25.5.0`, npm `11.8.0`.
- Source commits: `ef5e336` (`security: add non-interactive Keychain key reads`)
  and `44c16ad` (`security: bind approval keys to explicit Keychain sources`).
- Focused credentials/native tests: 12 passed, 0 failed.
- Full regression: 308 passed, 0 failed, 2 opt-in real-sandbox tests skipped
  (310 total).
- The missing-item test performed a read-only query against a random account;
  no Keychain item was created, modified, or deleted.
- Native production and fault-test addons both compile and the protected loader
  now requires 18 exports. Typecheck, contract verification (44 unique
  contracts), high-severity npm audit, and `git diff --check` passed.

## Source identity

- `packages/broker/native/peer_credentials.cc` SHA-256:
  `19119705f4910a8fe8c0fe3049b5c3a65209d0f2bb72d6ed9fb15100418babe1`
- `packages/broker/src/peer-credentials.ts` SHA-256:
  `01f34a6ac74f6c6cbc9576efe07e74a44b13834dc182f4d4e722e931b5f7e198`
- `packages/broker/src/credentials.ts` SHA-256:
  `6158baf77923092454946a2512d86edf7dd13772312ccaec44dd00083c75e5f8`
- `packages/broker/src/credentials.test.ts` SHA-256:
  `4a5bbd9464b8a419460e31621d06bfc4e985e47bc3dcec0e25862f090b65d420`
- `packages/broker/src/approval-keyring.ts` SHA-256:
  `a008c7036799b632f1c778557187448d7992b86710df7720da3e471d3f335759`
- `packages/broker/src/approval-keyring.test.ts` SHA-256:
  `288285fbb71bc757f59ea6f54ab93ca9419941d7c25ab6953d01df2d67e560e0`
- `packages/broker/scripts/build-peer-credentials.sh` SHA-256:
  `1507c1c687ae1339c055bf402e4af88cf1c293db624afd90e35a9de7aee3ac03`
- `packages/broker/scripts/build-peer-credentials-fault-test.sh` SHA-256:
  `4c931884c795b116eb912658ef8600add404c74e0e621b79d15cf4f201207921`

## Limits and next gate

This proves a non-interactive Keychain read boundary and explicit Approval and
Edge-key source selection, not protected Keychain provisioning, access-control
policy, real-item rotation, deletion, or cross-process distribution. A real
secret item was intentionally not created during evidence capture. Developer ID
signing/notarization, Keychain ACL review, live installed startup, remote
issuer integration, and production capability enablement remain open.
