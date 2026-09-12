# Policy signer lifecycle evidence

- Source commit: `071d063308809b922dd2bb2611243fe8ce0b91f4`
- Source worktree: clean at verification time.
- Contract version: `0.1`
- Policy fixture version: `policy-0.1`
- Target host: Mac mini (Apple M4), macOS `26.2` (`25C56`), `arm64`
- Runtime: Node `v25.5.0`, npm `11.8.0`
- Timestamp: `2026-09-13` (Asia/Kuala_Lumpur)
- Verification: `npm test` — 206 passing, 0 failing; `npm run typecheck` — pass; `npm run verify:contracts` — 44 unique contracts; `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.

## Covered behavior

- Versioned owner-only signer metadata is written atomically with `0600` mode and protected parent-directory checks.
- Each signer entry binds an absolute public-key path, Ed25519 key type, validity window, and SHA-256 digest of the opened key file. A changed key file fails before restore or verification.
- BrokerStore persists signer configuration activation identities and history, restores only an exact revision/digest, rejects revision reuse, and records intent/completion audit events.
- A local `PolicySignerKeyManager` exposes explicit `activate`/`reload`, verified-history `rollback`, and durable audited revocation. The manager is not exposed through the remote MCP Edge.
- A revoked old signer remains loadable in an overlapping configuration but is rejected by the verifier's BrokerStore-backed revocation callback while the replacement signer remains valid.
- Legacy revocation tables migrate to the new `policy_signer` kind without losing existing rows.

## Artifact hashes

- `packages/broker/src/policy-signer-keyring.ts`: `7c0480c08f695531b51614999e06bf1340bd5e99a7752e69fd7dc70d6643ecfa`
- `packages/broker/src/policy-signer-keyring.test.ts`: `61a1d2eade83d869ee7a2ad71fd476640f7bc53eb6095a5a88429920a80a00aa`
- `packages/broker/src/persistence.ts`: `5321049e839a82d9669ba2ebb38812a613f11ceeaa21fa6eb9c8e3a3f2c6c84f`
- `packages/broker/src/persistence.test.ts`: `b0ae7b3c573917b5584abad5ac3219c892ae7e4657a0aad68dbc638dadfef7ea`

This evidence proves the protected local lifecycle primitive only. An authenticated operator caller/channel, installed startup wiring, Keychain or cross-process secret distribution, crash-window recovery between file replacement and database activation, general schema migration, cross-runtime canonicalization, and production enablement remain open.
