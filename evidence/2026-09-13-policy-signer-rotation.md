# Policy signer rotation evidence

- Source commit: `e34be2baf53932d6ae1107e5b751b8f109c21145`
- Source worktree: clean at verification time; documentation changes were applied afterward in the documentation commit that references this record.
- Contract version: `0.1`
- Policy fixture version: `policy-0.1`
- Target host: Mac mini (Apple M4), macOS `26.2` (`25C56`), `arm64`
- Runtime: Node `v25.5.0`, npm `11.8.0`
- Timestamp: `2026-09-13` (Asia/Kuala_Lumpur)
- Verification: `npm test` — 203 passing, 0 failing; `npm run typecheck` — pass; `npm run verify:contracts` — 44 unique contracts; `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.

## Covered behavior

- Loads up to 32 owner-protected, regular, non-symlink Ed25519 public-key files through `O_NOFOLLOW` and device/inode readback.
- Accepts bounded key IDs and overlapping `notBeforeMs`/`expiresAtMs` windows with a bounded clock-skew allowance.
- Rejects unknown, malformed, expired, not-yet-valid, non-Ed25519, duplicate, or weakly protected signer entries.
- Applies a Broker-owned revocation callback before digest/signature verification; a revoked old signer fails while a replacement signer remains usable.
- Preserves the existing canonical payload digest, strict policy schema, future-issue-time check, and policy-version binding.

## Artifact hashes

- `packages/broker/src/policy-loader.ts`: `1f047faf3560bcf829350897d367143e4f9fb26bed3f455c73abb98802323437`
- `packages/broker/src/policy-loader.test.ts`: `952872305c28c4983bc542771ef0bac4380c0468aeb0eeeca68d2746403ca9c4`

This evidence proves the verifier primitive and protected file boundary only. Durable signer metadata/revocation persistence, operator rotation/reload and rollback workflow, Keychain distribution, crash injection, migration, cross-runtime canonicalization, and production enablement remain open.
