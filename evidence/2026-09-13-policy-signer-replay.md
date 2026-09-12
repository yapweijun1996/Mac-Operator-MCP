# Policy signer replay persistence evidence

- Source commit: `e8112ea87895411668411c383ae79534d4dfb2dc`
- Source worktree: dirty only for documentation follow-up at verification time; the tested source change is committed at the source revision above.
- Contract version: `0.1`
- Policy fixture version: `policy-0.1`
- Target host: Mac mini (Apple M4), macOS `26.2` (`25C56`), `arm64`
- Runtime: Node `v25.5.0`, npm `11.8.0`
- Timestamp: `2026-09-13` (Asia/Kuala_Lumpur)
- Verification: `npm test` — 209 passing, 0 failing; `npm run typecheck` — pass; `npm run verify:contracts` — 44 unique contracts; `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.

## Covered behavior

- A policy-signer operator command nonce is admitted into the BrokerStore before execution.
- Reopening the SQLite store preserves the nonce reservation and denies the same request/nonce identity as a replay.
- The test exercises the persistence boundary directly and does not claim installed service, Keychain storage, native caller identity, or production enablement.

## Artifact hashes

- `packages/broker/src/persistence.test.ts`: `9400afe583817d5bd0cf27bd75a0afe3e26902f37cdbec0e696ff7073f3fcffe`

This evidence closes only the local persistence regression for policy-signer command replay. The broader operator-channel limitations remain open as documented in `evidence/2026-09-13-policy-signer-operator-channel.md`.
