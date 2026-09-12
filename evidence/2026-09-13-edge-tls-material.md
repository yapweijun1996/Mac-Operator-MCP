# Edge TLS material evidence

- Source commit: `87f3a726decaf42fdd6c0491fc36fcfde5abfc7d`
- Source worktree: dirty only for documentation follow-up at verification time; the tested source change is committed at the source revision above.
- Contract version: `0.1`
- Policy fixture version: `policy-0.1`
- Target host: Mac mini (Apple M4), macOS `26.2` (`25C56`), `arm64`
- Runtime: Node `v25.5.0`, npm `11.8.0`
- Timestamp: `2026-09-13` (Asia/Kuala_Lumpur)
- Verification: `npm test` — 217 passing, 0 failing; `npm run typecheck` — pass; `npm run verify:contracts` — 44 unique contracts; `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.

## Covered behavior

- TLS certificate and private-key paths must be canonical absolute paths in an owner-controlled directory.
- Both files must be owner-only regular non-symlink files and stay within a 256 KiB bound.
- The loader opens with `O_NOFOLLOW`, compares device/inode/size before reading, and rechecks device/inode/size after the descriptor read.
- Weak permissions, symlink targets, non-canonical paths, and oversized files fail closed before HTTPS startup receives material.

## Artifact hashes

- `packages/edge/src/tls-material.ts`: `847d5a6a09e642a40decc4b918cb6b99b4bbb33f597b7686f1c1df2c9cd40848`
- `packages/edge/src/tls-material.test.ts`: `4a2751e45c473015027e23002d438d250809eac369d2be34a8c53821078a2f34`

This evidence proves only the local file-protection boundary. It does not prove certificate rotation, Keychain/cross-process storage, remote OAuth deployment, native caller identity, or installed Edge startup.
