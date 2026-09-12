# Native operator IPC peer-boundary evidence

- Source commit: `66833441f5f06e17fa7c471ea0b50f1767c48efa`
- Source worktree: clean at source verification; documentation follow-up is the only subsequent change.
- Contract version: `0.1`
- Policy fixture version: `policy-0.1`
- Target host: Mac mini (Apple M4), macOS `26.2` (`25C56`), `arm64`
- Runtime: Node `v25.5.0`, npm `11.8.0`
- Timestamp: `2026-09-13` (Asia/Kuala_Lumpur)
- Verification: `npm test` — 221 passing, 0 failing; `npm run typecheck` — pass; `npm run verify:contracts` — 44 unique contracts; `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.

## Covered behavior

- `MacOsNativePeerIpcServer` is shared by Broker, policy-signer, and approval channels.
- Native listener creation, accept, UID/GID/PID lookup, peer authorization, public `Socket({ fd })` handoff, owner-only mode, bounded path/backlog, and fail-closed cleanup are implemented once at the transport boundary.
- `PolicySignerIpcServer` and `ApprovalIpcServer` select the native transport when `peerPolicy` is supplied; their existing HMAC/signed-command and approval parsing logic remains unchanged after peer authorization.
- Real-Mac tests exercise native policy-signer and approval round trips, and native denied-peer cases prove the connection is dropped before JSON parsing or audit persistence.
- The legacy `peerCredentialVerifier` option remains available only for compatibility and test fixtures; it still relies on the private Node socket descriptor path.

## Artifact hashes

- `packages/broker/src/native-peer-ipc-server.ts`: `20080be4e89c247f109e7e9c36782ebba308e7d41b9cc24347ea674f122e2111`
- `packages/broker/src/native-ipc-server.ts`: `f31992cc9e89c6ed55ed458a3d9f9d1acba2cd36d2c3b327af6254e1192e2118`
- `packages/broker/src/policy-signer-ipc.ts`: `b9b85244346037354756c491dc98354fad9518a8fd0dd2cc4bdbe1ed0fea3ecd`
- `packages/broker/src/policy-signer-ipc.test.ts`: `c95147206a3a9797102b4699010d3bc4fb6cfe9a4f28a2e4f0a11c8279fa9082`
- `packages/broker/src/approval-ipc-server.ts`: `1b2413a1918a1a84066d7a35ae96394a0dde10005992aadc8cc669ad4f5646cd`
- `packages/broker/src/approval-authority.test.ts`: `8d9a0ebe7c478b017ab6cb60ec9f5e44635343a2d6486b36526107296dbabd81`

This evidence closes the native peer-accept boundary for the three local IPC channel families only. It does not prove launchd installation, code signing, Edge PID lifecycle configuration, Keychain/cross-process secret distribution, or production capability enablement.
