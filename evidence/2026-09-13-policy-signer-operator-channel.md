# Policy signer operator channel evidence

- Source commit: `372a61bbfaeb3da546c73a68aed1a0178346cf20`
- Source worktree: clean at verification time.
- Contract version: `0.1`
- Policy fixture version: `policy-0.1`
- Target host: Mac mini (Apple M4), macOS `26.2` (`25C56`), `arm64`
- Runtime: Node `v25.5.0`, npm `11.8.0`
- Timestamp: `2026-09-13` (Asia/Kuala_Lumpur)
- Verification: `npm test` — 208 passing, 0 failing; `npm run typecheck` — pass; `npm run verify:contracts` — 44 unique contracts; `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.

## Covered behavior

- Signer reload, verified-history rollback, and key revocation use a separate owner-only Unix-domain socket; no MCP Edge route or model-facing tool is registered.
- Commands require a distinct HMAC key, strict operation-specific fields, bounded timestamps, nonce expiry, and constant-time proof comparison.
- The BrokerStore reserves command nonce/request identity before execution and rejects replay after the same process and store reopen.
- The server verifies the OS peer before parsing and drops denied peers without auditing or mutating policy state.
- Successful reload, rollback, and revoke operations use the existing BrokerStore activation/revocation audit chain.

## Artifact hashes

- `packages/broker/src/policy-signer-ipc.ts`: `106a08afad77b96164f73d3abaf5957eaa7aa623d879c438153dde2d7037f5e9`
- `packages/broker/src/policy-signer-ipc.test.ts`: `565e41ca803d700184e2170b69f7590dd366185db815cf70fee38549cac19bf5`
- `packages/broker/src/persistence.ts`: `a53a38bc0c8448a839176cd2b6ca4e1c7c2d5ad6a2b4b3d4c7bb01bd3b55b499`

This evidence proves the in-process local operator channel and replay boundary only. Installed startup wiring, native process identity allowlisting and packaging, protected operator-key provisioning/Keychain distribution, crash-window recovery across config-file replacement and database activation, and production enablement remain open.
