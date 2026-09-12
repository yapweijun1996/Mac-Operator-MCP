# Native Broker runtime assembly evidence

- Source commit: `24f18242191f68f231d7cc2cfff2e5542de640fc`
- Source worktree: clean at source verification; documentation follow-up is the only subsequent change.
- Contract version: `0.1`
- Policy fixture version: `policy-0.1`
- Target host: Mac mini (Apple M4), macOS `26.2` (`25C56`), `arm64`
- Runtime: Node `v25.5.0`, npm `11.8.0`
- Timestamp: `2026-09-13` (Asia/Kuala_Lumpur)
- Verification: `npm test` — 221 passing, 0 failing; `npm run typecheck` — pass; `npm run verify:contracts` — 44 unique contracts; `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.

## Covered behavior

- `createMacOsNativeBrokerRuntime` is the explicit macOS packaging/startup assembly boundary.
- The factory constructs `MacOsNativeBrokerIpcServer` directly and passes it to `LocalBrokerRuntime`; it cannot accidentally select the legacy `BrokerIpcServer` transport.
- Runtime startup creates the native owner-only UDS before any optional operator channels, and runtime close remains reverse-ordered and recoverable through the existing lifecycle implementation.
- The host test starts the factory-created runtime, confirms the native channel type and mode `0600`, and closes it without leaving the socket behind.

## Artifact hashes

- `packages/broker/src/runtime.ts`: `3e2d6ba718c9980bdbc3d8cbd9b87faf209783709ebd99caa4994c9671bfac88`
- `packages/broker/src/native-ipc-server.test.ts`: `c441c56c3cb09ee4ae88f65fcb78888c8e0e230a786ed1dd5ce1d4deabde1172`

This evidence proves only native transport selection at the in-process runtime assembly boundary. It does not prove an installed launchd service, code signing, Edge process lifecycle, protected secret distribution, operator-channel native migration, or production capability enablement.
