# Local Broker runtime lifecycle evidence

- Source commit: `10ef33a1885e02300d00c5949acc5638f7a1bf2b`
- Source worktree: dirty only for documentation follow-up at verification time; the tested source change is committed at the source revision above.
- Contract version: `0.1`
- Policy fixture version: `policy-0.1`
- Target host: Mac mini (Apple M4), macOS `26.2` (`25C56`), `arm64`
- Runtime: Node `v25.5.0`, npm `11.8.0`
- Timestamp: `2026-09-13` (Asia/Kuala_Lumpur)
- Verification: `npm test` — 214 passing, 0 failing; `npm run typecheck` — pass; `npm run verify:contracts` — 44 unique contracts; `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.

## Covered behavior

- `LocalBrokerRuntime` starts the Broker IPC channel before the separate policy-signer/approval operator channels supplied by the caller.
- A failed operator-channel startup closes already-started channels in reverse order and returns to `stopped` when cleanup succeeds.
- A cleanup failure is retained as `failed`; a subsequent explicit `close()` retries only active channels before allowing the runtime to return to `stopped`.
- Concurrent lifecycle calls are serialized, close is idempotent, and duplicate channel ownership is rejected.

## Artifact hashes

- `packages/broker/src/runtime.ts`: `0e40e7690d78d4a045b7d16b29d485c9ed7d0ace0348df4b199698ceae605f46`
- `packages/broker/src/runtime.test.ts`: `ab0675228be2b5a7eb642e8b52f5fedbfa4b0da4a04f496dcbfac618d2d14550`

This evidence proves only the in-process lifecycle primitive. It does not prove installed launchd startup, code signing, Keychain distribution, native caller identity, policy loading, store ownership, or production capability enablement.
