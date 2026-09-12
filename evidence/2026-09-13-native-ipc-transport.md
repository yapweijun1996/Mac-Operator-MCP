# Native Broker IPC transport evidence

- Source commit: `0cdb8f0de00ef9d76e13723e519b1e391381d334`
- Source worktree: clean at source verification; documentation follow-up is the only subsequent change.
- Contract version: `0.1`
- Policy fixture version: `policy-0.1`
- Target host: Mac mini (Apple M4), macOS `26.2` (`25C56`), `arm64`
- Runtime: Node `v25.5.0`, npm `11.8.0`
- Timestamp: `2026-09-13` (Asia/Kuala_Lumpur)
- Verification: `npm test` — 220 passing, 0 failing; `npm run typecheck` — pass; `npm run verify:contracts` — 44 unique contracts; `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.

## Covered behavior

- The macOS N-API adapter creates an absolute-path Unix listener with `FD_CLOEXEC`, `SO_NOSIGPIPE`, owner-only `0600` permissions, a bounded backlog, and non-blocking accept.
- Native accept performs `getpeereid` and `LOCAL_PEERPID` lookup before the connection is parsed or audited. UID, GID, and exact process-ID policy checks fail closed.
- Accepted descriptors are handed to Node through the public `Socket({ fd, readable: true, writable: true })` constructor. The new native transport does not read Node's private `_handle.fd` field.
- The shared IPC request handler preserves a bounded request size, timeout, stable invalid-request response, and single-request handling for both legacy and native transports.
- Tests prove owner-only socket permissions, authenticated Broker round-trip, denied-peer no-audit behavior, and rejection of a group-writable parent directory.

## Artifact hashes

- `.gitignore`: `33cd4ee9154281aa8833123b468dcfa3f0e60a9dfcb668a2712bcd316a9ca8e4`
- `packages/broker/native/peer_credentials.cc`: `acfdbe71e2ae7d79f97dbdf23ca164dbc44a24557527797dfece7e17d6720436`
- `packages/broker/src/peer-credentials.ts`: `eaf33eb665f28fe6320f95961d6030e9e1b2547aca78b7cec112a67961cd7821`
- `packages/broker/src/ipc-server.ts`: `e29e9d243856eaccc9d237dedfd7836d3b5a6daa73ee3a3de80c437763ea2ab3`
- `packages/broker/src/native-ipc-server.ts`: `8282c0ed9ffa415d951ad5ff0a649e242cedc88eea9e24704562381b24858ce9`
- `packages/broker/src/native-ipc-server.test.ts`: `2a14df8aa78257eab636ceb61fbbf313366549373f1a515709067ebcbdfcacb5`

This evidence proves the local native UDS acceptance boundary and public Node descriptor handoff. It does not prove installed launchd packaging, code signing, Edge PID lifecycle wiring, Keychain/cross-process secret distribution, sandbox enforcement, or production capability enablement. The legacy `BrokerIpcServer` compatibility path still uses the private Node socket handle through `MacOsPeerCredentialVerifier`; production startup must select the native transport until that compatibility path is removed or independently accepted.
