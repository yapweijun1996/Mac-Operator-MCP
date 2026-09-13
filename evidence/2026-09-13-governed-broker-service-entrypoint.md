# Governed Broker service entrypoint evidence

Status: PASS for the local startup/configuration boundary; not a live
LaunchAgent installation or release-gate result.

Date: 2026-09-13 (Asia/Kuala_Lumpur)
Host: macOS 26.2, arm64 Mac mini
Node: v25.5.0
Contract version: 0.1
Source commit: `8ac5fe02a15aa21cb40abc0d7d92814fd52dd516`
Working tree before this evidence document: clean after the source commit.

Source hashes:

- `packages/broker/src/service-startup.ts`: `ce2c0504559b2177e8934581a212da59d61280aeee41cbec3e174097f22e74c9`
- `packages/broker/src/service-startup.test.ts`: `c275bdb896764b75f5dcfc89a4135e2f6590b6e9e9e6df47f8da34be8dbbdcb3`
- `packages/broker/src/service-main.ts`: `86b5a188658d425e6a4616ac366d64e1f4ddac7ed50fbc868c92e9bb4949c1aa`
- `packages/broker/src/service-entrypoint.ts`: `0aa49aaeeaab378e5527e828c6ed167a0460b9c302cc5ba481c07715f9dccaf9`
- `packages/broker/src/edge-keyring.ts`: `ef9522face5ff15afc25da613709df5caf4c92d1acc5af79f9b361220835bccf`

## Startup contract

`service-main.ts` has no configurable argv or environment authority. It loads
the fixed `broker-service.json` adjacent to the packaged entrypoint. The
startup document contains only versioned identities, paths, and metadata; it
does not contain secret bytes. The loader requires an owner-only regular file,
canonical paths, distinct package/data/runtime roots, private data/runtime
directories, root-contained targets, a non-root per-user Edge service, and
strict source/contract/key identities. Symlinked or target-swapped files fail
closed.

`createBrokerServiceFromStartupConfig` verifies the signed policy and restores
its exact persisted activation before constructing the Broker. It restores the
Edge key configuration through the existing digest/revocation/activation
manager, requires the policy to trust the configured Edge, captures the Edge
launchd PID/start-time identity, and only then constructs the native Broker
runtime. The service close path wipes loaded Edge authentication keys.

## Results

```text
node --test packages/broker/dist/service-startup.test.js
3 passed, 0 failed

npm test
358 tests, 356 passed, 2 opt-in real-sandbox tests skipped, 0 failed

MOPS_REAL_SANDBOX=1 npm test
358 passed, 0 failed, 0 skipped

npm run verify:contracts
44 unique tool contracts validated

npm audit --omit=dev --audit-level=high
0 vulnerabilities
```

The startup test covers strict/unknown-field rejection, canonical root-bound
paths, weak and symlinked config denial, signed policy and Edge-key activation
restore, native runtime start/close, and readback of enabled capabilities. The
test uses a fake read-only `launchctl print` result; no launchd state is
changed.

## Remaining limits

This evidence proves a governed packaged entrypoint assembly and local native
runtime lifecycle. It does not prove an installed LaunchAgent, Developer ID
provenance/notarization, live launchd bootstrap/readback, Keychain ACL review,
remote issuer deployment, or production upgrade/rollback/uninstall. Those
remain open under MOP-072, MOP-081, VT-AUTH-01, and VT-OPS-01.
