# Replay boundary targeted rerun

- Date: 2026-09-22T11:46:44Z
- Source revision: `540541c`
- Working tree: dirty; evidence is bound to the listed built artifacts, not a
  clean-release claim
- Host: Darwin arm64, macOS 26.2 physical Mac mini
- Node: v25.5.0
- Contract/protocol scope: request/authentication and HTTPS Edge/Broker
  envelopes at schema version `0.1`
- Status: targeted replay and freshness regression passed; production release
  and public remote-issuer acceptance remain open

## Commands

The focused Broker/Auth replay command was:

```text
node --test --test-timeout=120000 \
  --test-name-pattern='duplicate nonce|tampered authenticated request|expired requests and sessions|rejects replay|replay survives|replay revokes' \
  packages/broker/dist/broker.test.js \
  packages/edge/dist/edge-broker-https.test.js \
  packages/edge/dist/edge-status-ipc.test.js \
  packages/auth/dist/auth.test.js
```

Result: 7 tests passed, 0 failed, 0 skipped. The cases covered:

- altered authenticated request rejection before execution;
- duplicate nonce rejection after BrokerStore reopen;
- expired request and session fail-closed behavior;
- Auth refresh replay revoking the grant family;
- authenticated Edge OAuth revocation replay rejection; and
- Edge status IPC replay rejection.

The full HTTPS and status IPC files were then run:

```text
node --test --test-timeout=120000 \
  packages/edge/dist/edge-broker-https.test.js \
  packages/edge/dist/edge-status-ipc.test.js
```

Result: 4 tests passed, 0 failed, 0 skipped. This included the HTTPS Edge to
Broker path, the separately spawned Edge/Broker native-IPC path, and the
owner-only Edge status replay path.

## Artifact identity

SHA-256 hashes of the built test entrypoints used above:

```text
packages/broker/dist/broker.test.js        13627028b5b5f7795b3ceffd42e36191af246da9d1a6509b6a398608a3cb7eb1
packages/edge/dist/edge-broker-https.test.js 2d02e821e4720b0a0caa93ea5025872756a3a205938d5906d850369ef0aaef2a
packages/edge/dist/edge-status-ipc.test.js  acb3de2eba249fb2008325fac519c0414b2a7d1b1219ffb87144ec0cbd9b9be0
packages/auth/dist/auth.test.js             17f98a3e412daa3eb991e4613ea144319365a7ee8e627b7427518fb2699c0ed1
```

This evidence proves the local Broker and HTTPS Edge replay boundary for the
current built artifacts. It does not prove an installed production service,
public issuer deployment, Developer ID provenance, Accessibility readiness, or
production acceptance. The verification matrix therefore remains `OPEN` for
the broader `VT-AUTH-02` release row.
