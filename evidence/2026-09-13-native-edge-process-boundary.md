# Native Edge process boundary evidence

Status: PASS for the local cross-process native IPC test boundary; not a
production deployment or release-gate result.

Date: 2026-09-13 (Asia/Kuala_Lumpur)
Host: macOS 26.2, arm64 Mac mini
Node: v25.5.0
Contract version: 0.1
Policy version: 0.1
Source commit: `511f8a666c3dd1c0c87ee7caa0c839cd9e5d4ea9`
Source file SHA-256: `f8efb768101949b01aa0f95862e37ff710e1e5a5c167a45415065558cf843cb4`
Working tree before this evidence document: clean after the source commit.

## Procedure

The `native IPC accepts a separately spawned Edge bound to its PID start-time
identity` test starts a real child Node process with an explicit `/` working
directory and a minimal `PATH` environment. The child reads a temporary
owner-only (`0600`) HMAC key, signs a `mac_health` request, connects to the
temporary native Unix-domain socket, and verifies the complete Broker response
proof before reporting the result. The Broker captures the child's PID and
start-time identity, requires matching macOS UID/GID/PID identity before
constructing a socket, and then accepts the request. The parent asserts a
`SUCCEEDED` `mac_health` response. The existing peer-loss case also verifies
that a bound process exit closes the listener, removes the socket, and invokes
Edge revocation behavior.

No launchd service, root action, public endpoint, production key, or mutation
was used. Temporary sockets, SQLite state, key material, and child processes
are cleaned up by the test.

## Results

Commands and results from the clean source revision:

```text
node --test packages/broker/dist/native-ipc-server.test.js
7 passed, 0 failed

npm test
350 tests, 348 passed, 2 opt-in real-sandbox tests skipped, 0 failed

MOPS_REAL_SANDBOX=1 npm test
350 passed, 0 failed, 0 skipped
```

The source also passed TypeScript type checking before this documentation
record was written. The cross-process child verifies the response HMAC, so a
successful IPC result is not based only on transport delivery or an untrusted
stdout value.

## Scope and remaining limits

This closes local evidence that a separately spawned Edge process can reach the
native Broker IPC boundary when its exact PID/start-time identity is captured
and authorized. It does not prove separately packaged production binaries,
launchd installation or readback, Developer ID provenance/notarization,
Keychain-backed cross-process key delivery, a remote issuer chain, or Edge
restart/revocation behavior in an installed service. Those remain open under
MOP-011, MOP-081, and VT-AUTH-01.
