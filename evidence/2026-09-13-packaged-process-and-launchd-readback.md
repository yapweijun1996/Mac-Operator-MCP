# Packaged process and launchd readback evidence

Status: PASS for the local separately spawned process and read-only launchd
readback boundaries; not a live installation or release-gate result.

Date: 2026-09-13 (Asia/Kuala_Lumpur)
Host: macOS 26.2, arm64 Mac mini
Node: v25.5.0
Contract version: 0.1
Policy version: 0.1
Source commit: `018565d5b7ff77ef7afdec4faebd61bcdfe1b498`
Working tree before this evidence document: clean after the source commit.

Source hashes:

- `packages/broker/src/launchd-readback.ts`: `c619402276ed22ef592c2253e9e7913306241e32ea0f25473004c8e9c7c02135`
- `packages/broker/src/launchd-readback.test.ts`: `c18242830514403efc45eb6ee86dcfcf6677930299527434907adecbaac3ce85`
- `packages/broker/src/native-ipc-server.test.ts`: `6e4e59fc585ea91fd8e99e65bfab39a690811318ac00ad3164bfee62598b8000`

## Readback boundary

`readLaunchdJobReadback` accepts only a bounded `system/...` or `gui/<uid>/...`
service identifier and executes fixed `/bin/launchctl print <service>` with
working directory `/`, an empty environment, a five-second timeout, and a
131,072-byte output cap. It validates the exact service header, state, PID,
canonical absolute program/plist paths, service type, and exit code, and
returns only stable metadata. Traversal, identity substitution, relative
paths, unsupported states, and oversized output fail closed.

The real-Mac smoke reads the existing `system/com.apple.logd` service without
changing launchd state. The focused readback/IPC command passes 11/11.

## Independent process boundary

The native IPC smoke starts a separately spawned Broker process and a
separately spawned Edge process from the built package modules. Both children
use working directory `/` and only the fixed system `PATH`; the temporary
HMAC key is an owner-only (`0600`) file. The Broker child captures the Edge
PID/start-time identity before constructing the native listener. The Edge child
signs a `mac_health` request, reaches the Broker over the native UDS, verifies
the complete response proof, and exits only after receiving `SUCCEEDED`.

Commands and results from the clean source revision:

```text
node --test packages/broker/dist/launchd-readback.test.js packages/broker/dist/native-ipc-server.test.js
11 passed, 0 failed

npm test
354 tests, 352 passed, 2 opt-in real-sandbox tests skipped, 0 failed

MOPS_REAL_SANDBOX=1 npm test
354 passed, 0 failed, 0 skipped
```

Temporary sockets, SQLite state, key material, readiness files, and child
processes are cleaned up. No launchd bootstrap/bootout, plist installation,
root action, public endpoint, production credential, or mutation was used.

## Remaining limits

This evidence proves a local separately spawned Edge/Broker process boundary
and a bounded read-only launchd parser. It does not prove an installed
LaunchAgent, production package artifact, Developer ID provenance or
notarization, Keychain ACLs, live upgrade/rollback/uninstall, remote issuer
deployment, or restart behavior under launchd. Those remain open under
MOP-011, MOP-072, MOP-081, VT-AUTH-01, and VT-OPS-01.
