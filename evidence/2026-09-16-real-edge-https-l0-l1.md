# Real macOS Edge and L0/L1 Readback Evidence

Date: 2026-09-16
Source revision: `c82d04a`
Dirty state: clean before and after the run
Host: Darwin 25.2.0, arm64 (`yaps-Mac-mini.local`)
Runtime: Node.js `v25.5.0`
Policy: `policy-0.1`, read-only `mac.control.read` fixture

## Boundary

This run exercises the local layered path `HTTPS MCP Edge -> authenticated
local IPC -> Broker` and the bounded L0/L1 host readback probe. The Edge uses a
temporary self-signed certificate and a test RS256 issuer; the native Broker
IPC peer is bound to the expected macOS UID/GID and, in the cross-process case,
the captured Edge PID/start-time identity. No installed service, public
listener, mutation, credential surface, or privileged helper is used.

## Verification

```text
node --test --test-timeout=120000 packages/edge/dist/edge-broker-https.test.js packages/broker/dist/l0-l1-host-readback.test.js
```

Result: 3/3 tests passed, including metadata-only bounded L0/L1 readback,
same-process signed HTTPS-to-Broker delivery, and a separately spawned Edge
process completing the native Broker IPC and HTTPS MCP request. The test also
verified that a replayed Broker request is rejected and that the bearer token
does not enter Broker audit rows.

## Limitations and rollback

This is real-host prototype evidence for the local boundary, not production
issuer, certificate-chain, launchd installation, remote deployment, or release
evidence. Rollback is to the parent implementation revision `1ea5ab4`; the
test creates and removes only temporary files and sockets.
