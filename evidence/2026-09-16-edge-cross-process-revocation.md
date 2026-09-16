# Cross-process Edge revocation evidence

Date: 2026-09-16
Source revision: `37ab0fc`
Host: physical Darwin arm64 Mac mini

## Boundary exercised

The test starts a separately spawned Edge process, binds the native Broker
socket to the child's captured UID/GID/PID-start-time identity, and connects
an MCP client over HTTPS. The parent process then revokes the Edge identity in
the Broker while the child remains alive.

## Verification

- The child Edge completes an authenticated `mac_health` request through native
  peer-checked IPC.
- The parent persists `edge-1` revocation and confirms the durable revocation
  row.
- The same MCP client session sends another `mac_health` call. The Edge's
  bounded capability projection still routes the call, and Broker authority
  returns stable `REVOKED` instead of publishing success or failing during
  server construction.
- The audit readback does not contain the bearer token.

Command:

```text
node --test packages/edge/dist/edge-broker-https.test.js
```

Result: 2/2 focused HTTPS tests pass. The complete Edge suite passes 66/66.

## Limits

This proves the cross-process local HTTPS/native-IPC propagation path only. It
does not prove installed launchd lifecycle, remote revocation distribution,
physical worker termination after an OS race, or production key rotation.
