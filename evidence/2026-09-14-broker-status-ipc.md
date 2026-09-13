# Broker Status IPC Evidence

Status: Partial real-host authenticated readback; package lifecycle rerun remains open

## Scope

This evidence covers the separate Broker-owned operator status channel used by
startup readback and the install host observer. It is not an MCP tool and does
not grant capability authority.

## Implemented boundary

- The status channel uses a distinct owner-only Unix socket and a separate
  owner-only 32-byte key whose SHA-256 digest is pinned in the startup config.
- macOS startup uses the native peer transport with the configured Edge UID/GID;
  requests and responses use a domain-separated HMAC, bounded timestamps, and
  strict readback envelopes.
- BrokerStore persists status nonces and request IDs transactionally, so a
  replay is rejected after a Broker restart. The server authorizes status only
  while the Broker service is running.
- The install host observer can select this authenticated client explicitly;
  the legacy callback remains available only for focused test fixtures.

## Verification

- `Broker status IPC authenticates readback and rejects durable replay` passed,
  including replay rejection after closing and reopening the BrokerStore.
- `Broker service startup restores signed authority before native runtime start`
  passed on the physical Darwin arm64 host. It restored signed policy and Edge
  keys, started the native Broker and status sockets, and completed an
  authenticated `readBrokerStatus` readback with `state=running` and
  `runtimeState=running`.
- The full startup-focused suite passed 4/4 after the status channel was wired;
  `npm run typecheck` and `npm run build` passed.

## Boundary

This proves the local authenticated status protocol, durable replay fence, and
real macOS startup integration. The earlier package install smoke was not
retroactively rerun with this channel and remains historical fixture evidence;
Developer ID provenance, remote Edge exchange, upgrade/rollback, and helper
installation remain open.

Host: Darwin arm64, Node v25.5.0. No secret bytes or private keys are recorded.
