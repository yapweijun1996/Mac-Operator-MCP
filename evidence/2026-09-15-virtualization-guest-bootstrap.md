# Virtualization guest bootstrap evidence

Date: 2026-09-15

## Decision

Guest protocol serving is separated from the transport-specific vsock
acceptor. The guest bootstrap accepts a startup-owned connection source and
delegates exactly one bounded framed request to `VirtualizationGuestAgent`.
The bootstrap never receives host paths, raw commands, credentials, or MCP
authority claims.

## Implementation

`packages/broker/src/virtualization-guest-bootstrap.ts` owns a bounded guest
server lifecycle. It requires an explicit `enabled` gate, limits frame and
response bytes, limits concurrent connections, applies one connection deadline
across read/agent/write, rejects invalid lengths and coalesced trailing request
data, closes every stream after one response, and closes the guest agent (which
wipes its HMAC key) during shutdown. Per-connection cancellation now propagates
through `VirtualizationGuestAgent` to the guest executor before the stream is
drained. The `VirtualizationGuestConnectionSource` interface keeps
AF_VSOCK/native accept policy outside the protocol loop.

The service startup path remains host-owned: it composes the native VM,
authenticated transport, and Broker task runner independently. A future guest
image can provide a vsock acceptor implementing this source without changing
the authenticated frame or task contracts.

## Verification

- Guest bootstrap tests: 5/5 pass.
- Full physical-Darwin suite after this change: 560/560 pass, 0 skipped.
- `npm run typecheck`, `npm run lint`, and `git diff --check` pass.

This evidence does not claim a production AF_VSOCK acceptor, bootable guest
image, Virtualization entitlement, real guest process isolation, or
`mac_task_run` enablement. Those remain separate release gates.

## Rollback

Remove the bootstrap module and its export/tests; the existing host transport
and guest-agent contract remain unchanged. No persisted data or MCP contract
changes are required.
