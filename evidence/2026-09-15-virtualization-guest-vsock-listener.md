# Virtualization guest virtio-socket listener evidence

## Decision and boundary

The native Virtualization.framework lifecycle artifact now exposes a separate
startup-owned listener boundary for guest-initiated virtio-socket connections.
`listenGuestPort` installs one fixed-port `VZVirtioSocketListener` with a
bounded pending-connection queue; `acceptGuestConnection` waits with a finite
deadline; and connection handles expose bounded asynchronous chunk reads,
writes, and deterministic close. The TypeScript adapter wraps this ABI as a
`VirtualizationGuestConnectionSource` consumed by
`VirtualizationGuestBootstrap`.

The listener is not an MCP tool and receives no request-selected port, handle,
path, command, or credential. The native handle keeps the listener state
separate from the host-initiated exchange path, rejects invalid ports and
limits, drains queued connections on listener or VM close, and keeps external
connection handles alive while asynchronous I/O is pending. Abort of an
accept cleans up a connection that arrives after the caller has stopped
waiting.

This closes the host-side virtio-socket acceptor seam only. It does not claim a
bootable entitled guest image, a guest-side AF_VSOCK server process, guest
profile execution, attestation production, kernel isolation, or
`mac_task_run` enablement. The native listener still requires an actually
running VM with a configured `VZVirtioSocketDevice`.

## Verification

- Native lifecycle artifact builds and passes strict code-sign verification on
  the current Darwin host.
- Native binding export readback covers listener, accept, chunk I/O, and close
  operations.
- TypeScript source-adapter test passes with a bounded fake native ABI,
  including source close and connection cleanup.
- Full physical-Darwin regression after this change: 562/562 pass, 0 skipped.
- `npm run typecheck`, `npm run lint`, and `git diff --check` pass.

## Remaining evidence

No production VM was booted in this change. A real guest image, guest-side
agent service, listener handshake, profile registry, guest filesystem/network/
credential/process evidence, and final capability enablement remain required
before this boundary can be released.
