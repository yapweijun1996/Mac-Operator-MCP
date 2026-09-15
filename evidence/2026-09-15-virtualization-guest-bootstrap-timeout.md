# Virtualization guest bootstrap timeout cancellation evidence

Date: 2026-09-15
Source commit: `9148013`
Host: physical Darwin arm64 development host
Scope: guest bootstrap deadline cancellation; no VM boot

## Decision

A guest connection deadline is an execution authority boundary, not only a
transport read/write limit. When the deadline expires or transport handling
fails, the per-connection controller must abort guest work before the stream
is closed. This prevents an adapter from continuing guest-side mutation after
the bootstrap has rejected the connection.

## Implementation

`VirtualizationGuestBootstrap.serveStream` now owns the per-connection
`AbortController` instead of receiving only its signal. Cleanup aborts that
controller before closing the stream on every path, including request-read,
guest-execution, and response-write deadline failures. Successful teardown is
idempotent because `AbortController.abort()` is safe to repeat, while
`VirtualizationGuestAgent` already maps the propagated signal to a stable
`CANCELLED` result and refuses to sign a response after cancellation.

## Verification

- Bootstrap tests pass 6/6, including a deadline-expiry test that observes the
  guest callback's abort signal and no completed response.
- The combined guest/transport/lifecycle/startup/native focused suite passes
  52/52 with 0 skipped tests.
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This evidence does not claim a production AF_VSOCK service, bootable image,
guest filesystem/network/credential isolation, or `mac_task_run` enablement.
Those independent gates remain open.

## Rollback

Revert commit `9148013`. No persisted state, wire contract, or MCP capability
advertisement changes are involved.
