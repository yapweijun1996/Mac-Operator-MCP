# Virtualization Guest Transport Shutdown Evidence

Date: 2026-09-15
Source commit: `4a22a64`
Host: physical Darwin arm64 development host

## Implemented boundary

`VirtualizationGuestTransportClient` now tracks every active exchange with a
Broker-owned `AbortController` and rejects the exchange with a stable
`CANCELLED` result when the client closes. The client checks the closed state
before creating a frame, before sending a post-admission frame, after the
channel returns, and before parsing a task or status response. New work after
close remains `POLICY_DENIED`; already admitted work cannot publish a success
after close.

The underlying channel still receives the abort signal, and its late result
cannot win the bounded exchange race. Replay admission remains durable before
transport; a request admitted before shutdown is therefore recoverable through
the existing authenticated status path rather than silently retried.

## Verification

- Focused transport tests: 15/15 pass.
- The shutdown test proves active exchange cancellation and prevents a
  post-admission send after close.
- Full physical-Darwin regression: 571/571 pass, 0 skipped.
- `npm run typecheck`, `npm run lint`, and `git diff --check` pass.

## Remaining boundary

This closes a client-side shutdown race only. It does not claim a bootable
Virtualization.framework guest, a production AF_VSOCK server, guest
filesystem/network/credential/process isolation, or `mac_task_run`
enablement.

## Rollback

Revert the client active-exchange tracking and its focused regression test;
the authenticated request/response contract and channel interface remain
unchanged.
