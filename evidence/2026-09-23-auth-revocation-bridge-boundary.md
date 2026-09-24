# Auth revocation bridge boundary

## Decision

Durable AuthStore revocation notices must not be silently lost between the
personal auth service and the authenticated Edge-to-Broker IPC boundary. The
parent personal service now owns a bounded FIFO queue for notices received from
AuthStore. It sends one notice at a time, removes a notice only after the child
transport acknowledges the send, retains the in-flight notice on transport
failure, and stops the service on transport failure or queue overflow. The Edge
child applies the same bounded fail-closed rule while it is waiting for its
Broker IPC channel to become ready. A failure after Edge readiness is also
fatal to the child process, so the parent supervisor observes the exit and
stops instead of allowing a revoked session to remain active.

## Evidence

- Source boundary: `packages/auth/src/personal-revocation.ts` implements the
  bounded ordered queue; `packages/auth/src/personal-service.ts` wires it from
  AuthStore through the Edge child and authenticated IPC.
- Queue regression: 4/4 passed, including FIFO ordering, retained in-flight
  notices after send failure, and overflow rejection.
- Durable integration regression: the real macOS test
  `durable AuthStore revocation propagates through authenticated Broker IPC`
  passes. It issues a token, revokes it through the AuthStore HTTP endpoint,
  observes the authenticated IPC callback, and verifies the Broker session
  revocation plus the `internal_authority_revoke` audit intent.
- Auth and affected Edge regression: 39 passed, 0 failed. Auth suite:
  22 passed, 0 failed.
- Full repository regression on macOS 26.2 arm64, UID 501: 1,179 total,
  1,164 passed, 15 skipped, 0 failed.
- Repository base revision inspected: `540541cb44a290ea512070796004e9129ff0ab36`.
  The working tree also contains the uncommitted source and evidence changes
  described here.

## Limits

This proves local durable AuthStore-to-Broker propagation and fail-closed
transport handling. It does not prove a live remote issuer push, a deployed
personal service, installed operator recovery, restart readback, or production
LaunchAgent acceptance. VT-AUTH-01/02/03 and the remaining VT-REV-01 remote,
installed-recovery, and restart-readback cases remain open.
