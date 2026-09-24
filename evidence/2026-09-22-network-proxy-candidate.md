# Broker-Owned Network Proxy Candidate

Date: 2026-09-22
Host: Darwin arm64 physical Mac, current process UID 501
Status: `implemented` as a disabled-by-default Broker candidate with an
App Sandbox child-facing channel; no MCP tool, task-child entitlement, or
production network grant is enabled

## Boundary

`packages/broker/src/network-proxy.ts` defines a Broker-owned loopback TCP
proxy candidate. The policy normalizes `localhost` and `127.0.0.1` to a fixed
`tcp://localhost:<port>` identity, rejects duplicates, and binds the complete
destination and byte/timeout budgets to a SHA-256 policy digest. The exchange
path accepts only a Broker-frozen policy, connects to the numeric loopback
address without DNS, bounds request and response bytes, maps timeout and
cancellation to stable Broker errors, and rejects known credential-shaped
payload or response content.

The proxy is not an MCP tool and does not receive policy data from caller
arguments. Its constructor is unavailable by default unless an explicit
Broker-owned enablement flag is supplied. The App Sandbox executor now
integrates it through a per-run inherited Unix FD and a token-bound framed
child protocol; that channel is still not permission to give a task process
raw network sockets.

## Verification

The focused proxy/channel suite passes 5/5:

- default-disabled construction rejects use;
- a controlled loopback server succeeds only for the digest-bound target;
- policy drift, secret payloads, and request budgets fail closed;
- cancellation and timeout close the exchange without leaving an active proxy
  socket; and
- the child-facing channel authenticates a token-bound frame and rejects a
  replayed request ID.

`npm run typecheck` passes. The focused proxy/channel suite passes 5/5. The
full repository regression passes 996/1011 tests, with 15 explicit skips and
0 failures. The restart-process recovery regression now waits for the
authoritative `onStarted` persistence signal instead of relying on a fixed
delay, so the result is stable under full-suite parallel load.

## Remaining boundary

The candidate is integrated with `AppSandboxTaskRunner` behind the independent
network evidence gate and has physical loopback positive-network evidence, but
the helper remains ad-hoc signed. Developer ID/notarization, installed
identity readback, rollback, recovery, and public task enablement remain
independent release gates. The full-suite count in this file will be refreshed
after the current integration regression completes.

## Rollback

Rollback is source-level removal of the candidate, focused tests, export, and
this evidence. No host listener, persistent policy, credential, OAuth grant,
or MCP scope was changed.
