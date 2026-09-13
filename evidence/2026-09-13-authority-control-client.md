# Authority Control IPC Client Evidence

Date: 2026-09-13
Source commit: `eeebec3`
Dirty-state: clean at capture
Host: macOS 26.2 (25C56), arm64
Runtime: Node.js v25.5.0
Tool contract version: 0.1
Policy version: policy-0.1

## Scope

This record covers the host-only uninstall authority assembly path. It does
not claim an installed LaunchAgent, a production operator key, a live Edge, or
remote authority propagation.

`AuthorityControlIpcClient` now drives the existing owner-only Authority
Control IPC server. Every request is a fresh protocol-`0.1` command with a
random request ID and nonce, a bounded expiry, and an HMAC over the complete
canonical command. The server admits the request/nonce durably before applying
the allowlisted switch or revocation operation, so duplicate commands remain
rejected across a store reopen. Responses carry an HMAC bound to both the
request digest and the complete response body; forged or mismatched responses
fail closed before the caller can treat an authority change as successful.

The client validates a canonical owner-only socket directory and socket,
rechecks device/inode identity after connect, bounds response bytes and
transport time, supports cancellation, and maps transport, timeout, malformed
response, and authority failures to stable Broker errors. Read-only switch and
revocation operations provide authenticated pre/post readback. The uninstall
adapter factory uses those reads before writes, binds revocation to the exact
selected Edge ID, and is idempotent when the desired authority state already
exists.

## Verification

- `npm test`: 329 tests, 327 passed, 0 failed, 2 opt-in real-sandbox tests skipped.
- Focused authority/install suites: 14 passed, 0 failed.
- `npm run build -- --pretty false`: passed.
- `npm run typecheck -- --pretty false`: passed.
- `npm run verify:contracts`: 44 unique tool contracts validated.
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities.
- `git diff --check`: passed.

Focused coverage includes wrong-key and denied-peer rejection, response-proof
forgery, durable replay denial, stale expected-state conflict, authenticated
readback, client set/revoke calls, socket identity checks, idempotent uninstall
authority actions, exact Edge binding, and fail-closed uninstall sequencing.

## Remaining gates

The implementation remains a host-only library boundary. Production acceptance
still requires protected operator-key delivery/rotation, signed and notarized
packaging, launchd startup ownership, installed Edge identity binding, live
uninstall and key cleanup, active-process termination, remote revocation
propagation, restart recovery, and final readback on the supported Mac mini.
