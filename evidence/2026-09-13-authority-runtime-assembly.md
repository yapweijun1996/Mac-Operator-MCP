# Authority Control Runtime Assembly Evidence

Date: 2026-09-13
Source commit: `a06eb81`
Dirty-state: clean at capture
Host: macOS 26.2 (25C56), arm64
Runtime: Node.js v25.5.0
Tool contract version: 0.1
Policy version: policy-0.1

## Scope

This record covers startup assembly only. It does not claim that the service
was installed into the user's LaunchAgent domain, that an operator process was
connected, or that a live production uninstall was performed.

## Implemented boundary

`createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfigAndAuthority`
restores the active Edge key configuration and the active Authority Control
key configuration before constructing channels. The Authority channel uses a
separate socket and requires an explicit native peer PID/start-time identity;
it cannot silently fall back to a legacy PID-only or unauthenticated path.

The authority server is appended to the same `LocalBrokerRuntime` lifecycle as
the native Broker channel. Broker IPC starts first, partial startup rolls back
in reverse order, and the Authority server owns a defensive key copy that is
wiped on close. If authority restoration, channel construction, or Edge
startup fails, the new channel is closed and the source manager releases its
key buffer without misclassifying Edge startup failures as authority success.

## Verification

- `npm test`: 333 tests, 331 passed, 0 failed, 2 opt-in real-sandbox tests skipped.
- Native runtime startup suite: 6 passed, 0 failed.
- `npm run build -- --pretty false`: passed.
- `npm run typecheck -- --pretty false`: passed.
- `npm run verify:contracts`: 44 unique tool contracts validated.
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities.
- `git diff --check`: passed.

The focused startup test uses a temporary protected store and paths, restores
both key configurations, assembles separate Broker and Authority sockets,
starts and closes the native runtime, and verifies the lifecycle returns to
`stopped`. No persistent service or user data was changed.

## Remaining gates

Production still requires signed/notarized artifacts, approved Keychain ACLs,
operator-process packaging and identity, live LaunchAgent install/readback,
key rotation/retirement procedure, active-work termination, remote
revocation propagation, and final real-Mac uninstall readback.
