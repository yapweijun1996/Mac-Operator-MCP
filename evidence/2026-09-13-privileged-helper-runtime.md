# Privileged Helper Runtime Assembly Evidence

Date: 2026-09-13
Source commit: `12a1ac3`
Dirty-state: clean at capture
Host: macOS 26.2 (25C56), arm64
Runtime: Node.js v25.5.0
Tool contract version: 0.1
Policy version: policy-0.1

## Scope

This record covers startup/lifecycle assembly for the separately authenticated
L5 helper. It does not install launchd jobs, change user/root ownership, launch
a root process, or enable service, package, or power operations.

## Implemented boundary

`createPrivilegedHelperRuntimeFromActiveKeyConfig` restores the exact
BrokerStore-approved `helper_key` configuration before constructing the helper
IPC server. The startup boundary requires a native peer policy with an
explicit PID/start-time identity, rejects non-canonical paths and socket reuse
with the unprivileged Broker or reserved control channels, and never accepts a
key, socket, or peer identity from an MCP request.

`PrivilegedHelperRuntime` serializes start/close operations, rolls back a
partial start by closing the helper server and wiping its defensive HMAC key,
and reports a failed lifecycle when cleanup itself fails. The replay guard,
allowlisted adapter, and Broker-owned authority callback are supplied by the
caller; the tested adapter is `FailClosedPrivilegedHelper`.

## Verification

- `npm test`: 337 tests, 335 passed, 0 failed, 2 opt-in real-sandbox tests skipped.
- Focused helper runtime/keyring tests: 4 passed, 0 failed.
- `npm run typecheck -- --pretty false`: passed.
- `npm run build -- --pretty false`: passed.
- `npm run verify:contracts`: 44 unique tool contracts validated.
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities.
- `git diff --check`: passed.

Coverage includes exact activation restore, native peer identity requirement,
Broker/control socket separation, clean temporary-root listener start/close,
invalid-boundary denial before key restore, and fail-closed adapter wiring.

## Remaining gates

Separate helper/root packaging, caller identity provenance, code signing and
notarization, approved Keychain ACLs, real adapters, crash recovery, rollback
on a real installed process, independent security review, and all privileged
host evidence remain open. No privileged operation is enabled.
