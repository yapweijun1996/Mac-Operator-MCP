# Privileged Helper Caller Identity Evidence

Date: 2026-09-13
Source commit: `7af182e`
Dirty-state: clean at capture
Host: macOS 26.2 (25C56), arm64
Runtime: Node.js v25.5.0
Tool contract version: 0.1
Policy version: policy-0.1

## Scope

This record covers helper-side caller identity capture before listener
construction. It does not install or mutate launchd, start a root process, or
enable privileged operations.

## Implemented boundary

`captureLaunchdBrokerProcessIdentity` accepts only the canonical per-user
`gui/<uid>/com.mac-operator.broker` service ID and checks the expected UID.
It invokes fixed `/bin/launchctl print <service>` with cwd `/`, an empty
environment, a 5-second timeout, and a bounded output cap. Only a matching
running-state readback and bounded PID are accepted; native peer readback then
binds PID and process start-time identity.

`createPrivilegedHelperRuntimeForLaunchdBroker` does not accept a caller PID or
peer identity from request arguments. It captures the identity first, then
passes the resulting native policy into the activated-key helper runtime. The
existing peer monitor closes the helper listener if the Broker identity exits
or changes.

## Verification

- `npm test`: 342 tests, 340 passed, 0 failed, 2 opt-in real-sandbox tests skipped.
- Focused helper runtime/caller tests: 3 passed, 0 failed.
- `npm run typecheck -- --pretty false`: passed.
- `npm run build -- --pretty false`: passed.
- `npm run verify:contracts`: 44 unique tool contracts validated.
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities.
- `git diff --check`: passed.

Negative coverage rejects attacker service labels, stopped services, malformed
readbacks, and any startup path lacking an explicit native identity.

## Remaining gates

Real installed Broker/helper processes, root-domain launchd ownership,
Developer ID provenance, caller-spoof tests across separate processes,
Keychain ACL approval, helper adapters, crash recovery, and independent
security review remain open.
