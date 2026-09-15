# Real macOS Read-only Adapter Evidence

Date: 2026-09-16
Source revision: `c82d04a`
Dirty state: clean before and after the run
Host: Darwin 25.2.0, arm64 (`yaps-Mac-mini.local`)
Runtime: Node.js `v25.5.0`

## Boundary

The real-host probes exercise only bounded read-only adapters: running-app
inventory through the fixed JXA boundary, allowlisted system launchd status,
and sanitized system log tail. Docker tests in this command are deterministic
adapter/negative-boundary tests and do not claim a live Docker daemon.

## Verification

```text
node --test --test-timeout=120000 packages/broker/dist/app-inspector.test.js packages/broker/dist/service-inspector.test.js packages/broker/dist/log-inspector.test.js packages/broker/dist/docker-inspector.test.js
```

Result: 21/21 tests passed. The physical-host cases observed bounded running
apps, `system/com.apple.logd` launchd state, and a bounded redacted `system`
log prefix. The deterministic cases additionally covered fixed Docker local
commands, traversal/alias rejection, output caps, cancellation, mount/env
redaction, and malformed-result denial.

## Limitations and rollback

No app launch/focus/action, Accessibility-granted UI, Docker daemon object
readback, mutation, privileged operation, or external service was used. These
remain separate release gates. Rollback is to the parent revision `697f427`;
the probes create no persistent host state.
