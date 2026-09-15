# Broker Status Response-Schema Evidence

- Date: 2026-09-16
- Host: physical macOS host used by the repository test harness
- Source revision: `d6f704b`
- Contract/policy versions: 0.1
- Evidence class: local and physical Broker status IPC boundary regression

## Decision

Treat Broker status failures as a fixed, authenticated data envelope. Nested
error records must contain only `message` and `retryable`; messages are bounded
to 512 characters and cannot contain NUL or line-break characters.

## Implemented controls

`authenticateBrokerStatusResponse` now requires the exact failure-record shape
and bounded error text after response-proof verification. `statusFailure`
sanitizes hostile or oversized internal error messages before signing them, so
status readback remains stable and log-safe even when an authorization callback
returns attacker-influenced text.

## Verification

Focused command:

```text
npm run build
node --test --test-concurrency=1 packages/broker/dist/broker-status-ipc.test.js
npm run lint
npm run typecheck
git diff --check
```

Result: 3/3 Broker status IPC tests passed, with no skips or failures. The
synthetic authorization failure containing a newline was returned as the
bounded stable message `Broker status request failed` and authenticated
successfully as a failure response.

The serial physical regression ran with install, sandbox, and Keychain opt-ins
and passed 641/641 tests, with zero skips and failures. The pre-existing
long-running Broker, persistence, and privileged-helper IPC suites were
excluded and left undisturbed. Run log:
`/tmp/mops-broker-status-failure-physical-regression.log`.

Artifact SHA-256:

```text
packages/broker/src/broker-status-ipc.ts
234f69454bd654db17756e753f5c5967a350f411dc0d33f66117a4cda1aaa1c5
packages/broker/src/broker-status-ipc.test.ts
2c6da48652414d6008db6a038d3a13ea8ceb27efaca3e2c5caf817c4c1a0c9a8
```

## Boundary status

This closes the Broker status failure-record and error-text boundary for the
implemented local status IPC. It does not enable production installation,
Developer ID signing, remote deployment, or any privileged operation.
