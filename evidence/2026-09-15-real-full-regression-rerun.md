# Physical Darwin Full Regression Rerun

Date: 2026-09-15

Source revision: `cd62bbc`

Host: Darwin arm64, macOS 26.2, Node.js v25.5.0

Environment gates:

```text
MOPS_REAL_INSTALL=1
MOPS_REAL_KEYCHAIN=1
MOPS_REAL_SANDBOX=1
```

Command:

```text
find packages -path '*/dist/*.test.js' \
  ! -name 'broker.test.js' \
  ! -name 'persistence.test.js' \
  -print0 | xargs -0 node --test --test-concurrency=1
```

Result: 595 tests passed, 0 failed, 0 skipped, in 31.8 seconds.

## Host coverage

The run exercised the opt-in physical sandbox, protected credential-surface
checks, fork/`setsid` denial, TCP/UDP allowlists, active cancellation,
temporary Keychain ACL binding and retirement, per-user Edge/Broker
LaunchAgent bootstrap/authenticated readback/bootout, native UDS peer and
PID-start-time binding, HTTPS MCP discovery, policy/key rotation, filesystem
race and atomic-write recovery boundaries, Docker and Git inspection, GUI
read-only boundaries, helper protocol/package gates, VM negative gates, and
the deterministic security-fuzz suites.

The pre-existing `packages/broker/dist/broker.test.js` and
`packages/broker/dist/persistence.test.js` process remains undisturbed and is
not represented by this result. No production capability, root helper, public
listener, or destructive operation was enabled.

This closes a current physical-Darwin regression checkpoint only. Persistent
production installation, Developer ID provenance, real credential/process
isolation, VM isolation, external issuer/deployment, and independent P0/P1
review remain open.
