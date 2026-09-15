# Audit-Outage Read-Only Fail-Closed Evidence

Date: 2026-09-15

Source revision: `e1308c9`

## Decision

If the keyed audit tail cannot publish or verify, the Broker rejects every
new MCP request admission, including read-only tools, until restart with a
verified tail. Host recovery/readback remains separate and can inspect the
frozen state. This avoids an unrecorded read side channel at the cost of
availability during an audit outage.

## Verification

`audit-anchor-readonly.test.ts` first commits an audit event, holds the
owner-only anchor lock, and verifies that the next append returns stable
`AUDIT_UNAVAILABLE` after SQLite commit. Once the lock is removed, the same
BrokerStore remains frozen: a valid non-mutating `mac_health` admission also
returns `AUDIT_UNAVAILABLE` and creates no Request row. The two committed
audit rows remain available to the host readback path.

Focused test result: 1/1 passed, 0 failed, 0 skipped.

No external authority, production capability, privileged action, or
destructive operation was invoked. External immutable anchoring, production
Keychain recovery, and installed-service recovery remain open.
