# Packaged Broker audit-anchor startup evidence

Date: 2026-09-14
Host: Darwin 25.2.0 arm64; temporary per-user LaunchAgents only
Status: host evidence for a temporary, opt-in smoke; not a release gate

## Boundary

Packaged Broker startup now requires an owner-controlled audit-anchor path
under the configured data root and fixed Keychain service/account/key-id
coordinates. The compiled entrypoint constructs `BrokerStore` with the
Keychain-backed HMAC source before activating the Edge policy or reporting
`running`. Missing, mismatched, or unreadable Keychain material therefore
fails closed at the Broker boundary; neither MCP arguments nor environment
variables can select the anchor.

## Verification

Command:

```text
MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1 node --test packages/broker/dist/packaged-service-smoke.test.js
```

Result: 1 passed, 0 failed, 0 skipped.

The test provisioned a random temporary Keychain item bound to the packaged
Broker executable, booted the compiled Edge and Broker LaunchAgents, read back
launchd identity plus authenticated Broker status, and confirmed the audit
anchor before readiness. Cleanup retired the exact Keychain item and booted out
both labels; no persistent service or credential remained.

## Limits

This proves startup wiring and a real local ACL/readback path only. It does not
prove Developer ID signing, notarization, persistent production provisioning,
rotation across upgrades, cross-process sidecar locking, external immutable
anchoring, or privileged helper installation.
