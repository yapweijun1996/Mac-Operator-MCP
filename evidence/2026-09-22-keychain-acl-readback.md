# Broker Keychain ACL readback rerun

Date: 2026-09-22
Host: physical Darwin arm64 development host
Scope: real temporary user-Keychain ACL provisioning, identity rejection, exact retirement, and cleanup; no MCP capability enablement

## Command

```text
npm run build
MOPS_REAL_KEYCHAIN=1 node --test --test-timeout=120000 \
  packages/broker/dist/credentials.test.js \
  packages/broker/dist/peer-credentials.test.js
```

## Result

- 23 tests passed, 0 failed, 0 skipped.
- The physical Keychain ACL test provisioned a random temporary 32-byte
  generic-password item bound to the active Broker executable identity.
- The item was read back through the ACL-bound path without emitting secret
  bytes. A different executable identity was rejected before secret access.
- Retirement rejected an incorrect SHA-256 digest, then retired the exact
  item by its bound reference. The final lookup failed closed as unavailable.
- The test used a unique temporary account and removed the item in its
  `finally` cleanup path. No persistent production item, secret, token, or
  password was written to the repository or test output.

## Acceptance boundary

This rerun confirms the temporary user-domain ACL mechanism and exact
retirement behavior on the current host. It does not prove Developer ID
identity, notarization, stable installed Broker identity, root-domain helper
material, production rotation, or public capability enablement. Those remain
release gates.
