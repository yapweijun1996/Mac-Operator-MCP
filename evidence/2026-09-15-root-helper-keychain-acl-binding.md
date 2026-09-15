# Root-Helper Keychain ACL Binding Evidence

- Source revisions: `4bc0308` (explicit binding), `666a978` (metadata),
  `711f3e4` (stable path errors)
- Date: 2026-09-15
- Scope: helper-key loading and executable-bound Keychain access

## Change

The BrokerStore-backed helper-key loader continues to use the Broker executable
for Keychain ACL checks. The root-helper loader, which deliberately does not
open `BrokerStore`, accepts a startup-owned `keychainTrustedExecutablePath` and
requires it whenever the protected config selects a Keychain source. It then
checks the item's non-secret ACL/protection metadata before reading secret
bytes. Missing or non-canonical binding is rejected with a stable error before
native Keychain access. File-backed root-helper keys remain supported without
this option.

## Verification

- Focused helper keyring/runtime suites: 10/10 passed.
- Focused credential suite: 14 passed, 1 explicit physical Keychain test
  skipped because the temporary ACL gate was not enabled in that focused run.
- Negative coverage: a Keychain-backed root-helper config without an explicit
  trusted executable path, or with a missing canonical path, is rejected before
  native access.
- Protection coverage: helper Keychain reads invoke the non-secret ACL,
  synchronizable, and trusted-application metadata check before loading bytes.
- Physical non-overlapping built suite:
  `MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1 MOPS_REAL_SANDBOX=1 node --test --test-timeout=120000 $(find packages -path '*/dist/*.test.js' ! -name broker.test.js ! -name persistence.test.js | sort)`
- Physical result: 617/617 passed, 0 skipped, 0 failed.
- `npm run typecheck`: passed.
- `npm run lint`: passed across 634 tracked files.
- `git diff --check`: passed before commit.

The existing long-running Broker/Persistence test process was not restarted.
This evidence does not claim a production root helper, Developer ID signing,
or privileged operation enablement.
