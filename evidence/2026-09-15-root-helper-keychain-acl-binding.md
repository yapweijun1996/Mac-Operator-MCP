# Root-Helper Keychain ACL Binding Evidence

- Source revision: `4bc0308`
- Date: 2026-09-15
- Scope: helper-key loading and executable-bound Keychain access

## Change

The BrokerStore-backed helper-key loader continues to use the Broker executable
for Keychain ACL checks. The root-helper loader, which deliberately does not
open `BrokerStore`, accepts a startup-owned `keychainTrustedExecutablePath` and
requires it whenever the protected config selects a Keychain source. A missing
binding is rejected before native Keychain access or secret-byte loading.
File-backed root-helper keys remain supported without this option.

## Verification

- Focused helper keyring/runtime suites: 10/10 passed.
- Negative coverage: a Keychain-backed root-helper config without an explicit
  trusted executable path is rejected before native access.
- Physical non-overlapping built suite:
  `MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1 MOPS_REAL_SANDBOX=1 node --test --test-timeout=120000 $(find packages -path '*/dist/*.test.js' ! -name broker.test.js ! -name persistence.test.js | sort)`
- Physical result: 617/617 passed, 0 skipped, 0 failed.
- `npm run typecheck`: passed.
- `npm run lint`: passed across 633 tracked files.
- `git diff --check`: passed before commit.

The existing long-running Broker/Persistence test process was not restarted.
This evidence does not claim a production root helper, Developer ID signing,
or privileged operation enablement.
