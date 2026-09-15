# Privileged Helper Key-Material Isolation Evidence

Date: 2026-09-15
Source revision: `e786002`
Status: implemented boundary; disabled by default and not a privileged-release acceptance

## Scope

This checkpoint separates root-helper key loading from the Broker persistence
authority. It does not install a root launchd job, enable a privileged adapter,
or claim production root-domain evidence.

## Implemented boundary

`createPrivilegedHelperRuntimeFromKeyMaterial` accepts no `BrokerStore`. It
loads a protected local helper-key config and key, validates the configured
validity window, and creates defensive key copies for the helper command
server and optional authority poller. When an adapter is enabled, startup
requires a separately authenticated Broker authority poller; revocation,
rotation, Request/Approval/Job binding, and kill-switch decisions remain
Broker-owned. The loaded key snapshot is wiped after construction and all
temporary construction failures dispose the poller and helper server.

The existing `createPrivilegedHelperRuntimeFromActiveKeyConfig` and
`PrivilegedHelperKeyManager` remain for Broker-side activation and compatibility
paths. They are not the root-helper startup boundary.

## Verification

- `npm run typecheck` — passed.
- `npm run lint` — passed for 628 tracked files.
- Focused helper runtime/keyring/authority tests — 11/11 passed.
- Physical non-overlapping built suite with
  `MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1 MOPS_REAL_SANDBOX=1` — 614/614
  passed, zero failures and zero skips.
- The root-helper test constructed the key-material runtime without a
  `BrokerStore` and confirmed no Broker SQLite file was created.
- Existing long-running Broker/Persistence tests were not restarted or
  interrupted.

## Open evidence

The local test runs as a non-root user and therefore does not prove root-owned
file/Keychain ACL behavior. Developer ID signing/notarization, root launchd
installation, production key distribution, real privileged adapters, crash and
rollback recovery, and independent P0/P1 review remain open.
