# Root Helper Authority-Poller Construction Evidence

Date: 2026-09-15
Source revision: `a79d813`
Status: implemented boundary; disabled by default and not a privileged-release acceptance

## Scope

This checkpoint hardens the no-`BrokerStore` root-helper startup path. It does
not install or launch a root helper and does not enable a privileged adapter.

## Implemented boundary

`createPrivilegedHelperRuntimeFromKeyMaterial` no longer accepts a caller-
provided authority poller. When an adapter is enabled, it requires an explicit
authority socket and constructs `PrivilegedHelperAuthorityClient` itself using
the native Broker peer policy. The same configured key validity check is used
by the command server and poller, and missing authority configuration fails
before the helper can start enabled work. The older BrokerStore-backed runtime
factory retains injection for Broker-side compatibility and test seams.

## Verification

- `npm run typecheck` — passed.
- `npm run lint` — passed for 631 tracked files.
- Focused helper runtime tests — 5/5 passed.
- Physical non-overlapping built suite with
  `MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1 MOPS_REAL_SANDBOX=1` — 615/615
  passed, zero failures and zero skips.
- Existing long-running Broker/Persistence tests were not restarted or
  interrupted.

## Open evidence

Root-owned key source/ACL behavior, Developer ID signing/notarization, real
LaunchDaemon startup, production Broker authority socket ownership, real
privileged adapters, rollback/recovery, and independent P0/P1 review remain
open.
