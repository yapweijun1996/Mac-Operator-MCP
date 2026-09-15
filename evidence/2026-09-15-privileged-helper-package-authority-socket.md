# Privileged Helper Package Authority-Socket Evidence

Date: 2026-09-15
Source revision: `ee2c934`
Status: implemented boundary; disabled by default and not a privileged-release acceptance

## Scope

This checkpoint binds the root-domain helper package plan to the independent
Broker authority polling endpoint. It does not install a LaunchDaemon, change
ownership, or enable a privileged adapter.

## Implemented boundary

`PrivilegedHelperPackagePlanInput` and the resulting plan now require an exact
Broker-owned `helperAuthoritySocketPath`. The path must be canonical, distinct
from the helper and Broker command sockets, and outside the root-owned helper
package. The helper runtime status readback carries the same path and final
package readback rejects any mismatch. The package filesystem ownership set
does not silently claim the Broker-owned socket parent as root-owned helper
state.

## Verification

- `npm run typecheck` — passed.
- `npm run lint` — passed for 629 tracked files.
- Focused helper/package/status tests — 31/31 passed.
- Physical non-overlapping built suite with
  `MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1 MOPS_REAL_SANDBOX=1` — 614/614
  passed, zero failures and zero skips.
- Existing long-running Broker/Persistence tests were not restarted or
  interrupted.

## Open evidence

Developer ID signing/notarization, root LaunchDaemon installation, real
Broker-owned socket ownership and ACL readback, root helper process startup,
real privileged adapters, rollback/recovery on an installed host, and
independent P0/P1 review remain open.
