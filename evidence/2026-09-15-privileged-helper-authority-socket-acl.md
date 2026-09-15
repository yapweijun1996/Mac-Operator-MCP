# Privileged Helper Authority-Socket ACL Evidence

Date: 2026-09-15
Source revision: `fe9d681`
Status: implemented boundary; disabled by default and not a privileged-release acceptance

## Scope

This checkpoint verifies the Broker-owned authority Unix socket as a separate
ownership domain from the root-owned helper package. It does not install a
LaunchDaemon or enable a privileged adapter.

## Implemented boundary

`readPrivilegedHelperAuthoritySocketReadback` performs two `lstat` reads of
the planned authority endpoint. It requires a non-symlink Unix socket, the
planned Broker UID/GID, no group/other permissions, and unchanged
mode/ownership/device/inode between reads. The final helper package readback
requires this source and matches its path to the runtime status and package
plan. The endpoint is intentionally excluded from the root-owned helper file
preflight.

## Verification

- `npm run typecheck` — passed.
- `npm run lint` — passed for 630 tracked files.
- Focused helper package tests — 14/14 passed.
- Physical non-overlapping built suite with
  `MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1 MOPS_REAL_SANDBOX=1` — 615/615
  passed, zero failures and zero skips.
- The focused test exercised a real Unix socket, owner-only mode, and a
  symlink replacement denial.
- Existing long-running Broker/Persistence tests were not restarted or
  interrupted.

## Open evidence

Production Broker socket parent ACLs, root LaunchDaemon installation,
Developer ID signing/notarization, real root helper startup, privileged
adapters, rollback/recovery on an installed host, and independent P0/P1 review
remain open.
