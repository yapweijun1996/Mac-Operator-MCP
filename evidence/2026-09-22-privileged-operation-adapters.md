# Privileged operation adapter evidence

Date: 2026-09-22
Status: implemented boundary; disabled by default and not a privileged-release acceptance
Host: physical Darwin arm64 (`yaps-Mac-mini.local`)

## Scope

The separately authenticated helper now has concrete bounded adapters for all
three representable operations:

- `service_control`: existing fixed `/bin/launchctl` adapter with service-state
  readback.
- `package_install`: host-owned catalog resolution by exact package identity,
  optional version, and optional source profile; root-protected artifact
  path/device/inode/metadata/digest checks; fixed
  `/usr/sbin/installer -pkg <catalog artifact> -target /`; and exact
  `/usr/sbin/pkgutil --pkg-info <package id>` receipt verification.
- `power`: fixed `/sbin/shutdown -r|-h now|+N`; the caller's reason remains
  inside the Broker-bound payload but is never forwarded to the child; future
  `not_before` values are rounded upward to a minute boundary and bounded to
  seven days; success means accepted/scheduled handoff, not completed reboot.

Each adapter has its own enabled flag and host readiness check. The composition
factory publishes only handlers whose adapter is independently available. The
Broker's authenticated command factory, explicit approval, target policy, Job
lease, kill switches, revocation checks, helper replay ledger, and root helper
release evidence remain authoritative and are not bypassed by the adapter.
The Broker dispatch integration invokes the actual composed package and power
adapters through approval, Job lease, signed command issuance, the authenticated
helper socket with HMAC response verification and durable replay guard, fixed
command runners, and postcondition mapping; it does not substitute a fabricated
helper result.

## Verification

- TypeScript typecheck passed.
- Focused package-install, power, helper-composition, and existing helper
  package/runtime/executor/service suites passed 57/57 after integration.
- Broker dispatch integration, adapter, composition, and recovery coverage
  passes 29/29, including authenticated helper IPC, durable replay admission,
  fixed installer/shutdown argv, readback mapping, unresolved outcomes,
  Job-ledger cancellation, and authority revocation.
- `mac_job_status` performs a separate authenticated `job_readback` exchange
  for unresolved privileged Jobs. The request and the Broker authority poll
  bind the exact Job ID, owner session, operation, target, payload digest, and
  policy version; adapters return only `matches`, `mismatch`, or `unavailable`.
  The Broker keeps the Job UNKNOWN and never replays the mutation command. The
  persistence readback selector accepts only exact `BROKER_RESTART` privileged
  rows with a stored payload descriptor.
- Full repository regression passed 1,151 tests: 1,136 passed, 15 skipped,
  0 failed.
- No live package installation, reboot/shutdown, root LaunchDaemon install,
  helper key activation, or MCP capability enablement was performed.

## Release limits

This proves source-level bounded adapter behavior and injected test seams only.
Production still requires a protected approved-package catalog and artifact
provenance, production helper key distribution, Developer ID/notarization,
supported root-helper sandbox evidence, root-domain installation, independent
live readback, rollback/recovery, and P0/P1 review. The default helper and
policy remain fail-closed.

## Rollback

Remove the two adapter modules, composition export, capability-release
allowlist expansion, tests, and this evidence file. No host state was changed.
