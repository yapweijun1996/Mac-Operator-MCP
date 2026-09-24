# Queued Job recovery metadata cleanup

## Decision

Queued Jobs that are cancelled before dispatch must not retain metadata that
is valid only for an active or restart-recoverable operation. The Broker now
clears service-control and privileged-helper recovery metadata when a queued
Job is cancelled directly, by a kill switch or revocation, or by Broker
restart reconciliation. Running Jobs converted to `UNKNOWN` retain the
metadata required for conservative recovery.

## Evidence

- Direct owner cancellation of a queued `mac_service_control` Job clears its
  service metadata and survives a Broker restart.
- Broker restart reconciliation converts a queued service-control Job to
  `cancelled`, clears its metadata, and remains stable on a second restart.
- Focused persistence and Job-state coverage: 66 passed, 0 failed, 0 skipped
  in the latest persistence-focused run.
- Full repository regression on macOS 26.2 arm64, UID 501: 1,179 total,
  1,164 passed, 15 skipped, 0 failed.
- `npm run build` passed. No host LaunchAgent, privilege, permission, or
  service state was changed.

## Limits

This closes the queued service/privileged metadata cleanup slice. It does not
prove physical process termination, descendants created after the last
snapshot, disk-full/remount durability, external actor attribution, broader
partial-mutation recovery, installed service recovery, or production
acceptance. The remaining VT-REL-01 recovery cases stay open.
