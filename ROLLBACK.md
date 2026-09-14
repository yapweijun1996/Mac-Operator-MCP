# Rollback Contract

Status: Draft; no artifact or deployed version exists

## Required rollback inputs

Source and artifact version, contract and policy versions, persistence schema version, backup identity, component compatibility, active request/job state, credential state, and target release.

## Rules

- Disable affected capability admission before rollback.
- Reconcile active mutations and jobs before replacing components or state.
- Reject incompatible policy, data, Edge/Broker, or helper combinations.
- Preserve append audit evidence and never restore secret-bearing outputs.
- Verify component identity, health, Broker privacy, policy version, switches, and tool enable state after rollback.
- A rollback does not restore revoked credentials or approvals unless explicitly and safely reissued.

## Evidence

Each releasable phase requires a tested rollback procedure with exact artifacts, commands, expected state, failure handling, and post-rollback verification. The source-level launchd boundary now includes a non-executing install plan, double-`lstat` filesystem preflight, and a temporary-root-tested `applyMacOsPlistPlan` that uses descriptor-relative atomic install/upgrade/rollback/uninstall with target identity and postcondition readback. No installed artifact, live `launchctl` rollback, signed artifact, or production uninstall evidence exists yet.

The Broker persistence-specific migration and recovery order is documented in
[PERSISTENCE_CUTOVER.md](PERSISTENCE_CUTOVER.md). It restores only authenticated
encrypted backups into fresh destinations and does not expose an in-place
down-migration or force-reset operation.
