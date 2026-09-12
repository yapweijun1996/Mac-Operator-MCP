# Operations Guide

Status: Draft; operational commands will be added after runtime selection

## Operator responsibilities

Monitor Edge, Broker, persistence, audit, jobs, disk budgets, policy version, credential expiry, and helper compatibility. Apply authority changes through an authenticated operational workflow. Never edit production state through generic model-facing file tools.

## Required runbooks

- Startup, health verification, and degraded-state interpretation.
- Broker lock/unlock and capability-specific kill switches.
- Credential issue, rotation, expiry, and revocation.
- Policy validation, atomic reload, rollback, and readback.
- Job cancellation and `UNKNOWN` reconciliation.
- Audit inspection, retention, integrity checks, backup, and restore.
- Upgrade, migration, rollback, uninstall, and stale-authority cleanup.
- Incident response and evidence preservation.

## Current limitation

No runtime or operational command exists. This guide records required operator behavior and must be updated with verified commands only after implementation.
