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

The source tree now contains a separate HMAC-authenticated `PolicySignerIpcServer` for reload, rollback, and revocation, but no installed launchd service or operator CLI is shipped. This guide records required operator behavior and must be updated with verified install/startup/readback commands after packaging and native caller identity are accepted.

## Local runtime lifecycle

`LocalBrokerRuntime` is the in-process lifecycle boundary used by a future packaged service. It starts the Broker IPC channel before separate operator channels, closes started channels in reverse order, serializes concurrent lifecycle calls, and enters `failed` when cleanup itself fails so an explicit retry is required. It does not own the SQLite store, load secrets, install launchd persistence, or enable capabilities; those responsibilities remain with the future packaging entrypoint and accepted ADR-0007 configuration.

The packaged service must instantiate `MacOsNativeBrokerIpcServer` for the Edge-to-Broker channel. The legacy `BrokerIpcServer` path remains a compatibility prototype because its verifier reads Node's private socket handle; production startup must record the native module, Node version, caller PID policy, socket mode, and readback evidence.
