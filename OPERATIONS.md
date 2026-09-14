# Operations Guide

Status: Draft; bounded authority commands are available in the source-level Broker package CLI

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

The persistence-specific order, preconditions, rollback path, and final
readback are recorded in [PERSISTENCE_CUTOVER.md](PERSISTENCE_CUTOVER.md).

## Authority control CLI

After `npm run build`, the package exposes
`node packages/broker/dist/authority-control-cli.js` (or the package bin
`mac-operator-authority`). It accepts only `status`, `set-switch`, and
`revoke`; all paths are explicit canonical owner-only paths, the key is loaded
only through the activated `AuthorityControlKeyManager`, and mutations require
an expected state plus an exact `--confirm` token. Every mutation performs an
authenticated readback before returning `verified: true`. Use the commands in
`KILL_SWITCH.md`; never pass a key, command, executable, or capability grant on
the command line.

The CLI is an operator interface, not a production install proof. It does not
replace launchd identity, job-status reconciliation, or active process-tree
termination evidence.

## Current limitation

The source tree now contains a separate HMAC-authenticated `PolicySignerIpcServer` for reload, rollback, and revocation, but no installed launchd service or operator CLI is shipped. This guide records required operator behavior and must be updated with verified install/startup/readback commands after packaging and native caller identity are accepted.

## Local runtime lifecycle

`LocalBrokerRuntime` is the in-process lifecycle boundary used by a future packaged service. It starts the Broker IPC channel before separate operator channels, closes started channels in reverse order, serializes concurrent lifecycle calls, and enters `failed` when cleanup itself fails so an explicit retry is required. It does not own the SQLite store, load secrets, install launchd persistence, or enable capabilities; those responsibilities remain with the future packaging entrypoint and accepted ADR-0007 configuration.

The packaged service must instantiate `BrokerServiceEntrypoint` with `createMacOsNativeBrokerRuntime`, which constructs `MacOsNativeBrokerIpcServer` for the Edge-to-Broker channel, and must pass native `peerPolicy` to the policy-signer and approval channels. The launchd renderer emits no environment or privilege fields. The legacy `BrokerIpcServer`/`peerCredentialVerifier` paths remain compatibility prototypes because they read Node's private socket handle; production startup must record the native module, Node version, caller PID policy, socket modes, and bounded service readback.
