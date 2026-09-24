# Operations Guide

Status: Draft; bounded authority commands are available through the source-level CLI and the disabled-by-default owner proxy service

## Operator responsibilities

Monitor Edge, Broker, persistence, audit, jobs, disk budgets, policy version, credential expiry, and helper compatibility. Apply authority changes through an authenticated operational workflow. Never edit production state through generic model-facing file tools.

## Required runbooks

- Startup, health verification, and degraded-state interpretation.
- Broker lock/unlock and capability-specific kill switches.
- Credential issue, rotation, expiry, and revocation.
- Policy validation, atomic reload, rollback, and readback.
- Job cancellation and `UNKNOWN` reconciliation.
- Audit inspection, retention, integrity checks, encrypted archive export, backup, and restore. See [AUDIT_ARCHIVE_RUNBOOK.md](AUDIT_ARCHIVE_RUNBOOK.md).
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

## Stable operator LaunchAgent

The optional `mac-operator-authority-service` is the stable owner-domain proxy.
It loads the same protected `broker-service.json` as Broker startup, accepts
only owner UID/GID peers on `authorityOperatorSocketPath`, and forwards signed
commands to the Broker-owned `authorityControlSocketPath`. Broker startup binds
the latter to the exact operator LaunchAgent PID/start-time identity. The
read-only plan command is:

```sh
npm run plan:macos:authority -- --manifest /absolute/path/authority-manifest.json --development-probe
```

The plan includes fixed install, rollback, and uninstall actions but never
writes a plist or invokes `launchctl`. Production signing, package installation,
live readback, and recovery evidence remain required before enablement.

The host-owned three-component coordinator uses `Authority -> Edge -> Broker`
for install, upgrade, and rollback because Broker startup binds both stable
peer identities; uninstall uses the exact reverse and recovers completed
components in reverse order. Authority has a dedicated lifecycle readback and
is never substituted with Broker status.

After a service restart, use the same owner-only primary/inverse manifest pair
with the read-only readback mode. It performs no plist, launchd, authority, or
capability mutation and returns success only after every planned component
passes its launchd, process, plist, signature, and status-channel readback:

```sh
npm run readback:macos:launchagents -- \
  --manifest /absolute/path/PRIMARY.json \
  --recovery /absolute/path/INVERSE.json \
  --confirm install --readback
```

An absent or mismatched component fails closed. This is restart/readback
evidence, not proof of Developer ID signing, persistent production
installation, or active-process termination.

The apply controller also persists a bounded owner-only deployment journal at
`.macos-launchagent-deployment.journal.json` inside the planned install root.
It is written with a same-directory temporary file, `fsync`, atomic rename,
and descriptor/readback checks. The journal contains only the operation,
manifest digest, dependency order, component completion state, and recovery
state. A controller crash therefore leaves an explicit `in-progress` record
for the next readback; a `recovery-required` record is never reported as
healthy. The install root must already be an owner-only directory; the journal
does not create or broaden package permissions.

The owner-invoked apply handoff accepts either the legacy Edge/Broker manifest
or a three-component primary/inverse pair. A three-component pair must bind
the same `authorityConfigPath` and `authorityOperatorSocketPath` in both
manifests; its authority-control socket argument is the owner proxy socket,
not the Broker-owned authority socket.

## Completion audit

Run `npm run verify:completion` before describing the service as production
ready. The command emits a versioned, redacted JSON record and checks the
current evidence set plus the read-only physical-host release, Accessibility,
and persistent-service gates. It exits non-zero while any gate is incomplete.
It does not grant permissions, install services, load secrets, or enable
capabilities.

## Current limitation

The source tree now contains a separate HMAC-authenticated `PolicySignerIpcServer` for reload, rollback, and revocation, plus a code-level operator proxy and LaunchAgent plan. No operator service is installed or enabled by default. This guide must be updated with verified production startup/readback commands after signing, packaging, and native caller identity are accepted.

## Local runtime lifecycle

`LocalBrokerRuntime` is the in-process lifecycle boundary used by a future packaged service. It starts the Broker IPC channel before separate operator channels, closes started channels in reverse order, serializes concurrent lifecycle calls, and enters `failed` when cleanup itself fails so an explicit retry is required. It does not own the SQLite store, load secrets, install launchd persistence, or enable capabilities; those responsibilities remain with the future packaging entrypoint and accepted ADR-0007 configuration.

The packaged service must instantiate `BrokerServiceEntrypoint` with `createMacOsNativeBrokerRuntime`, which constructs `MacOsNativeBrokerIpcServer` for the Edge-to-Broker channel, and must pass native `peerPolicy` to the policy-signer and approval channels. The launchd renderer emits no environment or privilege fields. The legacy `BrokerIpcServer`/`peerCredentialVerifier` paths remain compatibility prototypes because they read Node's private socket handle; production startup must record the native module, Node version, caller PID policy, socket modes, and bounded service readback.
