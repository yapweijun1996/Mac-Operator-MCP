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

## Incident note: personal service down after reboot (2026-10-06)

**Symptom.** After a Mac restart, pm2 `mac-operator-personal` sat in `waiting restart` (70 restarts), nothing listened on `127.0.0.1:3443`, and auto-deploy logged `mac-operator-personal is not online`.

**Root cause.** The installed profile was `v2` (development). Startup builds a Docker inspector against the pinned socket `~/.docker/run/docker.sock`. Docker Desktop did not come up after the reboot, so startup threw `ENOENT` and `personal-service.ts` swallowed it into the generic `Personal service failed closed` message. `GUI_HELPER_UNAVAILABLE` in the same log is only a warning.

**Diagnosis tip.** The real error is hidden by the catch in `main()`. Run the service in the foreground with a preload that wraps `Promise.prototype.catch` and prints the rejection reason; do not edit the release directory.

**What was tried.**
- OrbStack as the engine: its socket is `~/.orbstack/run/docker.sock` and the code does not hard-code Docker Desktop (peer identity is read at startup; the socket path must be a real path, not a symlink). The 17 physical container checks passed there with a freshly built image. The runtime config pins `engineId` and `imageId`, so both must change, and `acceptance.json` needs all 16 checks, including the two Codex end-to-end checks.
- The Codex end-to-end checks failed because the Codex child process exited (`CODEX_PROCESS_EXITED`). The cause is not yet known, so no new `acceptance.json` was produced and no production config or policy was changed.

**Recovery taken.** Rolled back to the Docker-free G1 profile using the recorded launch config in `MacOperator-o1-20261001a/rollback-launch.json`: release `personal-20260925-g1a`, data root `MacOperator-g1-20260925a`, same pm2 flags as auto-deploy, then `pm2 save`. Public `/mcp` returns 401 and OAuth metadata is served. The V2/O1 data root and a full backup (`MacOperator/backups/pre-orbstack-20261006-071421`) are untouched.

**Consequences of the rollback.**
- The OAuth grants issued by the V2 installation do not carry over, so the ChatGPT/Claude connector must be reconnected.
- The development tools (`mac_task_run`, `mac_test_run`, `mac_build_run`, `mac_codex_run`) are not available under G1.
- Auto-deploy is paused by `MacOperator/auto-deploy/PAUSE`. Remove that file only when the intended release and profile are live again.

**Leftovers.** All temporary artifacts from the OrbStack attempt (probe script, local test branches and worktrees in `cloudflare-tunnel-server-001`, test image, evidence directory) were removed. The pre-attempt backup `MacOperator/backups/pre-orbstack-20261006-071421` is kept.

**Why the Codex end-to-end checks failed (resolved diagnosis).** Not the engine and not Codex. The snapshot copied into the container is filtered by the broker secret scanner (`secret-policy.js`, content pattern 29: a secret-like name followed by `:` or `=` and an 8+ character value). 14 files in the YAP `scripts/` directory are filtered out, including `scripts/test-isolation.test.js` (lines 45-46: `DB_PASSWORD: PRIVATE_VALUE`, `OPENAI_API_KEY: PRIVATE_VALUE`). The registered profile `yap.test-isolation` runs that file, so it would fail under V2 on any engine until the YAP test is rewritten to build those names from an array instead of `NAME: value` pairs. Do not loosen the scanner.

**Open follow-ups.** Decide whether V2 is needed; if so, fix the YAP test as above, rebuild the image on OrbStack, re-run the 16-check acceptance, then run the offline `development --enable` upgrade; or make Docker an optional dependency so a missing engine only disables the container tools instead of failing startup.
