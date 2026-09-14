# Kill-Switch Runbook

Status: Prototype admission, filesystem active-work, durable authority-audit controls, and a separate authenticated authority channel implemented; packaged operator CLI is source-level only and installed runbook remains draft

## Required controls

- Global remote execution disable.
- Mutating capability disable.
- Process/job execution disable.
- App and GUI disable.
- Privileged-helper disable.
- Principal/session/approval revocation.

## Required semantics

Activation rejects new matching requests, cancels queued matching work, rechecks authority immediately before mutation, and requests termination of active cancellable work. Non-interruptible operations declare their behavior and are reconciled before reporting a terminal result. Kill-switch state persists across restart and is visible through bounded health/capability readback.

## Future procedure

The source-level operator path is the bounded `mac-operator-authority` CLI
described below. It is not an installer, does not accept raw key material, and
does not grant capabilities. Installed launchd ownership and active process
termination evidence are still required before this becomes an executable
production runbook.

## Source-level operator procedure

Build the exact reviewed revision, then invoke the Broker package entrypoint
with explicit canonical paths. The key configuration must already be the
exact persisted active revision; the CLI never activates or discovers a key.

```text
node packages/broker/dist/authority-control-cli.js status \
  --database /protected/state/broker.sqlite \
  --socket /protected/run/authority.sock \
  --key-config /protected/config/authority-key.json
```

To disable a family, supply the state you observed and an explicit confirmation
token. The command returns `verified: true` only after authenticated readback:

```text
node packages/broker/dist/authority-control-cli.js set-switch \
  --database /protected/state/broker.sqlite \
  --socket /protected/run/authority.sock \
  --key-config /protected/config/authority-key.json \
  --name process --disabled true --expected-disabled false \
  --reason INCIDENT_CONTAINMENT --confirm set-switch
```

Revocation is similarly bounded and supports principal, session, Edge/key,
authority/helper, policy-signer, approval, and guest-attestation identities:

```text
node packages/broker/dist/authority-control-cli.js revoke \
  --database /protected/state/broker.sqlite \
  --socket /protected/run/authority.sock \
  --key-config /protected/config/authority-key.json \
  --kind session --subject-id session-123 \
  --reason REVOKE_SESSION --confirm revoke
```

After disabling or revoking, inspect capability and job status through their
authenticated readback paths. Do not re-enable while queued work, active work,
or `UNKNOWN` outcomes remain unexplained. Re-enable requires the observed
disabled state as the precondition and a fresh readback:

```text
node packages/broker/dist/authority-control-cli.js set-switch \
  --database /protected/state/broker.sqlite \
  --socket /protected/run/authority.sock \
  --key-config /protected/config/authority-key.json \
  --name process --disabled false --expected-disabled true \
  --reason INCIDENT_RECOVERED --confirm set-switch
```

The CLI prints bounded JSON only. It does not print key bytes, operator text,
command strings, credentials, or audit evidence contents. A failed readback or
transport error is a failed operation; the operator must leave the switch
disabled and reconcile jobs before retrying.

## Current implementation evidence

The Broker core evaluates both persisted runtime switches and signed-policy kill-switch states. Either source can disable admission; policy cannot override an already-active persisted runtime switch. Capability discovery also evaluates those same family switches before advertising an enabled tool, so Edge readback cannot claim a process, network, GUI, destructive, or privileged capability that the Broker would reject. The global and capability-family primitives reject new matching work, and signed global-disable behavior passes tests. Filesystem workers poll authority during execution, request termination on revocation, revalidate before returning success, and emit a failed completion audit with `CANCELLED`. Broker-owned queued jobs can be cancelled durably and idempotently; abandoned queued/running jobs reconcile to `cancelled`/`unknown` on restart. Generic switch and revocation changes now append a redacted, hash-linked `intent`/`completion` audit pair in the same persistence transaction as the authority change and queued-job cancellation. A separate owner-only Authority Control IPC now accepts only HMAC-authenticated `set_switch` and `revoke` commands, checks the native peer identity before parsing, persists request/nonce admission across restart, uses an expected-state precondition for switch changes, and provides authenticated switch/revocation readback after a Store/server restart. It is not registered with the MCP Edge and exposes no command execution or capability-grant operation. Installed operator identity distribution, active process-tree termination, and safe re-enable procedures remain unimplemented. Evidence: `evidence/2026-09-15-capability-kill-switch-readback.md` and `evidence/2026-09-15-authority-control-restart-readback.md`.

## Authority Control IPC boundary

The prototype channel is a Broker-local Unix socket selected by the native peer transport. The caller must satisfy the configured UID/GID/PID policy and present a 32-byte-or-longer HMAC key. Commands are newline-delimited JSON with protocol version `0.1`, bounded request size, timestamp/skew and nonce-expiry windows, strict operation/target fields, and durable single-use request/nonce admission. Replays are rejected after Broker restart. `set_switch` requires both `disabled` and `expectedDisabled`; a stale expected state returns `CONFLICT` without changing the switch. `revoke` accepts only the enumerated principal, session, Edge, Edge-key, approval-key, policy-signer, authority-key, helper-key, or guest-attestation-key identities. Authority mutations and queued-job cancellations remain transactional; audit evidence records identity, state, and a reason digest rather than the operator text.

This channel is a source-level control boundary, not an installed emergency procedure. Production enablement still requires protected key distribution, launchd ownership/readback, operator recovery instructions, and evidence for active work termination.
