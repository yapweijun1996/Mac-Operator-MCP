# Kill-Switch Runbook

Status: Prototype admission, filesystem active-work, durable authority-audit controls, and a separate authenticated authority channel implemented; installed operator runbook remains draft

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

The implemented runbook must identify the trusted operator path, activation and verification commands, affected capability states, active-job handling, audit evidence, recovery prerequisites, and safe re-enable steps. Until then, this document is not an executable runbook.

## Current implementation evidence

The Broker core evaluates both persisted runtime switches and signed-policy kill-switch states. Either source can disable admission; policy cannot override an already-active persisted runtime switch. The global and capability-family primitives reject new matching work, and signed global-disable behavior passes tests. Filesystem workers poll authority during execution, request termination on revocation, revalidate before returning success, and emit a failed completion audit with `CANCELLED`. Broker-owned queued jobs can be cancelled durably and idempotently; abandoned queued/running jobs reconcile to `cancelled`/`unknown` on restart. Generic switch and revocation changes now append a redacted, hash-linked `intent`/`completion` audit pair in the same persistence transaction as the authority change and queued-job cancellation. A separate owner-only Authority Control IPC now accepts only HMAC-authenticated `set_switch` and `revoke` commands, checks the native peer identity before parsing, persists request/nonce admission across restart, uses an expected-state precondition for switch changes, and provides authenticated switch/revocation readback after a Store/server restart. It is not registered with the MCP Edge and exposes no command execution or capability-grant operation. Installed operator identity distribution, active process-tree termination, and safe re-enable procedures remain unimplemented. Evidence: `evidence/2026-09-15-authority-control-restart-readback.md`.

## Authority Control IPC boundary

The prototype channel is a Broker-local Unix socket selected by the native peer transport. The caller must satisfy the configured UID/GID/PID policy and present a 32-byte-or-longer HMAC key. Commands are newline-delimited JSON with protocol version `0.1`, bounded request size, timestamp/skew and nonce-expiry windows, strict operation/target fields, and durable single-use request/nonce admission. Replays are rejected after Broker restart. `set_switch` requires both `disabled` and `expectedDisabled`; a stale expected state returns `CONFLICT` without changing the switch. `revoke` accepts only the enumerated principal, session, Edge, Edge-key, approval-key, or policy-signer identities. Authority mutations and queued-job cancellations remain transactional; audit evidence records identity, state, and a reason digest rather than the operator text.

This channel is a source-level control boundary, not an installed emergency procedure. Production enablement still requires protected key distribution, launchd ownership/readback, operator recovery instructions, and evidence for active work termination.
