# Kill-Switch Runbook

Status: Prototype admission, filesystem active-work, and durable authority-audit controls implemented; operator runbook remains draft

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

The Broker core evaluates both persisted runtime switches and signed-policy kill-switch states. Either source can disable admission; policy cannot override an already-active persisted runtime switch. The global and capability-family primitives reject new matching work, and signed global-disable behavior passes tests. Filesystem workers poll authority during execution, request termination on revocation, revalidate before returning success, and emit a failed completion audit with `CANCELLED`. Broker-owned queued jobs can be cancelled durably and idempotently; abandoned queued/running jobs reconcile to `cancelled`/`unknown` on restart. Generic switch and revocation changes now append a redacted, hash-linked `intent`/`completion` audit pair in the same persistence transaction as the authority change and queued-job cancellation. Bulk queue cancellation, active process-tree termination, operator commands, restart switch readback, and safe re-enable procedures remain unimplemented.
