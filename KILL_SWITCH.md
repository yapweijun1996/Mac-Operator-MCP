# Kill-Switch Runbook

Status: Contract draft; no switch is implemented

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
