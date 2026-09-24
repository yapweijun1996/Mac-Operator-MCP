# D1 task execution boundary probe

- Date: 2026-09-21
- Scope: Broker-level named task execution through the fixed system-published sandbox boundary
- Status: physical Darwin arm64 evidence passed; public task capability remains disabled
- Host: unprivileged Broker using `/usr/bin/sandbox-exec`

## Probe

`npm run probe:d1:task` built the native and TypeScript artifacts, created a
temporary task root, and exercised the named task path through signed Broker
requests. The probe used the real `ApprovalAuthority`, a Broker-owned
`TaskProfileRegistry`, and the system-published root-owned executable allowlist
for `/usr/bin/printf` and `/bin/sleep`. The task profiles used a single-process,
no-network sandbox, bounded output and timeout budgets, no credentials, and a
separate protected Broker state root. The temporary root and state directory
were removed after verification.

## Result

```json
{
  "schema_version": "0.1",
  "probe": "d1-task-boundary",
  "platform": "darwin",
  "arch": "arm64",
  "physical_system_published_runner": true,
  "approval_issuer": "verified",
  "unapproved_task": "POLICY_DENIED",
  "task_success": {
    "result": "SUCCEEDED",
    "verification": "verified",
    "stdout_readback": "verified",
    "process_tree_policy": "single_process",
    "job_state": "completed"
  },
  "cancellation": {
    "request_result": "CANCELLED",
    "cancel_result": "SUCCEEDED",
    "cancel_requested": true,
    "termination_observed": true,
    "process_identity_recorded": true,
    "job_state": "cancelled"
  },
  "sandbox_network": "none",
  "protected_persistence_root": "denied-by-default",
  "audit_raw_content": false,
  "public_task_scope": "disabled"
}
```

This closes the physical Broker-level evidence for a narrowly allowlisted
system-published task boundary: named profile resolution, signed approval,
unapproved denial, verified output, process identity capture, active Job
cancellation, terminal cancellation readback, and audit redaction. The probe
does not authorize interpreters, repository scripts, arbitrary executables, or
public `mac_task_run`. Generic descriptor-backed executable selection remains
unproven because this host lacks `fexecve`/`execveat`; the system-published
allowlist is a separate fixed-host boundary.

The probe also exposed and fixed a real Broker race: cancellation increments a
running Job revision before the task returns, so terminal persistence now
reloads the authoritative Job revision instead of writing with a stale one.
The regression test is `mac_task_run reconciles a cancellation revision race
before terminal Job persistence`.

## Rollback

The probe only creates and removes temporary directories. Disable or remove the
probe script and package entry if the evidence is no longer needed; the task
runner remains disabled by default in the production policy.
