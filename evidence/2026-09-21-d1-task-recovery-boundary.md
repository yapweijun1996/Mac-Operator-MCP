# D1 Task Recovery Boundary Evidence

Date: 2026-09-21
Host: Darwin arm64 physical Mac mini
Probe: `scripts/probe-d1-task-recovery-boundary.mjs`
Command: `npm run probe:d1:task-recovery`

## Result

The physical Broker-level recovery probe passed through the fixed,
system-published `/bin/sleep` task profile. The first Broker instance started
the bounded single-process task and durably recorded the process PID,
process-group ID, start-time identity, task descriptor digest, and
`sandbox-exec-no-fork-v1` ownership proof. The BrokerStore was then closed and
reopened to exercise the restart boundary.

The second Broker instance found exactly one restart-reconciled `UNKNOWN` Job
and drained the exact persisted process identity. The Job remained
`unknown`; recovery did not publish success, replay the task, or clear the
persisted identity. The completion audit readback was
`PROCESS_DRAINED`. The original task observer saw the external termination and
did not return a verified success.

Observed result:

```json
{
  "physical_system_published_runner": true,
  "broker_restart_readback": "verified",
  "exact_pid_start_time_binding": "verified",
  "recovery": {
    "inspected": 1,
    "drained": 1,
    "identity_mismatch": 0,
    "unknown": 0
  },
  "job_after_recovery": "unknown",
  "task_was_not_replayed": true,
  "audit_result": "PROCESS_DRAINED",
  "public_task_scope": "disabled"
}
```

## Boundary claims

- The probe uses a real Darwin arm64 `sandbox-exec` path and fixed root-owned
  `/bin/sleep`; it is not a generic repository-script launcher.
- Recovery binds the persisted PID and start-time identity before signalling;
  no success promotion is possible from process-drain evidence alone.
- The task remains outside the public MCP catalog and OAuth grant.
- This evidence does not prove native descriptor-backed executable selection,
  VM/guest isolation, production packaging, or public task enablement.

## Rollback

The probe creates a temporary task root and Broker SQLite store, never touches
the project repository, and removes both temporary directories in `finally`.
No persistent service, public policy, OAuth grant, or production task profile
was changed.
