# D1 mutation boundary probe

- Date: 2026-09-21
- Scope: MOP-102 bounded atomic write and textual patch execution
- Status: physical temporary-root evidence passed; public mutation capability remains disabled
- Host: Darwin arm64, unprivileged Broker

## Probe

`npm run probe:d1:mutations` built the native and TypeScript artifacts, started
the real Broker with a temporary filesystem root, and exercised the mutation
paths through signed Broker requests. The probe used the real
`ApprovalAuthority` to issue a signed, preview-digest-bound trusted-write
approval for each mutation and removed the temporary root after verification.

## Result

```json
{
  "schema_version": "0.1",
  "probe": "d1-mutation-boundary",
  "platform": "darwin",
  "arch": "arm64",
  "physical_temp_root": true,
  "approval_issuer": "verified",
  "unapproved_write": "POLICY_DENIED",
  "atomic_write": {
    "result": "SUCCEEDED",
    "verification": "verified",
    "job_state": "completed"
  },
  "idempotent_retry_reused_job": true,
  "bounded_patch": {
    "result": "SUCCEEDED",
    "verification": "verified",
    "job_state": "completed"
  },
  "postcondition_readback": "verified",
  "audit_raw_content": false,
  "temporary_files_remaining": 0
}
```

This closes the physical temporary-root evidence for the existing atomic-write
and bounded-patch adapters. It does not enable public D1 scopes, prove generic
task executable isolation, or authorize repository-script execution.

## Rollback

The probe only creates and removes a temporary directory. Disable or remove the
probe script and package entry if the evidence is no longer needed; the Broker
mutation adapters and their default-deny policy are unchanged.
