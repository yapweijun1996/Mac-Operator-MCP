# D1 Git mutation boundary probe

- Date: 2026-09-21
- Scope: explicit Git staging and local commit execution
- Status: physical temporary-repository evidence passed; public mutation capability remains disabled
- Host: Darwin arm64, unprivileged Broker

## Probe

`npm run probe:d1:git` built the native and TypeScript artifacts, created a
temporary Git repository, and exercised the Git mutation paths through signed
Broker requests. The probe used the real `ApprovalAuthority` to issue signed,
preview-digest-bound trusted-write approvals. The Broker used the fixed
system `git` adapter with explicit path arguments and a staged-diff digest
precondition; the temporary repository and separate Broker state directory were
removed after verification.

## Result

```json
{
  "schema_version": "0.1",
  "probe": "d1-git-boundary",
  "platform": "darwin",
  "arch": "arm64",
  "physical_temp_git_repo": true,
  "approval_issuer": "verified",
  "unapproved_stage": "POLICY_DENIED",
  "explicit_stage": {
    "result": "SUCCEEDED",
    "verification": "verified",
    "staged_paths": [
      "README.md"
    ],
    "job_state": "completed"
  },
  "staged_digest_precondition": {
    "result": "PRECONDITION_FAILED",
    "job_state": "unknown",
    "index_preserved": true
  },
  "local_commit": {
    "result": "SUCCEEDED",
    "verification": "verified",
    "precondition": true,
    "head_readback": "verified",
    "staged_index_empty": true,
    "working_tree_clean": true,
    "job_state": "completed"
  },
  "remote_operations": "not configured",
  "audit_raw_content": false
}
```

The probe verifies a physical local stage/commit path, signed approval binding,
explicit staged-diff preconditions, conservative `UNKNOWN` handling after a
failed commit readback path, Broker Job status, HEAD/index/worktree readback,
and audit redaction. The adapter still exposes no remote, push, force-reset, or
implicit all-files operation. This does not enable public D1 scopes, prove
generic task executable isolation, or authorize repository-script execution.

## Rollback

The probe only creates and removes a temporary Git repository and separate
temporary Broker state. Disable or remove the probe script and package entry if
the evidence is no longer needed; the Broker Git adapters and their
default-deny policy are unchanged.
