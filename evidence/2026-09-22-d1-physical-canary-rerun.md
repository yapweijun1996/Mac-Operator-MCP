# D1 Physical Canary Rerun

Date: 2026-09-22

Status: `PASSED / STAGING ONLY`

The three physical Darwin arm64 D1 canaries were rerun after the production
exposure-gate changes:

- `node scripts/probe-d1-mutation-boundary.mjs`: unapproved write was
  `POLICY_DENIED`; atomic write and bounded patch completed with verified
  readback; idempotent retry reused the Job; no temporary files remained.
- `node scripts/probe-d1-git-boundary.mjs`: unapproved staging was
  `POLICY_DENIED`; explicit staging and local commit completed with verified
  HEAD/index/worktree readback; staged-digest mismatch preserved the index and
  returned an `UNKNOWN` Job; no remote operation was configured.
- `node scripts/probe-d1-task-boundary.mjs`: unapproved task was
  `POLICY_DENIED`; the fixed system-published runner completed the named task,
  cancellation observed process termination, and the public task scope stayed
  disabled.

All probes use disposable temporary state and remove it on completion. The
production exposure gates remain separate: these canaries do not make D1
public, install services, change OAuth grants, or alter macOS permissions.
