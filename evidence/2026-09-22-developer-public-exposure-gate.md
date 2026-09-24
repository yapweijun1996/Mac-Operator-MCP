# Developer Mutation Public Exposure Gate

Date: 2026-09-22

Status: `IMPLEMENTED / NOT ENABLED`

Production Broker startup now applies a host-owned readiness gate to:

- `mac_write_file_atomic`
- `mac_apply_patch`
- `mac_git_stage`
- `mac_git_commit`
- `mac_job_cancel`

Each tool is classified as `unavailable`, `staging-only`, or `production`.
Production startup defaults the gate to `unavailable` and rejects an enabled
policy unless the explicit state is `production`, before any public listener is
published. The Broker also projects these tools as runtime-unavailable and
rejects requests before approval consumption when the gate is not production.
`mac_task_run` remains governed by its separate TaskRunner gate.

The owner-only `broker-service.json` startup configuration now accepts the
same strict readiness enum, and the fixed `runBrokerServiceMain` entrypoint
passes it into Broker startup. Missing fields still resolve to `unavailable`;
unknown values are rejected before authority restoration or listener startup.

When either GUI or D1 exposure is set to `production`, startup additionally
requires a fresh owner-only `macos-host-readiness-v1` record. The record is
validated for exact shape, current UID/platform/architecture, ten-minute
freshness, and the requested release/GUI readiness. Generate it with
`npm run record:host-readiness -- <absolute-path>`; a blocked host record is
written safely but still causes production startup to fail closed.
Detailed evidence: `evidence/2026-09-22-host-readiness-evidence-gate.md`.

Verification:

- `npm run build` passed.
- Focused Broker/readiness regression passed: 89 passed, 6 skipped, 0 failed.
- Startup configuration regression passed: 2 passed, 0 failed.
- Host-readiness validation and startup fail-closed regression covers missing,
  blocked, stale, cross-host, and inconsistent evidence with 0 failures.
- Physical D1 canary rerun passed for mutation, Git, and named-task boundaries;
  see `evidence/2026-09-22-d1-physical-canary-rerun.md`.
- Full repository regression passed: 1,089 total; 1,074 passed, 15 skipped,
  0 failed.
- No live R1 process, OAuth grant, policy, filesystem, permission, launchd
  label, or deployment state was changed.

This is a production exposure control, not production readiness evidence. The
physical host still lacks a valid Developer ID identity and persistent
production lifecycle proof, so D1 mutation tools remain disabled in the live
deployment.
