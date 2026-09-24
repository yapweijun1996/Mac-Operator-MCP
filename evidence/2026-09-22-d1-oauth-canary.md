# D1 OAuth-to-Edge-to-Broker canary evidence — 2026-09-22

## Result

An isolated temporary-directory canary now proves the staging D1 grant across
the Auth, HTTPS Edge, Broker capability projection, approval boundary, and
filesystem/job readbacks. The live personal R1 deployment was not changed.

## Boundary covered

- Auth issues a real authorization-code JWT containing the exact 23-scope D1
  profile.
- Edge verifies the Auth-issued token and requires the D1 initialization
  scopes `mac.control.read` and `mac.files.write`.
- Broker policy grants the owner principal the D1 scopes but enables only eight
  temporary capabilities: `mac_capabilities`, `mac_health`, `mac_job_status`,
  `mac_job_cancel`, `mac_write_file_atomic`, `mac_apply_patch`,
  `mac_git_stage`, and `mac_git_commit`.
- MCP `tools/list` exposes exactly those eight enabled tools; no planned,
  disabled, GUI, task, privileged, or unrelated mutation tool is exposed.
- A write without a matching approval returns `POLICY_DENIED`, writes no file,
  and creates a durable non-secret approval preview.
- An exact owner approval matching tool, target, payload digest, contract, and
  policy permits one atomic write and verified file readback.
- A bounded patch without approval is denied and creates a durable preview;
  exact owner approval permits the patch and verifies changed-path/hash
  readback.
- A Broker-owned queued Job cannot be cancelled without approval; exact owner
  approval cancels only that owner-bound Job and verifies the terminal state.
- A local temporary Git repository proves explicit-path staging and local commit
  through the real bounded Git adapter. A wrong staged digest returns
  `PRECONDITION_FAILED`, leaves the index unchanged, and leaves the Job
  `UNKNOWN`; the approved commit verifies HEAD, empty index, clean worktree,
  and no configured remote.
- An explicit physical-host opt-in additionally exposes two named task profiles
  through the same canary; fixed `/usr/bin/printf` execution, active
  `/bin/sleep` cancellation, Edge revocation to an `UNKNOWN` recovery state,
  Job status, and process-metadata cleanup pass.
  Details are recorded in
  `evidence/2026-09-22-d1-auth-task-canary.md`. The separate opt-in
  `mac_service_control` canary is recorded in
  `evidence/2026-09-22-d1-auth-edge-broker-user-service-canary.md`.
- Audit evidence does not contain the OAuth bearer token.

## Verification

The canary is the `isolated D1 canary binds the Auth grant to Edge tools/list
and owner-approved write` test in `packages/auth/src/auth.test.ts`. The Auth
suite passes 20/20 after this canary. This is staging evidence only: it does
not enable public D1 tools, change the live policy, install services, prove
Developer ID/notarization, or substitute for production rollback, recovery,
revocation-under-active-work, and ChatGPT UI acceptance.
