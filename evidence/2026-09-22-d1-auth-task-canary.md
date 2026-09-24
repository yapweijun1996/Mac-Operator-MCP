# D1 Auth-to-Edge-to-Broker named-task canary evidence — 2026-09-22

## Result

An explicit physical-host opt-in now verifies named D1 task profiles through
the real Auth-issued token, HTTPS Edge MCP transport, Broker approval boundary,
system-published executable boundary, and Broker Job readback. The live R1
deployment and public D1 grant were not changed.

## Host and gate

- Host: macOS 26.2, arm64.
- Opt-in command: `MOPS_REAL_SANDBOX=1 node --test --test-timeout=120000 packages/auth/dist/auth.test.js`.
- Result: Auth suite 20/20 passed.
- Without `MOPS_REAL_SANDBOX=1`, the default D1 canary keeps `mac_task_run`
  hidden and exposes only the previously verified eight temporary tools.

## Boundary covered

- Auth issues the exact staging D1 JWT; Edge verifies it and MCP discovery
  exposes exactly nine temporary tools for this opt-in, including
  `mac_task_run`.
- The named profile `d1.printf` fixes `/usr/bin/printf`, its SHA-256 content
  identity, fixed argument `d1-auth-task`, task-root cwd, `LANG=C`, no network,
  no credentials, a 5-second timeout, a 1 KiB output cap, and a single-process
  sandbox proof.
- A task call without matching approval returns `POLICY_DENIED` and creates a
  durable non-secret preview.
- An exact owner `trusted_profile` approval permits only that named profile;
  the task returns `d1-auth-task`, `completed`, and verified output.
- Broker Job status returns `completed`, and transient process ownership
  metadata is cleared after readback.
- The named profile `d1.sleep` fixes `/bin/sleep` and is started through the
  same HTTPS MCP path only after exact owner approval. While its Job is
  running with the `sandbox-exec-no-fork-v1` ownership proof, an exact owner
  `mac_job_cancel` approval persists cancellation; the task resolves as
  `CANCELLED`/`CONFLICT`, final status is `cancelled`, and process ownership
  metadata is cleared.
- A second running `d1.sleep` Job is revoked through the Broker's host-lifecycle
  Edge revocation hook after HTTPS MCP admission. The request resolves as
  `CANCELLED`, the Job remains `UNKNOWN` with its verified process ownership
  metadata retained for recovery, and the audit record does not contain the
  revocation reason.
- Audit evidence does not contain the task output or the OAuth bearer token.

## Limits

This is physical staging evidence for the fixed named profile. It does not
enable public task scopes, generic executable selection, repository scripts,
interpreters, arbitrary shell, unattended approval, or live ChatGPT task
calls. Production Developer ID/notarization, installed identity readback,
session/process revocation variants, recovery readback, rollback, and public
enablement remain release gates.
