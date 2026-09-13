# Broker child-process environment boundary evidence

- Source commit: `e9d8570`
- Host: Mac mini M4, Darwin arm64, Node `v25.5.0`
- Scope: explicit child-process environment construction and task-profile
  validation; no credential access, service installation, or network mutation

## Implemented boundary

The Broker never inherits the parent environment for a child process. A shared
environment-key policy now rejects secret-shaped names and execution-control or
dynamic-loader variables such as `PATH`, `NODE_OPTIONS`, `NODE_PATH`,
`DYLD_*`, `LD_*`, `PYTHONPATH`, `RUBYOPT`, `BASH_ENV`, and `NPM_CONFIG_*`.
Task profiles use the strict policy. The lower-level `ProcessSupervisor` allows
only the exact non-secret keys required by fixed Broker-owned Git and Docker
adapters (`HOME`, the bounded Git config keys, `DOCKER_CONFIG`, and
`DOCKER_HOST`); arbitrary `GIT_*` or `DOCKER_*` names are not accepted.

## Verification

- ProcessSupervisor rejects `NODE_OPTIONS` even when the caller supplies an
  environment allowlist.
- TaskProfileRegistry rejects `PATH` and `NODE_OPTIONS` profile entries.
- Existing real-Mac sandbox smoke confirms controller-secret, `HOME`,
  `SSH_AUTH_SOCK`, and `AWS_PROFILE` are unset in the child, while the
  ProcessSupervisor test confirms a non-stdio parent descriptor is not visible.
- `npm test`: 387 tests, 384 passed, 3 opt-in sandbox tests skipped.
- `MOPS_REAL_SANDBOX=1 npm test`: 387 tests, 387 passed, 0 skipped.
- `npm run typecheck -- --pretty false`, `npm run verify:contracts`,
  `npm audit --omit=dev --audit-level=high`, and `git diff --check` pass.

## Limits

This closes an environment-injection boundary; it is not proof of real
Keychain/credential-content isolation, persistence isolation, sandbox escape
resistance, or production `mac_task_run` enablement. Those remain gated by
MOP-086 and the L2 release criteria.
