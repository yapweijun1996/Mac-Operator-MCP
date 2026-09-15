# Process Environment Secret-Value Boundary Evidence

Date: 2026-09-15

Source revision: `98b36ac`

## Boundary

`ProcessSupervisor` already rejects secret-shaped environment names and
requires an explicit profile allowlist. The shared policy now also rejects
known token, credential, and authorization signatures in allowlisted
environment values before local process or virtualization guest dispatch;
guest task arguments use the same protected-option check. This prevents a
generic profile variable or argument from being used as an opaque credential
channel while preserving the existing explicit environment model.

## Verification

- `npx tsc -b packages/broker/tsconfig.json --pretty false`: passed.
- `node --test --test-timeout=120000 packages/broker/dist/process-supervisor.test.js packages/broker/dist/task-profile.test.js packages/broker/dist/virtualization-guest-executor.test.js`:
  51 passed, 0 failed, 0 skipped.
- `npm run lint`: passed for 617 tracked files.
- `git diff --check`: passed.

This is a local process-boundary hardening check. It does not prove production
sandbox credential isolation, native credential-store separation, or enable
`mac_task_run`; those release gates remain open.
