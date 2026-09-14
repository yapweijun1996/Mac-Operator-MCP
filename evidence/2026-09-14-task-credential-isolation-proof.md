# Task credential-isolation proof evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: L2 child-process isolation proof schema; no credential contents opened

## Decision

`TaskIsolationProof` now carries a mechanism-bound credential proof instead of
only the generic `credentials: "isolated"` marker:

- `sandbox-exec-empty-env-deny-secret-zones-v1` for the experimental host
  sandbox; and
- `virtualization-no-host-credentials-v1` for a future guest-backed runner.

Validation rejects a proof whose credential statement does not match its
selected mechanism. The proof remains host-owned and is checked against the
resolved profile before dispatch; MCP task arguments cannot supply it.

## Verification

```text
npm run build
node --test packages/broker/dist/task-runner.test.js packages/broker/dist/sandbox-profile.test.js
```

The focused runner/sandbox suite passed 21 tests: 18 passed and 3 explicit
Darwin opt-in tests skipped on the non-Darwin execution context. The suite
covers mechanism mismatch, malformed credential proof, profile binding, and
the existing explicit-environment/secret-zone sandbox checks.

## Limitations

This is a stronger machine-checked proof contract, not proof that deprecated
`sandbox-exec` is a production-grade credential boundary. Real credential
store isolation, remount resistance, post-snapshot process ownership, and a
production task runner remain release gates; `mac_task_run` stays disabled by
default.
