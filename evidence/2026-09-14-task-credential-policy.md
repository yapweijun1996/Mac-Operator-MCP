# Task Credential Policy Evidence

Date: 2026-09-14
Scope: Broker TaskProfile contract and execution boundary; no credential contents opened

## Commands

```text
npm run typecheck
npm run build
MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/task-profile.test.js packages/broker/dist/task-runner.test.js packages/broker/dist/sandbox-profile.test.js
MOPS_REAL_SANDBOX=1 npm test
```

## Observed result

- Typecheck and build passed.
- Focused task-profile/runner/sandbox suite: 17/17 passed.
- Full real-sandbox suite: 445/446 passed, 0 failed, 1 explicit host-boundary/opt-in skip.

## Boundary

`TaskProfile` and `ResolvedTaskProfile` now carry `credentialPolicy`. The
current schema accepts only `none`, resolves an omitted legacy field to
`none`, and rejects unsupported values before profile registration. The
Broker-rendered Seatbelt profile and `requireTaskIsolationProof` repeat the
same fail-closed check before a runner can launch.

Process environments remain explicit profile data and are independently
restricted to safe, non-secret keys. No task profile can request Broker,
Edge, user, Keychain, SSH, cloud, signing, or other credential material.

## Limitations

This proves a machine-enforced no-credential task contract and dispatch gate.
It does not prove the contents of real credential stores, remount resistance,
post-snapshot descendant ownership, crash attribution, or production isolation
of deprecated `sandbox-exec`; `mac_task_run` remains disabled by default.
