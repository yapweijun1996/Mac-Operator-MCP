# Sandbox Keychain ACL Canary Evidence

- Date: 2026-09-16
- Host: physical Mac mini, macOS/Darwin arm64
- Source revision: `bc5ee74`
- Contract/policy versions: 0.1
- Evidence class: opt-in real-host security regression; partial

## Decision

Record one real ACL-bound credential-path denial for the experimental
`SandboxExecTaskRunner`. Keep MOP-086 and MOP-045 blocked: this canary does not
prove complete credential-surface isolation or authorize production
`sandbox-exec`/`mac_task_run`.

## Boundary exercised

The test provisions a synthetic Broker-owned Keychain generic-password item
through the native Keychain authentication-key path. The item is bound to
`process.execPath` and addressed by a random account identifier. A task started
by the runner invokes the fixed executable `/usr/bin/security` with
`find-generic-password -s <service> -a <account> -w`. The sandbox denies the
lookup; the result is non-success and stdout is empty. The test never prints
the item value. Cleanup retires the item using its digest in a `finally` path.

## Verification

Focused command:

```text
MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 node --test --test-concurrency=1 packages/broker/dist/sandbox-profile.test.js
```

Result: 17/17 passed, 0 skipped, 0 failed.

Serial physical regression:

```text
npm run typecheck
npm run lint
git diff --check
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 node --test --test-concurrency=1 <all allowed dist test files>
```

Result: 639/639 passed, 0 skipped, 0 failed. The pre-existing long-running
`broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js` suites were excluded and not
interrupted. `npm run verify:matrix` and `npm run verify:docs` also pass after
the documentation update.

## Artifact readback

SHA-256 digests captured for the implementation artifacts:

```text
packages/broker/src/sandbox-profile.test.ts
f39f518778adadedc571ebcd50a0016e3dba8ffc08eba843802d4d7b77d5ffe7
packages/broker/src/task-runner.ts
0885339536680b9a9556814c68a75e1c33b880e1faae5688a8899db0456fa556
packages/broker/src/credentials.ts
56f59f0369bc5fee438c71976d59c2ced0b500d7bef09e69752c408f82972155
```

## Residual boundary

The result closes only the tested ACL-bound generic-password path. It does not
cover other Keychain APIs, controller credential stores, arbitrary task
executables, Docker or persistence escape, remount resistance,
post-snapshot `setsid` ownership, crash/restart cleanup, installed launchd
packaging, signing provenance, or production task-runner enablement.
