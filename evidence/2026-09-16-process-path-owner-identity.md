# Process Path Owner-Identity Evidence

- Date: 2026-09-16
- Host: physical macOS host used by the repository test harness
- Source revision: `138b6ed`
- Contract/policy versions: 0.1
- Evidence class: local and physical process-boundary regression

## Decision

Treat executable and working-directory owner UID/GID as part of the authorized
process-path identity. A path that keeps its device, inode, mode, and content
but changes ownership after authorization is a target-integrity failure.

## Implemented controls

`assertProcessPathIdentityStable` now compares `ownerUid` and `ownerGid` in
addition to device, inode, mode, size, timestamps, and executable content
digest. The check applies to both executable and cwd identities before and
after a Broker-supervised child starts. The regression mutates the expected
owner identity and requires the stable `POLICY_DENIED` result without spawning
work.

## Verification

Focused command:

```text
npm run build
node --test --test-concurrency=1 packages/broker/dist/process-supervisor.test.js
npm run lint
npm run typecheck
git diff --check
```

Result: 37/37 process-supervisor tests passed, with no skips or failures.

The serial physical regression ran with install, sandbox, and Keychain opt-ins
and passed 640/640 tests, with zero skips and failures. The pre-existing
long-running Broker, persistence, and privileged-helper IPC suites were
excluded and left undisturbed.

Artifact SHA-256:

```text
packages/broker/src/process-supervisor.ts
00777634f67ea8d68567336570c9a7ba3e00a430c84c4de7cc0ce173acbb15a6
packages/broker/src/process-supervisor.test.ts
498617082c4e30885fdbca842fde48174f405744c43c66e92389e00be1fd01d8
```

## Boundary status

This closes the previously omitted ownership-field comparison for supervised
process paths. It does not prove kernel-held mount isolation, PID-reuse timing
outside the observer window, post-snapshot session escape, or production
`mac_task_run` enablement.
