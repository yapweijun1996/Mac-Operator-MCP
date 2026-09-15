# Persisted Process Ownership Readback Evidence

Date: 2026-09-15
Source revision: `7ad478c`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T05:54:34Z
Artifact hashes: `packages/broker/src/process-supervisor.ts` SHA-256
`1bac49d45d8da349e4aeb34c36096ef84b73365cb033fe381338ee29c990d8cd`;
`packages/broker/src/process-supervisor.test.ts` SHA-256
`f1ebb78399b2e1ce18367848570077bc62258a4b97a9847af23b65af66b689e7`.

## Decision

Persisted process ownership is an authority input to recovery and signalling.
Only an exact, plain-data identity/snapshot may reach native process observers;
ambiguous or malformed state must fail closed before any signal is sent.

## Implemented controls

- Root identities require exact `pid`, `processGroupId`, and `startTimeMicros`
  fields with the existing safe numeric and same-group invariants.
- Snapshots require exact identity/descendant fields plus the single allowed
  no-fork proof marker; descendant arrays are dense, bounded, ordered, and
  composed of exact plain records.
- Recovery distinguishes a plain snapshot from a legacy identity without
  accepting inherited `identity` properties, then preserves existing native
  PID/start-time and descendant readback fencing.

## Verification

Focused command:

```text
npm run build && node --test packages/broker/dist/process-supervisor.test.js
```

Result: 33 tests passed, 0 failed, 0 skipped. Accessor, inherited, and
unknown-field persisted ownership fixtures fail with stable
`PRECONDITION_FAILED`; process-group, descendant, cancellation, and restart
recovery tests remain green.

## Boundary status

This proves persisted ownership representation integrity only. It does not
prove post-snapshot descendant escape resistance, kernel-level termination
guarantees, credential isolation, production task-runner enablement, or
installed-service recovery. Those gates remain fail-closed and incomplete.
