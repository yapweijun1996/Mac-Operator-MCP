# Process-Group Census Evidence

Date: 2026-09-15
Host: physical macOS host used by the repository test harness
Source revision: `ea7b133`
Tool contract version: 0.1
Policy version: 0.1

## Decision

Process ownership observation must continue to cover a detached child after
the kernel reparents it away from the tracked root. The Broker therefore keeps
the existing parent/descendant traversal and supplements it with a bounded
native census of the root's detached process group. The census is an
observation aid only; the Broker remains fail-closed on uncertainty and does
not treat group membership as a complete isolation or termination proof.

## Implemented controls

- `peer_credentials.node` exports `listProcessGroupMembers(processGroupId)`.
- The native observer scans a bounded PID list, reads PID/start-time/group
  identities, returns at most 256 members, sorts by PID, and marks truncation.
- `ProcessTreeTracker` merges descendant and process-group snapshots by PID;
  duplicate identities with different start times, malformed data, observer
  errors, and either truncation state fail closed.
- Recovery and runtime capability gates require the new native export, so an
  older or incomplete addon cannot silently use the weaker observer.
- Existing PID/start-time replacement checks, process-group identity checks,
  post-exit strict readback, and `setsid` handling remain unchanged.

## Verification

Commands:

```text
npm run build
npm run typecheck
npm run lint
node --test --test-concurrency=1 packages/broker/dist/peer-credentials.test.js packages/broker/dist/process-supervisor.test.js
git diff --check
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 node --test --test-concurrency=1 $(find packages -path '*/dist/*.test.js' ! -name 'broker.test.js' ! -name 'persistence.test.js' ! -name 'privileged-helper-authority-ipc.test.js' | sort)
```

Results:

- build, typecheck, lint, and diff checks passed;
- focused process/peer regression: 47 passed, 0 failed, 0 skipped;
- native runtime readback found the current process in its requested group,
  with safe positive start-time identities and `truncated: false`;
- serial physical regression: 638 passed, 0 failed, 0 skipped in 34.8s;
- the three pre-existing long-running suites were excluded and left running
  undisturbed.

## Boundary status

This closes the specific observation gap where a reparented process can leave
the parent-child traversal before the next sample. It does not prove that a
descendant cannot call `setsid()` after the final sample, that process-group
membership is an isolation boundary, that the kernel honors every termination
request, or that child credentials are isolated. Those release gates remain
disabled and fail-closed.
