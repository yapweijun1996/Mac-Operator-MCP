# Task Profile Request Snapshot Evidence

Date: 2026-09-15
Source revision: `04f77eb`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T05:08:30Z
Artifact hashes: `packages/broker/src/task-profile.ts` SHA-256
`0646f35f6c25b1f23d290240e53e420312455ed9e8aacf2f095c445939639043`

## Finding and fix

`TaskProfileRegistry.resolve()` performs asynchronous canonical cwd, allowed
root, and executable readback. The request object was still caller-owned when
argument matching and process construction ran after those awaits. A caller
could therefore change the request arguments after target authorization.

The registry now validates and copies the plain request before the first
filesystem await. Profile selection, cwd checks, argument matching, and the
resolved process request use only this snapshot. The profile itself remains a
registry-owned clone.

## Verification

Focused command:

```text
node --test packages/broker/dist/task-profile.test.js
```

Result: 6 tests passed, 0 failed, 0 skipped. The hostile mutation fixture
changes the argument immediately after `resolve()` starts; the resolved
process still contains the original allowlisted argument.

Non-overlapping package regression (excluding the two pre-existing long-lived
broker/persistence test processes): 518 tests total, 512 passed, 6 skipped,
0 failed.

## Boundary status

This is local task-request TOCTOU evidence. It does not prove kernel
sandboxing, credential or persistence isolation, VM/guest attestation,
production resource behavior, or `mac_task_run` enablement. Those gates remain
fail-closed and disabled.
