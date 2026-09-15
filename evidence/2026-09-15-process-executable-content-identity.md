# Process executable content identity evidence

Date: 2026-09-15  
Source revision: `a6dfe01` (`fix: detect in-place executable mutations`)

## Boundary

`ProcessSupervisor` now captures executable device, inode, permission mode,
size, mtime, and ctime metadata before spawn, then rechecks it after spawn and
after the awaited startup ownership callback. `SandboxExecTaskRunner` repeats
the executable check on final readback. A regular executable rewritten in place
at the same path and inode therefore fails closed with `POLICY_DENIED` instead
of being treated as the authorized target. Directory identities intentionally
continue to compare only device, inode, and mode because legitimate task writes
change directory timestamps.

The Darwin regression rewrites a canonical temporary executable from the
startup ownership callback without renaming it, then proves that the process
group is drained and the mutation is rejected.

## Verification

Commands run from the repository root:

```text
npm run lint
npm run build
node --test packages/broker/dist/process-supervisor.test.js
MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/sandbox-profile.test.js
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
npm run verify:contracts
npm run verify:canonical:native
git diff --check
```

Results:

- Process-supervisor tests: 28 passed, 0 failed.
- Sandbox-profile tests: 15 passed, 0 failed.
- Complete physical-Darwin suite: 605 passed, 0 failed, 0 skipped.
- Style, build, contract, native canonical-vector, and diff checks passed.

## Limits

The metadata guard catches ordinary in-place writes that update file size or
timestamps. It is not a cryptographic content digest, does not provide a
kernel-held descriptor/`fexec` guarantee, and does not resist an attacker able
to rewrite content while preserving every captured metadata value. Atomic
descriptor execution, remount resistance, and production task enablement
remain open under MOP-086.
