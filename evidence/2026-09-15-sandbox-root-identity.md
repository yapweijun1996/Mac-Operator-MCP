# Sandbox filesystem-root identity evidence

Date: 2026-09-15
Source revision: `f562bc2` (`fix: bind sandbox filesystem roots to identities`)

## Boundary

The sandbox renderer grants `file-read*` and `file-write*` access to resolved
Broker-owned filesystem roots. Volume identity alone is insufficient: a root
directory can be renamed and replaced on the same volume while retaining the
same volume identifier. `SandboxExecTaskRunner` now captures each unique root
directory's device, inode, and mode before dispatch, rechecks them from its
awaited startup ownership callback, and repeats the checks after the
supervisor returns. The existing volume identity preflight/final readback is
still required.

The physical-Darwin regression uses a second allowed root that is not the
process cwd, renames it after dispatch begins, recreates the path, and proves
that the runner rejects the replacement instead of publishing a synthetic
success. The Broker close test now waits for active process ownership before
closing, matching the supervisor's explicit capacity-release-on-drain rule.

## Verification

Commands run from the repository root:

```text
npm run lint
npm run build
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 node --test packages/broker/dist/sandbox-profile.test.js
node --test packages/broker/dist/filesystem-executor.test.js
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
npm run verify:contracts
npm run verify:canonical:native
git diff --check
```

Results:

- Sandbox profile tests: 15 passed, 0 failed.
- Filesystem worker capacity test: passed.
- Complete physical-Darwin suite: 604 passed, 0 failed, 0 skipped.
- Style, build, contract, native canonical-vector, and diff checks passed.

## Limits

This closes the implemented directory-path target-swap checks across startup
and final readback windows. It does not provide a kernel-held descriptor or
`fexec` guarantee for changes after the final check, and it cannot prove
resistance to a host-level remount that occurs inside an already-running
syscall. Task execution remains disabled unless the independently reviewed
sandbox and credential-isolation evidence gate is accepted.
