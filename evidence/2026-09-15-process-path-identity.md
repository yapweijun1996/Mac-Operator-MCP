# Process path identity evidence

Date: 2026-09-15
Source revision: `5efe002` (`fix: recheck process path identities`)

## Boundary

The Broker's `ProcessSupervisor` rejects non-canonical or symlinked
executables and working directories. During validation it records each
regular target's device, inode, and permission-mode identity. After the child
has been created, and again after the optional startup ownership callback, it
revalidates both paths. A changed, missing, or newly symlinked target aborts
the process group; the denial is returned only when the process has been
drained, otherwise the result is `UNKNOWN_OUTCOME`.

The physical-Darwin regression creates an executable in a canonical temporary
directory, replaces that path from `onStarted`, and proves that the Broker
rejects the post-authorization executable identity change.

## Verification

Commands run from the repository root:

```text
npm run lint
npm run build
node --test packages/broker/dist/process-supervisor.test.js
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
npm run verify:contracts
npm run verify:canonical:native
git diff --check
```

Results:

- Process-supervisor tests: 27 passed, 0 failed.
- Complete physical-Darwin suite: 602 passed, 0 failed, 0 skipped.
- Style, build, contract, native canonical-vector, and diff checks passed.

## Limits

These checks detect target swaps across the validated startup windows; they do
not claim a kernel-held descriptor or `fexec` guarantee for every filesystem
change after the final check. The Broker still relies on its bounded child
process policy, explicit cwd/environment, process-group ownership, timeout,
output cap, cancellation, and post-execution verification.
