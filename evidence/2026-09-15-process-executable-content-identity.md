# Process executable content identity evidence

Date: 2026-09-15
Source revision: `a0e62e2` (`fix: bind executable content identity`)

## Boundary

`ProcessSupervisor` now captures executable device, inode, permission mode,
size, mtime, ctime, and a SHA-256 content digest before spawn. The digest is
read from an `O_NOFOLLOW` descriptor in bounded 1 MiB chunks (64 MiB maximum),
with descriptor metadata checked before and after the read. The executable
identity is rechecked after spawn and after the awaited startup ownership
callback; `SandboxExecTaskRunner` repeats it on final readback. A regular
executable rewritten in place at the same path and inode therefore fails closed
with `POLICY_DENIED` instead of being treated as the authorized target.
Directory identities intentionally continue to compare only device, inode, and
mode because legitimate task writes change directory timestamps.

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
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 node --test --test-concurrency=1 packages/*/dist/**/*.test.js
npm run verify:contracts
npm run verify:canonical:native
git diff --check
```

Results:

- Process-supervisor tests: 29 passed, 0 failed.
- Sandbox-profile tests: 15 passed, 0 failed.
- Complete serial physical-Darwin suite: 606 passed, 0 failed, 0 skipped.
- Style, build, contract, native canonical-vector, and diff checks passed.

## Limits

The digest is computed from a bounded descriptor read, but the child is still
started by path after the final check. It does not provide a kernel-held
descriptor/`fexec` guarantee, does not close the post-read mutation window, and
does not resist remount or filesystem replacement after the final readback.
Atomic descriptor execution, remount resistance, and production task
enablement remain open under MOP-086.
