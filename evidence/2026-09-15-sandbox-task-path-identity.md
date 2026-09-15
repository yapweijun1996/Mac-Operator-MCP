# Sandbox task process-path identity evidence

Date: 2026-09-15
Source revision: `2599502` (`fix: bind sandbox tasks to process path identities`)

## Boundary

`SandboxExecTaskRunner` launches a Broker-rendered `sandbox-exec` command whose
argument vector contains the real task executable. The outer ProcessSupervisor
cannot protect that inner path by checking only `/usr/bin/sandbox-exec`, so the
runner now captures the inner executable and cwd device/inode/mode identities
before dispatch. It awaits the startup ownership callback, rechecks both
identities there, and repeats the checks after the supervisor returns. A
changed, missing, or newly symlinked target fails closed; the Broker's Job
handling retains an unresolved outcome when execution-side verification cannot
be trusted.

The physical-Darwin regression creates a canonical temporary task executable,
replaces it after authorization but before the awaited startup callback, and
proves that the runner rejects the replacement rather than publishing the
synthetic success result. The process-supervisor regression also proves an
asynchronous ownership callback is awaited and a failed callback drains the
child before returning.

## Verification

Commands run from the repository root:

```text
npm run lint
npm run build
node --test --test-name-pattern='SandboxExecTaskRunner' packages/broker/dist/sandbox-profile.test.js
node --test packages/broker/dist/process-supervisor.test.js
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
npm run verify:contracts
npm run verify:canonical:native
git diff --check
```

Results:

- Sandbox runner tests: 9 passed, 0 failed.
- Process-supervisor tests: 27 passed, 0 failed.
- Complete physical-Darwin suite: 603 passed, 0 failed, 0 skipped.
- Style, build, contract, native canonical-vector, and diff checks passed.

## Limits

The checks close the implemented startup-window target-swap boundary. They do
not provide a kernel-held descriptor or `fexec` guarantee for a path replaced
after the final readback, and they do not claim resistance to a host-level
filesystem remount performed inside an already-running syscall. The task
runner remains disabled unless its independently reviewed sandbox,
credential, filesystem, network, persistence, and process-tree proof is
accepted.
