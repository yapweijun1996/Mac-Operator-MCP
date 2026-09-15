# Serial physical-Darwin regression after mount-flag identity hardening

Date: 2026-09-15
Source revision: `eaca6c6`
Host: Darwin 25.2.0, arm64, Node v25.5.0

## Command

```text
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
node --test --test-concurrency=1 $(find packages -path '*/dist/*.test.js' \
  ! -name 'broker.test.js' \
  ! -name 'persistence.test.js' \
  ! -name 'privileged-helper-authority-ipc.test.js' | sort)
```

## Result

```text
tests 633
pass 633
fail 0
skipped 0
cancelled 0
duration_ms 34058.646584
```

The run includes the rebuilt native filesystem adapter with mount flags bound
into `SameFilesystem` and storage-volume IDs, plus the versioned descriptor
launch capability gate. It covers real sandbox, Keychain, temporary
LaunchAgent, native IPC, filesystem/write recovery, helper, GUI,
virtualization, policy/audit, and HTTPS Edge boundaries.

The already-running `broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js` processes were excluded by filename
and left undisturbed. No host configuration, mount, or remount was changed.

## Interpretation

This is a regression result for the implemented boundaries, not proof of
in-syscall remount resistance, kernel-held descriptor execution, production
signing, or task-runner enablement. Those release gates remain open.

## Rollback

Remove this evidence note only; the test run changed no host or runtime state.
