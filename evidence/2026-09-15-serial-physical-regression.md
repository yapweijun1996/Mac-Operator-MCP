# Serial Physical-Darwin Regression Evidence

- Source revision: `339d932`
- Date: 2026-09-15
- Host: physical Mac mini, arm64, macOS 26.2 (Build 25C56), Darwin 25.2.0
- Runtime: Node.js v25.5.0
- Scope: non-overlapping full repository test regression

## Command

```text
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
node --test --test-concurrency=1 $(find packages -path '*/dist/*.test.js' \
  ! -name 'broker.test.js' ! -name 'persistence.test.js' \
  ! -name 'privileged-helper-authority-ipc.test.js' | sort)
```

The three excluded suites were already running as long-lived processes and
were not interrupted or restarted. Their results are not inferred by this
record.

## Result

630 tests passed, 0 failed, 0 skipped, 0 cancelled. The serial run exercised
the updated root-owned fixed-adapter executable gate and its writable/owner
negative cases, real sandbox credential/environment/filesystem/network/process
boundaries, temporary-user Edge/Broker LaunchAgent bootstrap and cleanup,
Keychain ACL lifecycle, native IPC, policy/replay/audit persistence, atomic
filesystem writes and crash recovery, helper authority checks, GUI/app
readback, virtualization boundary checks, and authenticated HTTPS Edge flows.

The temporary install smoke created only generated user-domain launchd jobs and
temporary data; it booted both jobs out and confirmed label absence. No
production fixed label was changed.

## Boundary status

This closes a broad serial regression on the physical host and provides
current evidence that the owner gate did not regress non-overlapping adapters.
It does not close the excluded long-running suites, kernel-held executable
descriptor execution, in-syscall remount resistance, production Developer ID
deployment, or task-runner enablement.

## Rollback

Evidence-only change; remove this record if a newer full regression supersedes
it.
