# Serial physical regression evidence — safe integer parser boundary

Date: 2026-09-15
Host: physical Mac mini, Darwin arm64
Source revisions: `350ebbc`, `6f6bf2f`

## Command

```text
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
  node --test --test-concurrency=1 $(find packages -path '*/dist/*.test.js' \
    ! -name 'broker.test.js' ! -name 'persistence.test.js' \
    ! -name 'privileged-helper-authority-ipc.test.js' | sort)
```

Output was captured at `/tmp/mops-safe-int-physical-regression.log`.

## Result

- tests: 634;
- passed: 634;
- failed: 0;
- skipped: 0;
- cancelled: 0;
- duration: 35,059 ms;
- concurrency: 1.

The run covered the strict canonical JSON parser and authentication vectors,
native filesystem and IPC boundaries, write recovery, approval and authority
ledgers, process supervision, sandbox probes, GUI redaction, virtualization
seams, helper/install-plan boundaries, HTTPS Edge, and temporary packaged
LaunchAgent readback. The pre-existing `broker.test.js`, `persistence.test.js`,
and `privileged-helper-authority-ipc.test.js` processes were observed as live
before the run and were excluded without signalling, restarting, or modifying
them.

## Interpretation

This is fresh host evidence that the safe plain-decimal integer parser change
does not regress the non-overlapping physical suite. It does not close the
excluded long-running test processes, production Developer ID signing,
kernel-held descriptor execution, credential isolation, remount resistance,
remote CI, or final independent security review.
