# Serial physical regression evidence — native Node runtime binding

Date: 2026-09-15
Host: physical Mac mini, Darwin arm64
Source revision: `54d4590`

## Command

```text
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
  node --test --test-concurrency=1 $(find packages -path '*/dist/*.test.js' \
    ! -name 'broker.test.js' ! -name 'persistence.test.js' \
    ! -name 'privileged-helper-authority-ipc.test.js' | sort)
```

Output was captured at `/tmp/mops-native-node-runtime-physical-regression.log`.

## Result

- tests: 637;
- passed: 637;
- failed: 0;
- skipped: 0;
- cancelled: 0;
- duration: 34,182 ms;
- concurrency: 1.

The run includes the new native Node-version loader checks, native IPC,
filesystem/write recovery, process supervision, sandbox, Keychain, helper,
GUI, virtualization, packaged LaunchAgent, and HTTPS Edge boundaries. The
pre-existing `broker.test.js`, `persistence.test.js`, and
`privileged-helper-authority-ipc.test.js` processes were excluded without
signalling, restarting, or modifying them.

## Interpretation

This is fresh physical-host evidence that the exact native Node runtime binding
does not regress the non-overlapping repository suite. It does not prove
Developer ID signing/notarization, cross-host artifact delivery, kernel-held
descriptor execution, or the excluded long-running suites.
