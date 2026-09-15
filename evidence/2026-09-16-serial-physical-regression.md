# Serial physical regression evidence

- Source revision: `d3ebdf3`
- Working tree: clean before the evidence-only documentation update
- Host: Darwin `25.2.0`, arm64; macOS `26.2` build `25C56`
- Node: `v25.5.0`
- Command:

  ```text
  MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
    node --test --test-concurrency=1 $(find packages -path '*/dist/*.test.js' \
      ! -name 'broker.test.js' ! -name 'persistence.test.js' \
      ! -name 'privileged-helper-authority-ipc.test.js' | sort)
  ```

- Result: 653 tests, 648 passed, 0 failed, 5 skipped, 0 cancelled.
- The five skips are the explicit real-sandbox probes gated by the unavailable
  host-owned Darwin descriptor executable launcher. No skipped test was
  converted into a pass, and no runtime capability was enabled.
- The three existing long-running suites were excluded and left running:
  `broker.test.js`, `persistence.test.js`, and
  `privileged-helper-authority-ipc.test.js`.
- Scope: this is a serial physical regression readback for the implemented
  boundaries. It does not prove native immutable descriptor execution,
  remount resistance, production credential/process isolation, installed
  launchd/helper signing, or capability enablement.

## Rollback

Revert the documentation-only commit that adds this evidence. No installed
service, host configuration, signing key, or credential store was changed.
