# Physical Darwin sandbox regression

Date: 2026-09-15
Source revision: `4b76d46`
Host: Darwin arm64, macOS 26.2, Node v25.5.0

## Command

The built test set was run serially with the explicit physical-sandbox gate
exported to the test processes. The already-running Broker and Persistence
test files were excluded and left undisturbed:

```text
export MOPS_REAL_SANDBOX=1
find packages -path '*/dist/*.test.js' ! -name 'broker.test.js' ! -name 'persistence.test.js' -print0 | xargs -0 node --test --test-concurrency=1
```

## Result

```text
tests 595
pass 593
fail 0
skipped 2
```

The run exercised the real macOS sandbox environment, protected-surface and
credential-canary denial, single-process fork/`setsid` denial, selected TCP
and UDP loopback allowlists, and active cancellation/process-group cleanup.
The two skips are explicit host gates for real Keychain ACL mutation and
temporary LaunchAgent installation. No production capability was enabled and
no persistent service or credential was modified.

This closes only the applicable physical sandbox regression evidence. It does
not prove production credential isolation, remount resistance, installed
launchd lifecycle, Developer ID provenance, root helper execution, or final
P0/P1 release approval.
