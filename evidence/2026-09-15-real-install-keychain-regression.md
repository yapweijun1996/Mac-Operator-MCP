# Physical Keychain and LaunchAgent regression

Date: 2026-09-15
Source revision: `4ab7d59`
Host: Darwin arm64, macOS 26.2, Node v25.5.0, uid 501

## Command

The built test set was run serially with all three explicit physical-host
gates. Broker and Persistence test files that were already running were
excluded and left undisturbed:

```text
export MOPS_REAL_INSTALL=1
export MOPS_REAL_KEYCHAIN=1
export MOPS_REAL_SANDBOX=1
find packages -path '*/dist/*.test.js' ! -name 'broker.test.js' ! -name 'persistence.test.js' -print0 | xargs -0 node --test --test-concurrency=1
```

## Result

```text
tests 595
pass 595
fail 0
skipped 0
```

The run exercised the real Keychain ACL provision/load/identity-check/
digest-bound retirement path and the temporary per-user Edge/Broker
LaunchAgent bootstrap, authenticated status/readback path, and clean bootout.
The test uses a random Keychain account and an isolated `/tmp` package; fixed
service labels are checked before mutation. No production capability was
enabled.

Post-test readback with `/bin/launchctl print` confirmed both fixed labels
were absent: `gui/501/com.mac-operator.edge` and
`gui/501/com.mac-operator.broker`. The Keychain test also verifies the
temporary item is unavailable after digest-bound retirement.

This closes only the applicable temporary host smoke evidence. It does not
prove Developer ID/notarized provenance, persistent installation, production
Keychain ACL review, root helper execution, crash/remount durability, or
independent P0/P1 release approval.
