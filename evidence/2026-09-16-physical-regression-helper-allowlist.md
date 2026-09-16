# Physical regression after Helper operation-allowlist hardening

Date: 2026-09-16
Source revision: `39cb147`
Host: physical Darwin arm64 (`yaps-Mac-mini.local`, Darwin 25.2.0)
Node: `v25.5.0`

## Command

```text
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
```

## Result

- 892 total tests
- 880 passed
- 12 explicitly skipped
- 0 failed

The skipped tests are the six real Broker task paths and five real sandbox
runner paths that require the descriptor-backed launcher, plus the Docker
Desktop readback that requires Docker Desktop. The environment-gated install
and temporary Keychain coverage ran successfully. The run did not install a
production artifact, start the root Helper, mutate a privileged service,
install a package, change power state, or enable a task capability.

This is host-regression evidence for the operation-allowlist change, not proof
of production task isolation, VM boot/guest isolation, Developer ID release
identity, Helper installation, or capability enablement.
