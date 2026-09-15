# Helper and Install-Plan Boundary Evidence

Date: 2026-09-15

Source revision: `3d9e326`

Host: physical macOS host used by the repository test harness (`macOS 26.2`,
`Darwin 25.2.0`, `arm64`)

Command:

```text
npm run build && node --test \
  packages/broker/dist/macos-install-plan.test.js \
  packages/broker/dist/privileged-helper-package.test.js \
  packages/broker/dist/privileged-helper-runtime.test.js \
  packages/broker/dist/privileged-helper-native.test.js \
  packages/broker/dist/privileged-helper-keyring.test.js \
  packages/broker/dist/privileged-helper-executor.test.js
47 tests, 47 passed, 0 failed, 0 skipped
```

## Decision

The helper package and runtime remain fail-closed, host-only release
primitives. Passing these tests does not authorize root-domain installation or
enable a privileged operation.

## Verified boundaries

- Per-user install plans reject root-domain, interpreter, traversal, symlink,
  target-swap, service-substitution, and malformed-readback inputs.
- Code-signature plans use fixed bounded `codesign` arguments and bind the
  expected identifier, TeamIdentifier, and CDHash; the temporary artifact
  smoke uses only an ad-hoc test artifact.
- Helper package plans fix the root LaunchDaemon label, native-only argv,
  protected socket separation, Broker UID/GID binding, disabled capabilities,
  exact revision preconditions, and operation-specific recovery actions.
- Runtime startup restores an activated helper key, requires native peer
  process identity, fences socket reuse, and serializes start/close cleanup.
- Helper package and plist executors reject non-root callers before commands or
  filesystem access, require explicit host confirmation, and compose final
  readback from independent launchd, process, plist, runtime, and signature
  sources.

No root command, launchd bootstrap, package installation, reboot, shutdown,
Keychain provisioning, or privileged mutation was executed.

## Remaining gates

Developer ID provenance and notarization, protected production Keychain
material, unattended authorization, real root-domain install/upgrade/rollback/
uninstall readback, process ownership after restart, and independent release
review remain open under `MOP-061`, `MOP-072`, `MOP-073`, and `ADR-0007`/
`ADR-0009`.
