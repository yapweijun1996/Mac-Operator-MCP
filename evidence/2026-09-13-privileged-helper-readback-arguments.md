# Privileged Helper Exact-Arguments Readback Evidence

Date: 2026-09-13
Source commit: `8fd5814`
Dirty-state: clean at capture
Host: macOS 26.2 (25C56), arm64
Runtime: Node.js v25.5.0
Tool contract version: 0.1
Policy version: policy-0.1

## Scope

This record covers the source-level readback hardening for the separately
authenticated privileged helper. No LaunchDaemon was installed, no `launchctl`
mutation ran, and no root or privileged operation was started.

## Implemented boundary

`PrivilegedHelperLaunchdReadback` now includes the normalized native helper
`programArguments` vector. `buildPrivilegedHelperPackagePlan` copies that
vector into the fixed root-domain plan, and
`validatePrivilegedHelperPackageReadback` requires exact length and element
equality with the plan before accepting helper readiness. A matching label,
program, working directory, and signature cannot authorize a substituted or
extra argument. The helper remains native-only and rejects interpreters,
scripts, and extra argv entries at plan construction.

## Verification

- `npm test`: 395 tests, 392 passed, 0 failed, 3 opt-in macOS sandbox tests skipped.
- `npm run typecheck`: passed.
- Negative coverage: a helper readback with an attacker-supplied extra
  argument is rejected with stable `SERVICE_MISMATCH`.
- No root-domain installation or live `launchctl` readback was attempted.

## Remaining gates

Developer ID signing/provenance, successful root-owned descriptor-relative
installation, live launchd readback, helper PID/start-time process provenance
across the installed root process, Keychain ACL approval, crash recovery, and
independent security review remain open. This evidence is contract and test
evidence only; it does not enable a privileged helper capability.

## Source hashes

- `2ae62da868803a7eaf5cb666a175e4763a1a0e1b76f3baf83f6c0042b76a8523`
  `packages/broker/src/privileged-helper-package.ts`
- `da9232867ecddbbad6af2c66c05b78d1436f4865b550a324a3941cd0a9dfdd09`
  `packages/broker/src/privileged-helper-package.test.ts`
