# Privileged Helper Exact-Arguments Readback Evidence

Date: 2026-09-13
Source commit: `cc103a7`
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

The same readback now requires a positive launchd PID and a native
`{ pid, startTimeMicros }` identity whose PID matches it. Missing, null,
mismatched, reused, or non-positive identity values fail closed before a
running helper is accepted.

## Verification

- `npm test`: 395 tests, 392 passed, 0 failed, 3 opt-in macOS sandbox tests skipped.
- `npm run typecheck`: passed.
- Negative coverage: a helper readback with an attacker-supplied extra
  argument is rejected with stable `SERVICE_MISMATCH`.
- Negative coverage: null PID and zero start-time readbacks are rejected with
  stable `INVALID_READBACK`.
- No root-domain installation or live `launchctl` readback was attempted.

## Remaining gates

Developer ID signing/provenance, successful root-owned descriptor-relative
installation, live launchd readback, helper PID/start-time process provenance
across the installed root process, Keychain ACL approval, crash recovery, and
independent security review remain open. This evidence is contract and test
evidence only; it does not enable a privileged helper capability.

## Source hashes

- `a4773b1b5fe8fe38dbfb8cf4bf0a061f8577d3c776020370c5ba59f5659d7157`
  `packages/broker/src/privileged-helper-package.ts`
- `8420f1dd90178bad2916f0600d295326b4568467bf6a760a708aaacab0d535f2`
  `packages/broker/src/privileged-helper-package.test.ts`
