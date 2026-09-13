# Privileged Helper Exact-Arguments Readback Evidence

Date: 2026-09-13
Source commit: `d3efae1`
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

The final package readback also carries a descriptor-backed plist identity:
exact canonical path, rendered UTF-8 byte count, SHA-256, and device/inode.
`readPrivilegedHelperPlistReadback` reads only through the internal protected
filesystem inspector and rejects truncation, target replacement, and content
tampering before returning a source that can be composed into helper readiness.

## Verification

- `npm test`: 395 tests, 392 passed, 0 failed, 3 opt-in macOS sandbox tests skipped.
- `npm run typecheck`: passed.
- Negative coverage: a helper readback with an attacker-supplied extra
  argument is rejected with stable `SERVICE_MISMATCH`.
- Negative coverage: null PID and zero start-time readbacks are rejected with
  stable `INVALID_READBACK`.
- Negative coverage: a substituted plist digest is rejected with stable
  `INVALID_READBACK`; the reader's filesystem failures map to stable
  `FILESYSTEM_MISMATCH`.
- No root-domain installation or live `launchctl` readback was attempted.

## Remaining gates

Developer ID signing/provenance, successful root-owned descriptor-relative
installation, live launchd readback, helper PID/start-time process provenance
across the installed root process, Keychain ACL approval, crash recovery, and
independent security review remain open. This evidence is contract and test
evidence only; it does not enable a privileged helper capability.

## Source hashes

- `1664a70e42ee2677f5285d2b95087dd770a752a5c08eaed5b37d85295dd213ee`
  `packages/broker/src/privileged-helper-package.ts`
- `5bb4d0275944d5ce7f252cac48be6cb010ee5d1772ed6287edd9ad45f1da60f7`
  `packages/broker/src/privileged-helper-package.test.ts`
