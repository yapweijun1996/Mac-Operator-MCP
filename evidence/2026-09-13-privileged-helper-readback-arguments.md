# Privileged Helper Exact-Arguments Readback Evidence

Date: 2026-09-13
Source commit: `a3d7765`
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

`composePrivilegedHelperPackageReadback` is the composition boundary. It
accepts only raw `LaunchdJobReadback`, native process identity, plist,
helper-runtime, and signature sources. It requires the exact system service
ID, `LaunchDaemon` type, running state, PID, native argv, plist path, and
PID/start-time binding before copying the planned launchd configuration into a
validated package readback. A caller cannot promote a plan-shaped object into
launchd evidence.

`executePrivilegedHelperPackagePlan` now accepts only
`PrivilegedHelperPackageReadbackSources` from its host callback and invokes
the composition function internally. The execution boundary therefore cannot
report success from a preassembled, caller-provided package readback.

`observePrivilegedHelperPackageReadback` is the host observer fixture boundary.
It reads launchd, process PID/start-time, and plist identity before and after
runtime/signature collection. Any service, PID, process start-time, plist
device/inode, digest, or byte-count replacement between snapshots fails closed
before final composition. The fixture proves a stable two-snapshot success and
rejects a second-snapshot PID substitution.

`createPrivilegedHelperPackageHostObserver` wires the real read-only host
adapters: `readLaunchdJobReadback` with a bounded empty-environment executor,
native `capturePeerProcessIdentity`, the internal descriptor-backed plist
reader, and strict `codesign --verify --strict --deep` plus bounded
`codesign -dv --verbose=4` field parsing. Runtime metadata remains an explicit
helper-owned callback, so launchd state or request arguments cannot fabricate
the helper's policy/version/capability readback.

## Verification

- `npm test`: 397 tests, 394 passed, 0 failed, 3 opt-in macOS sandbox tests skipped.
- `npm run typecheck`: passed.
- Negative coverage: a helper readback with an attacker-supplied extra
  argument is rejected with stable `SERVICE_MISMATCH`.
- Negative coverage: null PID and zero start-time readbacks are rejected with
  stable `INVALID_READBACK`.
- Negative coverage: a substituted plist digest is rejected with stable
  `INVALID_READBACK`; the reader's filesystem failures map to stable
  `FILESYSTEM_MISMATCH`.
- Negative coverage: a substituted launchd service ID is rejected with stable
  `SERVICE_MISMATCH` before final helper validation.
- Type-level and executor boundary coverage prevent a preassembled package
  readback from being supplied to the lifecycle callback.
- Observer coverage performs two launchd/process/plist reads and rejects a
  PID replacement between snapshots with stable `SERVICE_MISMATCH`.
- Host-adapter coverage verifies the fixed launchd command, native identity
  binding, and bounded codesign detail parsing; malformed signature details
  fail with stable `SIGNATURE_MISMATCH`.
- No root-domain installation or live `launchctl` readback was attempted.

## Remaining gates

Developer ID signing/provenance, successful root-owned descriptor-relative
installation, live launchd readback, helper PID/start-time process provenance
across the installed root process, Keychain ACL approval, crash recovery, and
independent security review remain open. This evidence is contract and test
evidence only; it does not enable a privileged helper capability.

## Source hashes

- `cc8102ddc21b83b787cdd3df3711bb2232bc27dd6b8ab6b90356443a549267e4`
  `packages/broker/src/privileged-helper-package.ts`
- `5351b9a4de349b7ec0df321fc53fce8103b2e6c97da4a8e26e302101d132d2c5`
  `packages/broker/src/privileged-helper-package.test.ts`
