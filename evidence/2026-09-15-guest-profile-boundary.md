# Guest Profile Boundary Evidence

Date: 2026-09-15
Source revision: `5f67e18`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T05:08:30Z
Artifact hashes: `packages/broker/src/virtualization-guest-executor.ts` SHA-256
`a2d1ea91e46e38008be263154ba17dd2a82a7c74fe1e16b430f32b3a9f4fa2e4`

## Decision

Virtualization guest profiles are startup-owned authority, not caller input.
The registry must reject representation tricks before computing profile/task
digests or performing asynchronous executable and cwd readback. The
authenticated guest task request is also checked as a plain, known-field
record before digest lookup.

## Implemented controls

- Profile and request records use the shared plain-data boundary: no foreign
  prototypes, accessors, hidden properties, or symbols.
- Profile keys and request keys are allowlisted; unknown fields fail closed.
- Arguments, filesystem roots, and network destinations are dense bounded
  string arrays with no sparse or accessor elements.
- Environment data is a plain record and remains subject to existing key,
  value, secret, and byte-budget checks.
- Filesystem-root and network collection counts are bounded before async
  target checks or digest use.
- Cloned profiles preserve registry ownership after construction.

## Verification

Focused command:

```text
node --test packages/broker/dist/virtualization-guest-executor.test.js
```

Result: 10 tests passed, 0 failed, 0 skipped. Hostile inherited, accessor,
symbolic, sparse, unknown-field, and inherited-environment fixtures fail with
stable malformed-request/manifest errors before profile execution.

Non-overlapping package regression (excluding the two pre-existing long-lived
broker/persistence test processes): 516 tests total, 510 passed, 6 skipped,
0 failed.

## Boundary status

This proves local guest manifest/request representation integrity only. It does
not prove a native attestation producer, private-key distribution, approved
VM image, VM boot, guest filesystem/network/credential/process isolation,
production resource limits, or `mac_task_run` enablement. Those gates remain
fail-closed and disabled.
