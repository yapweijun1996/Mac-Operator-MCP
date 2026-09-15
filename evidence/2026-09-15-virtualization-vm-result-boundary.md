# Virtualization VM Result Boundary Evidence

Date: 2026-09-15
Source revision: `c22fc98`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T05:24:35Z
Artifact hashes: `packages/broker/src/virtualization-guest-vm-native.ts` SHA-256
`090531daa39e4ab8963c813aa97849ee33910743f5bbb810bb8b28a21d715aee`;
`packages/broker/src/virtualization-guest-vm-native.test.ts` SHA-256
`df489f260adb92e7328931dde35acf4f5242e9021b7d24f522bc1973f306fe6f`.

## Decision

Native Virtualization.framework lifecycle calls return data across a native
adapter boundary. The Broker must not accept additional authority fields or
unstable object shapes while proving guest and boot identity transitions.

## Implemented controls

- Start and stop transition results require plain records with exactly
  `bootId`, `guestIdentity`, and `state`.
- Status results use the same exact shape; state-specific boot identity rules
  still require a valid boot ID for `running` and `null` for stopped/unknown.
- Guest identities are parsed through the existing digest/runtime allowlist
  and compared to the startup-bound expected identity.
- Inherited, symbolic, non-enumerable, and accessor properties are rejected
  before semantic identity checks.
- The parser returns fresh guest identity records rather than propagating
  native objects into lifecycle consumers.

## Verification

Focused command:

```text
npm run build && node --test packages/broker/dist/virtualization-guest-vm-native.test.js
```

Result: 9 tests passed, 0 failed, 0 skipped. Hostile fixtures reject unknown
top-level fields and nested accessor authority on transition/status results;
existing lifecycle, handle-fencing, and virtio listener tests remain green.

Non-overlapping package regression (excluding the two pre-existing long-lived
broker/persistence test processes): 524 tests total, 518 passed, 6 skipped,
0 failed.

## Boundary status

This proves local native VM readback shape and identity-bound projection only.
It does not prove native code provenance, VM boot/isolation, attestation key
production, credential or persistence isolation, production resource
behavior, or `mac_task_run` enablement. Those gates remain fail-closed and
disabled.
