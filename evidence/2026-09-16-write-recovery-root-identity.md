# Write Recovery Root Identity Evidence

Date: 2026-09-16
Host: physical macOS host (Darwin arm64)
Source revision: `cd649e6`
Contract/policy versions: Broker Job metadata `0.1`; filesystem inspector `1.0`; policy `0.1`
Evidence class: implementation, focused recovery regression, physical regression

## Decision

Restart cleanup and unresolved-write postcondition checks must prove that the
current policy root is the same root that authorized the original write.
`rootId` alone is not sufficient because a policy path can be replaced while
remaining on the same volume.

## Implemented controls

- New write Jobs persist the canonical policy-root path and its device/inode
  alongside the existing root ID and target facts.
- Restart cleanup compares all three root identity fields before probing,
  recovering, or unlinking a temporary artifact. Legacy rows without the
  fields are preserved and reported as skipped.
- `mac_job_status` write postcondition inspection returns an unavailable
  recovery state when root identity is missing or changed, never inferring a
  match from a replacement root.
- Persistence accepts the prior metadata shapes for read-only compatibility,
  while rooted shapes require the three root identity fields as a complete
  set.

## Verification

- `npm run build`: passed.
- `node --test packages/broker/dist/write-recovery-root-identity.test.js
  packages/broker/dist/write-recovery-journal.test.js`: 4/4 passed.
- `npm run lint`, `npm run typecheck`, `npm run verify:docs`,
  `npm run verify:matrix`, and `git diff --check`: passed.
- Serial physical regression with install, sandbox, and Keychain opt-ins:
  644/644 passed, 0 skipped, 0 failed. The three pre-existing long-running
  suites (`broker.test.js`, `persistence.test.js`, and
  `privileged-helper-authority-ipc.test.js`) were excluded and left running.
  Full output: `/tmp/mops-write-root-recovery-physical-regression-2.log`.

## Artifact hashes

- `packages/broker/src/broker.ts`:
  `667bca03735376058bda803fd5fd12892398fdcc320f43c7f0740ca89a2537c9`
- `packages/broker/src/persistence.ts`:
  `16bfdf0aa5fed06f2659846f43fd87918f0f39339b418e852a6331536b720713`
- `packages/broker/src/write-recovery-journal.test.ts`:
  `6c047dca07cf7a490f6a3b57fa71a0c49d6a3eb22e14d1d52d794adb2caa1063`
- `packages/broker/src/broker.test.ts`:
  `78c55f65c2c99c0d0b78bb1200072fb29a25d3eb09f0a29b11941dca6184e715`
- `packages/broker/src/write-recovery-root-identity.test.ts`:
  `8e6c9efaaad8d4094bea815d0a066bc414af94920a21030c8c7947f42ce10ffb`

## Boundary status

This closes the persisted write-recovery policy-root replacement gap for the
implemented Broker Job path. It does not prove physical remount durability,
kernel-held descriptor execution, external-actor attribution, or production
write-tool enablement.
