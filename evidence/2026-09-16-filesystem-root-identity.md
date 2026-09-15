# Filesystem Root Identity Evidence

Date: 2026-09-16
Host: physical macOS host (Darwin arm64)
Source revision: `bed6a75`
Contract/policy versions: filesystem inspector contract `1.0`; policy `0.1`
Evidence class: implementation, focused regression, physical regression

## Decision

Filesystem authorization plans must bind both the storage-volume identity and
the authorized policy-root directory identity. A same-volume rename and
replacement of the root path must not make an existing plan address a new
directory.

## Implemented controls

- `FilesystemPathPlan.rootIdentity` records the root volume path/id plus the
  root directory device and inode captured through the native descriptor
  boundary.
- Plan creation requires a non-symlink directory whose native path equals the
  resolved volume root path and whose device/inode fields are decimal,
  bounded identities.
- Every planned operation rechecks the volume and root directory identities;
  volume mismatches retain the existing stable error and root mismatches fail
  closed before target access or result publication.
- The regression renames an authorized root, creates a replacement directory
  at the original pathname, and verifies that the old plan is rejected.

## Verification

- `npm run build`: passed.
- `node --test packages/broker/dist/filesystem-inspector.test.js`: 37/37
  passed.
- `node --test packages/broker/dist/security-fuzz.test.js`: 8/8 passed.
- `npm run lint`, `npm run typecheck`, `npm run verify:docs`,
  `npm run verify:matrix`, and `git diff --check`: passed.
- Serial physical regression with install, sandbox, and Keychain opt-ins:
  643/643 passed, 0 skipped, 0 failed. The three pre-existing long-running
  suites (`broker.test.js`, `persistence.test.js`, and
  `privileged-helper-authority-ipc.test.js`) were excluded and left running.
  Full output: `/tmp/mops-root-identity-physical-regression.log`.

## Artifact hashes

- `packages/broker/src/filesystem-inspector.ts`:
  `4dc8c9a7cc0aea573dbcb1a0de6ddf6d7e547ed91a8406374e4216613d2371c2`
- `packages/broker/src/filesystem-inspector.test.ts`:
  `cf3a91390b4dce1c887331254f343278529cc2f60c914f2b0d5ac33516dbeaf4`
- `packages/broker/src/security-fuzz.test.ts`:
  `4d07d07b7a9749bf09eb167cfe4b13a8d12d98321ecd243f1e5fa65f9511d813`

## Boundary status

This closes the previously unbound same-volume policy-root replacement race
for the implemented filesystem plan boundary. It does not provide a
kernel-held descriptor across an entire multi-syscall operation, an
in-syscall remount proof, production task-runner enablement, or installed
deployment evidence.
