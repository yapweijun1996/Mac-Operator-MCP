# Filesystem Native Result Boundary Evidence

Date: 2026-09-15
Source revision: `645f57b`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T05:38:03Z
Artifact hashes: `packages/broker/src/filesystem-inspector.ts` SHA-256
`cd9d86632d70be5c759f11c8180c717a9148b4f73b631e7a524083cda00c2db4`;
`packages/broker/src/filesystem-inspector.test.ts` SHA-256
`9c01e5ec4c42ed47b7a6b8cde434d17ded8ef7a872631aae061e0e9739576979`.

## Decision

Native filesystem adapter values are an untrusted boundary. They must be
validated before path containment, volume identity, content, or mutation
postcondition decisions consume them.

## Implemented controls

- Stat, storage-volume, read, hash, directory-list, atomic-write, and unlink
  records require exact field sets and plain data properties.
- Directory entry arrays are dense and bounded; each entry is an exact plain
  record with bounded metadata.
- Read and write buffers are copied before they cross the native boundary.
- Parsed records are projected to fresh objects, so native-owned hidden
  properties cannot become Broker authority.

## Verification

Focused command:

```text
npm run build && node --test packages/broker/dist/filesystem-inspector.test.js packages/broker/dist/filesystem-executor.test.js
```

Result: 37 tests passed, 0 failed, 0 skipped. Hostile injected native
metadata/volume fields fail closed; existing traversal, symlink, volume,
device, race, atomicity, and worker tests remain green.

Non-overlapping package regression (excluding the two pre-existing long-lived
broker/persistence test processes): 530 tests total, 524 passed, 6 skipped,
0 failed.

## Boundary status

This proves local native filesystem result integrity only. It does not prove
physical remount resistance, kernel-held I/O limits, native code provenance,
production-scale resource exhaustion, or capability enablement. Those gates
remain fail-closed and incomplete.
