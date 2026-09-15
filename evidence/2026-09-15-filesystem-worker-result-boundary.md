# Filesystem Worker Result Boundary Evidence

Date: 2026-09-15
Source revisions: `5657267`, `86a6792`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T05:16:25Z
Artifact hashes: `packages/broker/src/filesystem-executor.ts` SHA-256
`44742cadda8f04e8268876f26cc7e1680ace9bf0c44782c9fdaba5851d994564`;
`packages/broker/src/filesystem-inspector.ts` SHA-256
`bbe2cb78a716d7919822769a60e73d84b6dc9ae253b9609581e01117ec00ba2e`;
`packages/broker/src/filesystem-worker.ts` SHA-256
`cada33bfc834be166011f1614c85f8d52a50f3768c6d999791ec5aa571e8404b`;
`packages/broker/src/filesystem-worker-protocol.ts` SHA-256
`be09a2d8b11aa6b9b4d1fa033d7f77cb85b574c0a035f6a9a6f2fb4bdbd0c173`;
`packages/broker/src/filesystem-executor.test.ts` SHA-256
`c21defaed04973da5aa633211c69e46b3892d682d08c57f1ae29d3fc6e368852`.

## Decision

Filesystem worker results cross an untrusted worker-thread boundary before
the Broker consumes them. The Broker must reject unstable object shapes and
must not expose internal planning metadata as an authoritative public result.

## Implemented controls

- Every filesystem operation has an exact top-level field set. Unknown keys,
  symbols, accessors, inherited fields, and non-plain records fail closed.
- Nested metadata, directory entries, matches, projects, storage volumes, and
  consumers use the same plain-data and exact-field boundary.
- Arrays are dense, bounded, and free of accessor or hidden index authority.
- Storage analysis explicitly maps internal volume records to the public
  `id`, `name`, `mountPath`, and capacity fields, removing `rootPath` before
  worker serialization.
- The generic worker executor validates the result before resolving any
  filesystem operation to its Broker caller.

## Verification

Focused command:

```text
npm run build && node --test packages/broker/dist/filesystem-executor.test.js packages/broker/dist/contract-conformance.test.js
```

Result: 3 tests passed, 0 failed, 0 skipped. Hostile fixtures reject unknown
top-level fields, nested accessors, and unstable read-result fields. Contract
conformance also exercises `mac_storage_analysis` and confirms the sanitized
volume shape reaches the versioned Broker success schema.

Non-overlapping package regression (excluding the two pre-existing long-lived
broker/persistence test processes): 521 tests total, 515 passed, 6 skipped,
0 failed.

## Boundary status

This proves local filesystem worker result-shape integrity and public-field
projection only. It does not prove native code provenance, physical remount
resistance, kernel sandboxing, credential or persistence isolation, VM/guest
attestation, production resource behavior, or capability enablement. Those
gates remain fail-closed and disabled.
